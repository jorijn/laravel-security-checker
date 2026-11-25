<?php

namespace Jorijn\LaravelSecurityChecker\Tests\E2E;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;
use Symfony\Component\Yaml\Yaml;
use ZipArchive;

/**
 * Base class for the end-to-end suite.
 *
 * Unlike the unit tests (Orchestra Testbench plus a mocked checker), these tests run the real
 * `php artisan security-check:*` commands inside a real Laravel application that has this
 * package installed through Composer, exactly like a user would. Nothing in the package or in
 * enlightn/security-checker is mocked. Only the network edges are replaced:
 *
 *   - the advisory sources by a local TLS proxy: packagist.org (the 4.x drivers) gets a JSON
 *     feed, codeload.github.com (the deprecated "enlightn" driver) a zip of the same fixtures,
 *   - the Slack webhook by PHP's built-in web server recording every POST,
 *   - mail by Laravel's own "log" mailer, so the fully rendered message ends up in a file.
 *
 * Point E2E_APP_PATH at an app created with tests/E2E/bin/create-app.sh.
 */
abstract class E2ETestCase extends TestCase
{
    protected static string $appPath;

    protected static string $stateDir;

    protected static ?Process $proxy = null;

    protected static ?Process $slack = null;

    protected static int $proxyPort;

    protected static int $slackPort;

    public static function setUpBeforeClass(): void
    {
        $appPath = getenv('E2E_APP_PATH');

        if (!$appPath || !is_file($appPath.'/artisan')) {
            self::fail('Set E2E_APP_PATH to a Laravel app created with tests/E2E/bin/create-app.sh');
        }

        static::$appPath = realpath($appPath);
        static::$stateDir = sys_get_temp_dir().'/lsc-e2e-'.bin2hex(random_bytes(4));
        mkdir(static::$stateDir.'/tmp', 0777, true);

        static::generateCertificates(static::$stateDir);

        foreach (['vulnerable', 'clean'] as $set) {
            static::buildAdvisoryArchive($set);
            static::buildPackagistFeed($set);
        }

        static::startProxy();
        static::startSlack();
    }

    public static function tearDownAfterClass(): void
    {
        static::$proxy?->stop(0);
        static::$slack?->stop(0);
        static::$proxy = static::$slack = null;

        (new Process(['rm', '-rf', static::$stateDir]))->run();
    }

    protected function setUp(): void
    {
        parent::setUp();

        // Every test starts from the same known state: vulnerable fixtures, empty logs.
        $this->useAdvisories('vulnerable');
        @unlink(static::$stateDir.'/requests.jsonl');
        @unlink(static::$stateDir.'/slack.jsonl');
        @unlink($this->appLogPath());
    }

    /**
     * Picks which fixture set the fake advisory sources serve: "vulnerable" or "clean".
     */
    protected function useAdvisories(string $set): void
    {
        file_put_contents(static::$stateDir.'/mode', 'serve:'.$set);
    }

    /**
     * Simulates the advisory source being unreachable ("refuse") or failing ("http-error:503").
     */
    protected function breakAdvisorySource(string $mode): void
    {
        file_put_contents(static::$stateDir.'/mode', $mode);
    }

    /**
     * Runs `php artisan ...` in the e2e app with an environment that only reaches our fakes.
     *
     * Values in $env become real environment variables. Laravel's Dotenv loader never overrides
     * variables that already exist, so they win over the app's .env, like they do on a server.
     */
    protected function artisan(array $arguments, array $env = []): Process
    {
        $process = new Process(
            array_merge([PHP_BINARY, '-d', 'curl.cainfo='.static::$stateDir.'/ca.pem', 'artisan'], $arguments),
            static::$appPath,
            array_merge($this->baseEnvironment(), $env),
            null,
            120
        );

        $process->run();

        return $process;
    }

    protected function baseEnvironment(): array
    {
        $proxy = 'http://127.0.0.1:'.static::$proxyPort;

        return [
            // Guzzle (so Laravel's HTTP client and Enlightn) picks these up; libcurl reads the
            // lower-case variants.
            'HTTPS_PROXY' => $proxy,
            'https_proxy' => $proxy,
            // false removes the variable: a proxy inherited from the host must not intercept
            // the plain-HTTP Slack webhook on 127.0.0.1.
            'HTTP_PROXY' => false,
            'http_proxy' => false,
            'NO_PROXY' => '127.0.0.1,localhost',
            'no_proxy' => '127.0.0.1,localhost',
            // Enlightn caches the advisory archive in sys_get_temp_dir(); keep that per run.
            'TMPDIR' => static::$stateDir.'/tmp',
            'APP_NAME' => 'E2E App',
            'APP_URL' => 'http://e2e.test',
            'APP_LOCALE' => 'en',
            'MAIL_MAILER' => 'log',
            'LOG_CHANNEL' => 'single',
            'LOG_LEVEL' => 'debug',
            // Make sure values from the developer's shell never leak into a scenario.
            'LCS_MAIL_TO' => false,
            'LCS_SLACK_WEBHOOK' => false,
            'LCS_NOTIFY_WITHOUT_VULNERABILITIES' => false,
            'LCS_EXCLUDE_DEV' => false,
            'LCS_ALLOW_LIST' => false,
            'LCS_DRIVER' => false,
            'LCS_NOTIFY_ON_FAILURE' => false,
            'LCS_PACKAGIST_URL' => false,
            'LCS_MINIMUM_SEVERITY' => false,
        ];
    }

    protected function slackWebhookUrl(): string
    {
        return 'http://127.0.0.1:'.static::$slackPort.'/services/T000/B000/XXXX';
    }

    /**
     * @return array<int, array{method: string, uri: string, content_type: ?string, body: string}>
     */
    protected function slackRequests(): array
    {
        return $this->readJsonLines(static::$stateDir.'/slack.jsonl');
    }

    /**
     * @return array<int, array<string, string>>
     */
    protected function advisoryRequests(): array
    {
        return $this->readJsonLines(static::$stateDir.'/requests.jsonl');
    }

    protected function appLogPath(): string
    {
        return static::$appPath.'/storage/logs/laravel.log';
    }

    protected function appLog(): string
    {
        return (string) @file_get_contents($this->appLogPath());
    }

    /**
     * Returns every message the "log" mailer wrote, as raw MIME text.
     *
     * @return array<int, string>
     */
    protected function sentMails(): array
    {
        // Each log entry starts with "[YYYY-MM-DD HH:MM:SS] env.LEVEL: "; mails are the entries
        // whose message starts with MIME headers.
        $entries = preg_split('/^\[\d{4}-\d{2}-\d{2}[^\]]*\] \w+\.\w+: /m', $this->appLog(), -1, PREG_SPLIT_NO_EMPTY);

        return array_values(array_filter($entries, fn (string $entry) => preg_match('/^(From|To|Subject|Message-ID): /mi', $entry) === 1));
    }

    /**
     * Pulls the decoded HTML part out of a raw MIME message.
     */
    protected function mailHtml(string $mime): string
    {
        if (preg_match('#Content-Type: text/html.*?\r?\n\r?\n(.*?)(\r?\n--|\z)#s', $mime, $m)) {
            $html = $m[1];

            // Newer Laravel versions log decoded content; older ones log quoted-printable.
            if (preg_match('/=\r?\n|=[0-9A-F]{2}/', $html)) {
                $html = quoted_printable_decode($html);
            }

            return $html;
        }

        return $mime;
    }

    /**
     * Pulls the value of one header out of a raw MIME message.
     */
    protected function mailHeader(string $mime, string $name): ?string
    {
        if (preg_match('/^'.preg_quote($name, '/').': (.*(?:\r?\n[ \t].*)*)/mi', $mime, $m)) {
            return trim(preg_replace('/\r?\n[ \t]+/', ' ', $m[1]));
        }

        return null;
    }

    /**
     * The text report without the list of advisories the allow list ignored (since 4.1), so
     * tests can assert that an allowed advisory is no longer *reported*.
     */
    protected function reportedPart(string $output): string
    {
        return preg_split('/^\d+ advisor(y is|ies are) ignored by the allow list:$/m', $output)[0];
    }

    /**
     * Runs assertions that describe the *correct* behaviour for a known bug.
     *
     * While the bug exists the test is reported as incomplete instead of failing, so the suite
     * stays green but the bug stays visible in every run. Once the bug is fixed the assertions
     * pass and this helper fails on purpose: that is the reminder to delete the marker and turn
     * the scenario into a normal regression test.
     */
    protected function assertKnownBug(string $description, callable $assertions): void
    {
        try {
            $assertions();
        } catch (AssertionFailedError $e) {
            // Assertion messages can embed a whole rendered mail; keep the report readable.
            $this->markTestIncomplete("Known bug: $description\n".mb_strimwidth($e->getMessage(), 0, 600, ' [...]'));
        }

        $this->fail("Known bug appears to be fixed: $description. Remove assertKnownBug() around this test.");
    }

    private function readJsonLines(string $file): array
    {
        if (!is_file($file)) {
            return [];
        }

        return array_map(
            fn (string $line) => json_decode($line, true),
            array_values(array_filter(explode("\n", (string) file_get_contents($file))))
        );
    }

    private static function startProxy(): void
    {
        static::$proxy = new Process([PHP_BINARY, __DIR__.'/Support/fake-advisories-proxy.php', static::$stateDir]);
        static::$proxy->start();

        static::$proxyPort = (int) static::waitFor(fn () => @file_get_contents(static::$stateDir.'/port'), static::$proxy);
    }

    private static function startSlack(): void
    {
        // Ask the OS for a free port, then hand it to the built-in server. The tiny window
        // between closing and re-binding is acceptable for a test helper.
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $name = stream_socket_get_name($socket, false);
        fclose($socket);
        static::$slackPort = (int) substr($name, strrpos($name, ':') + 1);

        static::$slack = new Process(
            [PHP_BINARY, '-S', '127.0.0.1:'.static::$slackPort, __DIR__.'/Support/fake-slack-router.php'],
            null,
            ['FAKE_SLACK_LOG' => static::$stateDir.'/slack.jsonl']
        );
        static::$slack->start();

        static::waitFor(fn () => @fsockopen('127.0.0.1', static::$slackPort), static::$slack);
    }

    private static function waitFor(callable $probe, Process $process): mixed
    {
        for ($i = 0; $i < 100; $i++) {
            if ($result = $probe()) {
                return $result;
            }

            if (!$process->isRunning()) {
                self::fail('Helper process died: '.$process->getErrorOutput());
            }

            usleep(50_000);
        }

        self::fail('Helper process did not come up in time: '.$process->getErrorOutput());
    }

    /**
     * Creates a throw-away CA plus a certificate for the faked hosts, signed by it.
     *
     * Generated per run instead of committed, so no private key ever lives in the repository
     * (secret scanners would rightly complain) and the certificate never expires in CI.
     */
    private static function generateCertificates(string $dir): void
    {
        $config = $dir.'/openssl.cnf';
        file_put_contents($config, <<<'CNF'
            [req]
            distinguished_name = dn
            [dn]
            [v3_ca]
            basicConstraints = critical, CA:TRUE
            keyUsage = critical, keyCertSign, cRLSign
            subjectKeyIdentifier = hash
            [v3_leaf]
            basicConstraints = critical, CA:FALSE
            keyUsage = critical, digitalSignature, keyEncipherment
            extendedKeyUsage = serverAuth
            subjectAltName = DNS:codeload.github.com, DNS:packagist.org
            subjectKeyIdentifier = hash
            authorityKeyIdentifier = keyid
            CNF);

        $keyOptions = ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048, 'config' => $config];

        $caKey = openssl_pkey_new($keyOptions);
        $caCsr = openssl_csr_new(['commonName' => 'laravel-security-checker e2e CA'], $caKey, ['digest_alg' => 'sha256', 'config' => $config]);
        $caCert = openssl_csr_sign($caCsr, null, $caKey, 2, ['digest_alg' => 'sha256', 'config' => $config, 'x509_extensions' => 'v3_ca'], 1);

        $leafKey = openssl_pkey_new($keyOptions);
        $leafCsr = openssl_csr_new(['commonName' => 'packagist.org'], $leafKey, ['digest_alg' => 'sha256', 'config' => $config]);
        $leafCert = openssl_csr_sign($leafCsr, $caCert, $caKey, 2, ['digest_alg' => 'sha256', 'config' => $config, 'x509_extensions' => 'v3_leaf'], 2);

        if (!$caCert || !$leafCert) {
            self::fail('Could not generate e2e certificates: '.openssl_error_string());
        }

        openssl_x509_export_to_file($caCert, $dir.'/ca.pem');
        openssl_x509_export_to_file($leafCert, $dir.'/server.pem');
        openssl_pkey_export_to_file($leafKey, $dir.'/server.key', null, ['config' => $config]);
    }

    /**
     * Zips a fixture set the way GitHub's codeload does: everything below one top-level folder.
     */
    private static function buildAdvisoryArchive(string $set): void
    {
        $source = __DIR__.'/fixtures/advisories/'.$set;
        $zip = new ZipArchive();
        $zip->open(static::$stateDir.'/'.$set.'.zip', ZipArchive::CREATE | ZipArchive::OVERWRITE);

        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($source, \FilesystemIterator::SKIP_DOTS));

        foreach ($files as $file) {
            $relative = substr($file->getPathname(), strlen($source) + 1);
            $zip->addFile($file->getPathname(), 'security-advisories-master/'.$relative);
        }

        $zip->close();
    }

    /**
     * Converts a fixture set to the JSON that https://packagist.org/api/security-advisories/ serves.
     *
     * The YAML files stay the single source of truth for both drivers. The conversion mirrors
     * what Packagist does with FriendsOfPHP advisories: every branch becomes one range, and the
     * ranges are OR-ed together ("<1.0|>=2.0,<2.1").
     */
    private static function buildPackagistFeed(string $set): void
    {
        $source = __DIR__.'/fixtures/advisories/'.$set;
        $advisories = [];

        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($source, \FilesystemIterator::SKIP_DOTS));

        foreach ($files as $file) {
            $advisory = Yaml::parseFile($file->getPathname());
            $package = substr($advisory['reference'], strlen('composer://'));
            $id = 'PKSA-e2e-'.pathinfo($file->getFilename(), PATHINFO_FILENAME);

            $advisories[$package][] = [
                'advisoryId' => $id,
                'packageName' => $package,
                'remoteId' => $package.'/'.$file->getFilename(),
                'title' => $advisory['title'],
                'link' => $advisory['link'],
                'cve' => $advisory['cve'],
                'affectedVersions' => implode('|', array_map(
                    fn (array $branch) => implode(',', $branch['versions']),
                    array_values($advisory['branches'])
                )),
                'source' => 'FriendsOfPHP/security-advisories',
                'reportedAt' => '2099-01-01 00:00:00',
                'composerRepository' => 'https://packagist.org',
                // Optional in the fixtures; most FriendsOfPHP advisories have none on Packagist either.
                'severity' => $advisory['severity'] ?? null,
                'sources' => [['name' => 'FriendsOfPHP/security-advisories', 'remoteId' => $package.'/'.$file->getFilename()]],
            ];
        }

        // Sorted, so the order in reports never depends on the file system.
        ksort($advisories);
        file_put_contents(static::$stateDir.'/'.$set.'.json', json_encode(['advisories' => $advisories], JSON_PRETTY_PRINT));
    }
}
