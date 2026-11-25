<?php

namespace Jorijn\LaravelSecurityChecker\Tests\E2E;

/**
 * `php artisan security-check:now`: the report printed to the console.
 */
class ConsoleCommandTest extends E2ETestCase
{
    public function testReportsVulnerablePackagesAndExitsWithOne(): void
    {
        $process = $this->artisan(['security-check:now']);
        $output = $process->getOutput();

        // Exit code 1 is what CI pipelines and cron wrappers rely on to flag a problem.
        $this->assertSame(1, $process->getExitCode(), $process->getErrorOutput());
        $this->assertStringContainsString('Security Check Report: '.static::$appPath.'/composer.lock', $output);
        $this->assertStringContainsString('[CRITICAL] 2 packages have known vulnerabilities', $output);

        $this->assertMatchesRegularExpression('/^laravel\/framework \(\d+\.\d+\.\d+\)$/m', $output);
        $this->assertStringContainsString(' * CVE-2099-0001: E2E fixture: framework advisory with a CVE', $output);
        // The link is indented below its advisory. Laravel 12 keeps the three spaces the
        // formatter writes, Laravel 13 prints one, so only require "indented".
        $this->assertMatchesRegularExpression('/^ +https:\/\/example\.com\/advisories\/CVE-2099-0001$/m', $output);
        // An advisory without CVE is listed by its title only, without a dangling "CVE:" prefix.
        $this->assertStringContainsString(" * E2E fixture: framework advisory without a CVE\n", $output);
        $this->assertStringContainsString('phpunit/phpunit (', $output);
        $this->assertStringContainsString('CVE-2099-0003', $output);

        // Version constraints are honoured: this advisory only affects laravel/framework 4.0.0.
        $this->assertStringNotContainsString('CVE-2099-0009', $output);

        // The advisories really came from the (fake) Packagist feed, in a single request that
        // carries no package names: the privacy promise of the default driver.
        $this->assertSame(
            [['type' => 'request', 'host' => 'packagist.org', 'request' => 'GET /api/security-advisories/?updatedSince=0 HTTP/1.1']],
            $this->advisoryRequests()
        );
    }

    public function testPerPackageDriverSendsTheInstalledPackageNamesAndReportsTheSame(): void
    {
        $default = $this->artisan(['security-check:now'])->getOutput();
        @unlink(static::$stateDir.'/requests.jsonl');

        $process = $this->artisan(['security-check:now'], ['LCS_DRIVER' => 'packagist-per-package']);

        $this->assertSame(1, $process->getExitCode(), $process->getErrorOutput());
        $this->assertSame($default, $process->getOutput());

        $requests = $this->advisoryRequests();
        $this->assertNotEmpty($requests);

        foreach ($requests as $request) {
            $this->assertSame('POST /api/security-advisories/ HTTP/1.1', $request['request']);
        }

        $packages = array_merge(...array_column($requests, 'packages'));
        $this->assertContains('laravel/framework', $packages);
        $this->assertContains('phpunit/phpunit', $packages);
    }

    /**
     * The 3.x data source stays available, deprecated, until 5.0.
     */
    public function testDeprecatedEnlightnDriverStillWorks(): void
    {
        $process = $this->artisan(['security-check:now'], ['LCS_DRIVER' => 'enlightn']);
        $output = $process->getOutput();

        $this->assertSame(1, $process->getExitCode(), $process->getErrorOutput());
        $this->assertStringContainsString('"enlightn" driver of laravel-security-checker is deprecated', $output);
        $this->assertStringContainsString('[CRITICAL] 2 packages have known vulnerabilities', $output);
        $this->assertStringContainsString(' * CVE-2099-0001: E2E fixture: framework advisory with a CVE', $output);
        $this->assertStringNotContainsString('CVE-2099-0009', $output);

        $this->assertSame(
            [['type' => 'request', 'host' => 'codeload.github.com', 'request' => 'GET /FriendsOfPHP/security-advisories/zip/master HTTP/1.1']],
            $this->advisoryRequests()
        );
    }

    public function testReportsOkAndExitsWithZeroWithoutVulnerabilities(): void
    {
        $this->useAdvisories('clean');

        $process = $this->artisan(['security-check:now']);

        $this->assertSame(0, $process->getExitCode(), $process->getErrorOutput());
        $this->assertStringContainsString('[OK] 0 packages have known vulnerabilities', $process->getOutput());
    }

    public function testExcludeDevSkipsDevDependencies(): void
    {
        $process = $this->artisan(['security-check:now'], ['LCS_EXCLUDE_DEV' => 'true']);
        $output = $process->getOutput();

        $this->assertSame(1, $process->getExitCode());
        $this->assertStringContainsString('[CRITICAL] 1 package has known vulnerabilities', $output);
        $this->assertStringNotContainsString('phpunit/phpunit', $output);
        $this->assertStringContainsString('CVE-2099-0001', $output);
    }

    public function testAllowListHidesAdvisoriesByCveAndByTitle(): void
    {
        $process = $this->artisan(['security-check:now'], [
            'LCS_ALLOW_LIST' => json_encode(['CVE-2099-0001', 'E2E fixture: framework advisory without a CVE']),
        ]);
        $output = $process->getOutput();

        $this->assertSame(1, $process->getExitCode());
        $this->assertStringContainsString('[CRITICAL] 1 package has known vulnerabilities', $output);
        $this->assertStringNotContainsString('laravel/framework', $output);
        $this->assertStringContainsString('CVE-2099-0003', $output);
    }

    public function testAllowingEverythingExitsWithZero(): void
    {
        $process = $this->artisan(['security-check:now'], [
            'LCS_EXCLUDE_DEV' => 'true',
            'LCS_ALLOW_LIST' => json_encode(['CVE-2099-0001', 'E2E fixture: framework advisory without a CVE']),
        ]);

        $this->assertSame(0, $process->getExitCode());
        $this->assertStringContainsString('[OK] 0 packages have known vulnerabilities', $process->getOutput());
    }

    public function testInvalidAllowListIsIgnoredWithAWarningAndTheCheckStillRuns(): void
    {
        $process = $this->artisan(['security-check:now'], ['LCS_ALLOW_LIST' => 'CVE-2099-0001']);

        $this->assertSame(1, $process->getExitCode());
        $this->assertStringContainsString('allow_list is invalid and has been ignored', $process->getOutput());
        $this->assertStringContainsString('CVE-2099-0001', $process->getOutput());
        $this->assertStringContainsString('allow_list is invalid and has been ignored', $this->appLog());
    }

    /**
     * Exit code 2 means "the check could not run", so cron wrappers and CI steps can tell it
     * apart from "vulnerabilities found" (1). In 3.x both were 1.
     */
    public function testUnreachableAdvisorySourceExitsWithTwo(): void
    {
        $this->breakAdvisorySource('refuse');

        $process = $this->artisan(['security-check:now']);
        $output = $process->getOutput().$process->getErrorOutput();

        $this->assertSame(2, $process->getExitCode(), $output);
        $this->assertStringContainsString('The security check could not run: Could not reach Packagist', $output);
        $this->assertStringNotContainsString('[OK]', $output);
        $this->assertStringContainsString('the security check could not run', $this->appLog());
    }

    public function testAdvisorySourceHttpErrorExitsWithTwo(): void
    {
        $this->breakAdvisorySource('http-error:503');

        $process = $this->artisan(['security-check:now']);
        $output = $process->getOutput().$process->getErrorOutput();

        $this->assertSame(2, $process->getExitCode(), $output);
        $this->assertStringContainsString('Packagist answered HTTP 503', $output);
        $this->assertStringNotContainsString('[OK]', $output);

        // Server errors are retried before giving up, so one hiccup does not raise an alarm.
        $this->assertCount(3, $this->advisoryRequests());
    }

    public function testDeprecatedEnlightnDriverFailureAlsoExitsWithTwo(): void
    {
        $this->breakAdvisorySource('http-error:503');

        $process = $this->artisan(['security-check:now'], ['LCS_DRIVER' => 'enlightn']);

        $this->assertSame(2, $process->getExitCode(), $process->getOutput().$process->getErrorOutput());
        $this->assertStringContainsString('The Enlightn security checker failed', $process->getOutput());
    }

    public function testJsonFormatPrintsOnlyJsonOnStdout(): void
    {
        // The invalid allow list makes the command print a warning: it must go to stderr, so a
        // script can parse stdout as is.
        $process = $this->artisan(['security-check:now', '--format=json'], ['LCS_ALLOW_LIST' => 'not json']);

        $this->assertSame(1, $process->getExitCode(), $process->getErrorOutput());
        $this->assertStringContainsString('allow_list is invalid and has been ignored', $process->getErrorOutput());

        $report = json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);

        $this->assertSame(static::$appPath.'/composer.lock', $report['lock_file']);
        $this->assertSame(2, $report['vulnerable_package_count']);
        $this->assertSame(3, $report['advisory_count']);
        $this->assertSame(['laravel/framework', 'phpunit/phpunit'], array_keys($report['packages']));

        $framework = $report['packages']['laravel/framework'];
        $this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+$/', $framework['version']);
        $this->assertSame([
            'title' => 'E2E fixture: framework advisory with a CVE',
            'link' => 'https://example.com/advisories/CVE-2099-0001',
            'cve' => 'CVE-2099-0001',
        ], $framework['advisories']['PKSA-e2e-CVE-2099-0001']);
    }

    public function testJsonFormatWithoutVulnerabilities(): void
    {
        $this->useAdvisories('clean');

        $process = $this->artisan(['security-check:now', '--format=json']);

        $this->assertSame(0, $process->getExitCode(), $process->getErrorOutput());
        $this->assertSame('', $process->getErrorOutput());

        $report = json_decode($process->getOutput(), false, flags: JSON_THROW_ON_ERROR);
        $this->assertSame(0, $report->vulnerable_package_count);
        $this->assertEquals(new \stdClass(), $report->packages);
    }

    public function testJsonFormatWhenTheCheckCannotRun(): void
    {
        $this->breakAdvisorySource('refuse');

        $process = $this->artisan(['security-check:now', '--format=json']);

        $this->assertSame(2, $process->getExitCode(), $process->getErrorOutput());
        $this->assertStringContainsString('The security check could not run', $process->getErrorOutput());

        $report = json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
        $this->assertStringContainsString('Could not reach Packagist', $report['error']);
        $this->assertArrayNotHasKey('packages', $report);
    }
}
