<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;
use Jorijn\LaravelSecurityChecker\Advisories\PackagistPerPackage;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * The Packagist drivers against a faked Packagist API: what is requested, how versions are
 * matched, and that every way of failing surfaces as CheckFailedException.
 */
class PackagistCheckerTest extends TestCase
{
    private const LOCK = __DIR__.'/fixtures/installed.lock';

    protected function setUp(): void
    {
        parent::setUp();

        // Failed requests are retried with a pause in between; tests must not actually wait.
        Sleep::fake();
    }

    public function testReportsAffectedPackagesInTheSharedReportShape(): void
    {
        Http::fake(['packagist.org/*' => Http::response($this->feed())]);

        $this->assertSame([
            // lower-cased (the lock file says "Laravel/Framework") and sorted by name
            'laravel/framework' => [
                // without the "v", like the Enlightn driver in 3.x
                'version' => '10.0.0',
                'time' => '2023-02-14T14:38:27+00:00',
                'advisories' => [
                    'PKSA-0001' => [
                        'title' => 'Framework advisory with a CVE',
                        'link' => 'https://github.com/advisories/GHSA-0001',
                        'cve' => 'CVE-2099-0001',
                        'severity' => 'high',
                    ],
                    // no CVE, no link: still reported, with null and '' like the Enlightn driver
                    'PKSA-0003' => [
                        'title' => 'Framework advisory without a CVE',
                        'link' => '',
                        'cve' => null,
                        // the feed says "MODERATE", normalized to Packagist's own "medium"
                        'severity' => 'medium',
                    ],
                ],
            ],
            'phpunit/phpunit' => [
                'version' => '9.5.0',
                'time' => null,
                'advisories' => [
                    'PKSA-0005' => ['title' => 'Dev dependency advisory', 'link' => 'https://example.com/5', 'cve' => 'CVE-2099-0005', 'severity' => null],
                ],
            ],
            'symfony/http-kernel' => [
                'version' => '6.4.20',
                'time' => null,
                'advisories' => [
                    'PKSA-0004' => ['title' => 'Kernel advisory', 'link' => 'https://example.com/4', 'cve' => 'CVE-2099-0004', 'severity' => 'critical'],
                ],
            ],
        ], $this->checker()->check(self::LOCK));
    }

    public function testTheDefaultDriverDownloadsTheFullFeedWithoutSendingPackageNames(): void
    {
        Http::fake(['packagist.org/*' => Http::response($this->feed())]);

        $this->checker()->check(self::LOCK);

        Http::assertSentCount(1);
        Http::assertSent(function (Request $request) {
            // The privacy promise of the default driver: the request is the same for every app.
            return $request->method() === 'GET'
                && $request->url() === 'https://packagist.org/api/security-advisories/?updatedSince=0'
                && $request->body() === ''
                && str_starts_with($request->header('User-Agent')[0] ?? '', 'jorijn/laravel-security-checker');
        });
    }

    public function testExcludeDevSkipsDevDependencies(): void
    {
        Http::fake(['packagist.org/*' => Http::response($this->feed())]);

        $report = $this->checker()->check(self::LOCK, true);

        $this->assertSame(['laravel/framework', 'symfony/http-kernel'], array_keys($report));
    }

    public static function allowListProvider(): array
    {
        return [
            'cve' => ['CVE-2099-0001'],
            'exact title' => ['Framework advisory with a CVE'],
            'GitHub advisory id' => ['GHSA-0001'],
            'Packagist advisory id' => ['PKSA-0001'],
            'remote id of an additional source' => ['FOP-0001'],
        ];
    }

    #[DataProvider('allowListProvider')]
    public function testAllowListHidesAnAdvisoryByAnyOfItsIdentifiers(string $entry): void
    {
        Http::fake(['packagist.org/*' => Http::response($this->feed())]);

        $report = $this->checker()->check(self::LOCK, false, [$entry]);

        $this->assertSame(['PKSA-0003'], array_keys($report['laravel/framework']['advisories']));
    }

    public function testTheCheckerTellsWhichAdvisoriesTheAllowListIgnored(): void
    {
        Http::fake(['packagist.org/*' => Http::response($this->feed())]);
        $checker = $this->checker();

        // GHSA-0001 is written first, so that is the entry shown, although the CVE matches too.
        $checker->check(self::LOCK, false, ['GHSA-0001', 'CVE-2099-0001', 'CVE-2099-0004', 'never-matches']);

        $this->assertSame([
            'laravel/framework' => [
                'version' => '10.0.0',
                'time' => '2023-02-14T14:38:27+00:00',
                'advisories' => [
                    'PKSA-0001' => [
                        'title' => 'Framework advisory with a CVE',
                        'link' => 'https://github.com/advisories/GHSA-0001',
                        'cve' => 'CVE-2099-0001',
                        'severity' => 'high',
                        'allowed_by' => 'GHSA-0001',
                    ],
                ],
            ],
            'symfony/http-kernel' => [
                'version' => '6.4.20',
                'time' => null,
                'advisories' => [
                    'PKSA-0004' => [
                        'title' => 'Kernel advisory',
                        'link' => 'https://example.com/4',
                        'cve' => 'CVE-2099-0004',
                        'severity' => 'critical',
                        'allowed_by' => 'CVE-2099-0004',
                    ],
                ],
            ],
        ], $checker->ignoredAdvisories());

        // Every check starts over.
        $checker->check(self::LOCK);
        $this->assertSame([], $checker->ignoredAdvisories());
    }

    public function testAllowListMatchesExactlyAndCaseSensitively(): void
    {
        Http::fake(['packagist.org/*' => Http::response($this->feed())]);

        $report = $this->checker()->check(self::LOCK, false, ['cve-2099-0001', 'Framework advisory', 'CVE-2099-000']);

        $this->assertCount(2, $report['laravel/framework']['advisories']);
    }

    public function testAPackageWhoseAdvisoriesAreAllAllowedIsNotReported(): void
    {
        Http::fake(['packagist.org/*' => Http::response($this->feed())]);

        $report = $this->checker()->check(self::LOCK, false, ['CVE-2099-0004']);

        $this->assertArrayNotHasKey('symfony/http-kernel', $report);
    }

    public function testAnAdvisoryWithAnUnparseableVersionRangeIsReportedLikeComposerAuditDoes(): void
    {
        Http::fake(['packagist.org/*' => Http::response(['advisories' => [
            'symfony/http-kernel' => [$this->advisory('PKSA-0099', 'Broken range', 'this is not a constraint')],
        ]])]);

        $report = $this->checker()->check(self::LOCK);

        $this->assertSame(['PKSA-0099'], array_keys($report['symfony/http-kernel']['advisories']));
    }

    public function testPerPackageDriverOnlyAsksForTheInstalledPackages(): void
    {
        Config::set('laravel-security-checker.driver', 'packagist-per-package');
        Http::fake(['packagist.org/*' => Http::response($this->feed())]);

        $report = $this->checker()->check(self::LOCK, true);

        Http::assertSentCount(1);
        Http::assertSent(function (Request $request) {
            // POST keeps the package list out of URLs (and so out of access logs).
            return $request->method() === 'POST'
                && $request->url() === 'https://packagist.org/api/security-advisories/'
                && $request->isForm()
                && $request['packages'] === ['acme/private-package', 'laravel/framework', 'league/commonmark', 'symfony/http-kernel'];
        });

        // The same matching as the full feed.
        $this->assertSame(['laravel/framework', 'symfony/http-kernel'], array_keys($report));
    }

    public function testPerPackageDriverSendsLargeLockFilesInBatches(): void
    {
        Config::set('laravel-security-checker.driver', 'packagist-per-package');
        Http::fake(['packagist.org/*' => Http::response(['advisories' => []])]);

        $packages = array_map(fn (int $i) => ['name' => "vendor/package-$i", 'version' => '1.0.0'], range(1, 250));
        $lock = $this->temporaryLockFile(['packages' => $packages]);

        $this->assertSame([], $this->checker()->check($lock));

        Http::assertSentCount((int) ceil(250 / PackagistPerPackage::BATCH_SIZE));
    }

    public function testAMirrorUrlCanBeConfigured(): void
    {
        Config::set('laravel-security-checker.packagist.url', 'https://packagist.example.com/');
        Http::fake(['packagist.example.com/*' => Http::response($this->feed())]);

        $this->checker()->check(self::LOCK);

        Http::assertSent(fn (Request $request) => $request->url() === 'https://packagist.example.com/api/security-advisories/?updatedSince=0');
    }

    public static function brokenResponseProvider(): array
    {
        return [
            'server error' => [503, 'Service Unavailable', 'HTTP 503'],
            'client error' => [404, 'Not Found', 'HTTP 404'],
            'not json' => [200, '<html>captive portal</html>', 'unexpected response'],
            'no advisories key' => [200, ['data' => []], 'unexpected response'],
            'advisories is not a map' => [200, ['advisories' => 'nope'], 'unexpected response'],
            // packagist.org always lists thousands of advisories; zero is a broken response
            'empty feed' => [200, ['advisories' => []], 'empty'],
        ];
    }

    #[DataProvider('brokenResponseProvider')]
    public function testABrokenResponseMeansTheCheckFailedNotThatThereAreNoVulnerabilities(int $status, string|array $body, string $reason): void
    {
        Http::fake(['packagist.org/*' => Http::response($body, $status)]);

        $this->expectException(CheckFailedException::class);
        $this->expectExceptionMessage($reason);

        $this->checker()->check(self::LOCK);
    }

    public function testServerErrorsAreRetriedBeforeGivingUp(): void
    {
        Http::fake(['packagist.org/*' => Http::sequence()
            ->push('', 502)
            ->push($this->feed()),
        ]);

        $this->assertArrayHasKey('laravel/framework', $this->checker()->check(self::LOCK));
        Http::assertSentCount(2);
    }

    public function testClientErrorsAreNotRetried(): void
    {
        Http::fake(['packagist.org/*' => Http::response('', 400)]);

        try {
            $this->checker()->check(self::LOCK);
            $this->fail('Expected the check to fail');
        } catch (CheckFailedException) {
            Http::assertSentCount(1);
        }
    }

    public function testAnUnreachablePackagistMeansTheCheckFailed(): void
    {
        Http::fake(fn () => throw new ConnectionException('cURL error 6: Could not resolve host: packagist.org'));

        $this->expectException(CheckFailedException::class);
        $this->expectExceptionMessage('Could not resolve host');

        $this->checker()->check(self::LOCK);
    }

    public function testAMissingLockFileMeansTheCheckFailed(): void
    {
        Http::fake();

        $this->expectException(CheckFailedException::class);
        $this->expectExceptionMessage('Cannot read the lock file');

        $this->checker()->check(__DIR__.'/fixtures/does-not-exist.lock');
    }

    public function testAnInvalidLockFileMeansTheCheckFailed(): void
    {
        Http::fake();
        $lock = tempnam(sys_get_temp_dir(), 'lsc');
        file_put_contents($lock, '{"packages": [');

        try {
            $this->expectException(CheckFailedException::class);
            $this->expectExceptionMessage('not valid JSON');

            $this->checker()->check($lock);
        } finally {
            @unlink($lock);
        }
    }

    public function testALockFileWithoutPackagesDoesNotQueryPackagist(): void
    {
        Http::fake();

        $this->assertSame([], $this->checker()->check($this->temporaryLockFile(['packages' => []])));
        Http::assertNothingSent();
    }

    private function checker(): Checker
    {
        return $this->app->make(Checker::class);
    }

    private function temporaryLockFile(array $contents): string
    {
        $lock = tempnam(sys_get_temp_dir(), 'lsc');
        file_put_contents($lock, json_encode($contents));
        $this->beforeApplicationDestroyed(fn () => @unlink($lock));

        return $lock;
    }

    /**
     * A small feed in the format of https://packagist.org/api/security-advisories/.
     */
    private function feed(): array
    {
        return ['advisories' => [
            'laravel/framework' => [
                $this->advisory('PKSA-0001', 'Framework advisory with a CVE', '>=10.0.0,<10.1.0|>=9.0.0,<9.52.0', 'CVE-2099-0001', 'https://github.com/advisories/GHSA-0001', 'GHSA-0001', [
                    ['name' => 'GitHub', 'remoteId' => 'GHSA-0001'],
                    ['name' => 'FriendsOfPHP/security-advisories', 'remoteId' => 'FOP-0001'],
                ]),
                // v10.0.0 is installed, so this one does not apply
                $this->advisory('PKSA-0002', 'Framework advisory for older versions', '<10.0.0', 'CVE-2099-0002'),
                $this->advisory('PKSA-0003', 'Framework advisory without a CVE', '<11.0.0', null, null, severity: 'MODERATE'),
            ],
            'symfony/http-kernel' => [
                $this->advisory('PKSA-0004', 'Kernel advisory', '>=6.4.0,<6.4.21', 'CVE-2099-0004', 'https://example.com/4', severity: 'critical'),
            ],
            'phpunit/phpunit' => [
                // about 7% of Packagist's advisories have no severity
                $this->advisory('PKSA-0005', 'Dev dependency advisory', '<9.6.0', 'CVE-2099-0005', 'https://example.com/5', severity: null),
            ],
            // a branch install (dev-main) never matches a version range, as in composer audit
            'league/commonmark' => [
                $this->advisory('PKSA-0006', 'Commonmark advisory', '<2.0.0', 'CVE-2099-0006'),
            ],
            'not/installed' => [
                $this->advisory('PKSA-0007', 'Advisory for a package nobody uses', '*', 'CVE-2099-0007'),
            ],
        ]];
    }

    private function advisory(
        string $id,
        string $title,
        string $affectedVersions,
        ?string $cve = null,
        ?string $link = 'https://example.com',
        ?string $remoteId = null,
        array $sources = [],
        ?string $severity = 'high',
    ): array {
        return [
            'advisoryId' => $id,
            'packageName' => 'ignored/by-the-checker',
            'remoteId' => $remoteId ?? 'GHSA-'.$id,
            'title' => $title,
            'link' => $link,
            'cve' => $cve,
            'affectedVersions' => $affectedVersions,
            'source' => 'GitHub',
            'reportedAt' => '2099-01-01 00:00:00',
            'composerRepository' => 'https://packagist.org',
            'severity' => $severity,
            'sources' => $sources,
        ];
    }
}
