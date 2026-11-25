<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;
use Jorijn\LaravelSecurityChecker\Contracts\ReportsIgnoredAdvisories;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * security-check:now lists what the allow list hides, with the reason from the allow list.
 */
class IgnoredAdvisoriesTest extends TestCase
{
    private const IGNORED = [
        'vendor/package' => [
            'version' => '1.0.0',
            'time' => null,
            'advisories' => [
                'PKSA-1' => ['title' => 'With a reason', 'link' => '', 'cve' => 'CVE-2099-1', 'severity' => 'high', 'allowed_by' => 'GHSA-1'],
                'PKSA-2' => ['title' => 'Without a reason', 'link' => '', 'cve' => null, 'severity' => null, 'allowed_by' => 'Without a reason'],
            ],
        ],
    ];

    protected function setUp(): void
    {
        parent::setUp();

        Config::set('laravel-security-checker.allow_list', [
            ['id' => 'GHSA-1', 'reason' => 'We never call the affected method'],
            'Without a reason',
        ]);

        $checker = \Mockery::mock(Checker::class, ReportsIgnoredAdvisories::class);
        $checker->allows('check')
            ->with(base_path('composer.lock'), false, ['GHSA-1', 'Without a reason'])
            ->andReturns([]);
        $checker->allows('ignoredAdvisories')->andReturns(self::IGNORED);
        $this->app->instance(Checker::class, $checker);
    }

    public function testTheTextReportListsIgnoredAdvisoriesWithTheirReason(): void
    {
        [$exitCode, $output] = $this->runNow([]);

        // Ignored advisories never make the check fail.
        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('[OK] 0 packages have known vulnerabilities', $output);
        $this->assertStringContainsString("2 advisories are ignored by the allow list:\n", $output);
        $this->assertStringContainsString(" * vendor/package (1.0.0): CVE-2099-1: With a reason\n   Reason: We never call the affected method\n", $output);
        $this->assertStringContainsString(" * vendor/package (1.0.0): Without a reason\n   Allowed by \"Without a reason\", no reason given\n", $output);
    }

    public function testTheJsonReportListsIgnoredAdvisoriesWithTheirReason(): void
    {
        [, $json] = $this->runNow(['--format' => 'json']);
        $report = json_decode($json, true, flags: JSON_THROW_ON_ERROR);

        $advisories = $report['ignored']['vendor/package']['advisories'];
        $this->assertSame('GHSA-1', $advisories['PKSA-1']['allowed_by']);
        $this->assertSame('We never call the affected method', $advisories['PKSA-1']['reason']);
        $this->assertNull($advisories['PKSA-2']['reason']);
    }

    public function testNothingIsListedForDriversThatCannotTell(): void
    {
        // e.g. the Enlightn driver, or a custom driver written for 4.0
        $this->bindPassingSecurityChecker(false, ['GHSA-1', 'Without a reason']);

        [, $output] = $this->runNow([]);
        [, $json] = $this->runNow(['--format' => 'json']);

        $this->assertStringNotContainsString('ignored by the allow list', $output);
        $this->assertStringContainsString('"ignored": {}', $json);
    }

    /**
     * @return array{0: int, 1: string}
     */
    private function runNow(array $parameters): array
    {
        $output = new BufferedOutput();
        $exitCode = Artisan::call('security-check:now', $parameters, $output);

        return [$exitCode, $output->fetch()];
    }
}
