<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Mail;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;
use Jorijn\LaravelSecurityChecker\Severity;
use PHPUnit\Framework\Attributes\TestWith;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * LCS_MINIMUM_SEVERITY: which advisories are left out, for every command.
 */
class MinimumSeverityTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $checker = \Mockery::mock(Checker::class);
        $checker->allows('check')->andReturns([
            'vendor/mixed' => [
                'version' => '1.0.0',
                'time' => null,
                'advisories' => [
                    'PKSA-low' => ['title' => 'Low one', 'link' => '', 'cve' => null, 'severity' => 'low'],
                    'PKSA-critical' => ['title' => 'Critical one', 'link' => '', 'cve' => null, 'severity' => 'critical'],
                ],
            ],
            'vendor/only-medium' => [
                'version' => '1.0.0',
                'time' => null,
                'advisories' => [
                    'PKSA-medium' => ['title' => 'Medium one', 'link' => '', 'cve' => null, 'severity' => 'medium'],
                ],
            ],
            'vendor/unknown' => [
                'version' => '1.0.0',
                'time' => null,
                'advisories' => [
                    'PKSA-null' => ['title' => 'Unknown one', 'link' => '', 'cve' => null, 'severity' => null],
                    // a driver written for 4.0 does not know the key at all
                    'PKSA-missing' => ['title' => 'Missing one', 'link' => '', 'cve' => null],
                ],
            ],
        ]);
        $this->app->instance(Checker::class, $checker);
    }

    public function testEverythingIsReportedByDefault(): void
    {
        $this->assertSame(
            ['PKSA-low', 'PKSA-critical', 'PKSA-medium', 'PKSA-null', 'PKSA-missing'],
            $this->reportedAdvisories()
        );
    }

    public function testAdvisoriesBelowTheMinimumAndPackagesLeftEmptyAreDropped(): void
    {
        Config::set('laravel-security-checker.minimum_severity', 'high');

        // Unknown severity is always kept: it might be critical.
        $this->assertSame(['PKSA-critical', 'PKSA-null', 'PKSA-missing'], $this->reportedAdvisories());
    }

    public function testTheMinimumItselfIsIncluded(): void
    {
        Config::set('laravel-security-checker.minimum_severity', 'medium');

        $this->assertSame(
            ['PKSA-critical', 'PKSA-medium', 'PKSA-null', 'PKSA-missing'],
            $this->reportedAdvisories()
        );
    }

    #[TestWith(['HIGH'])]
    #[TestWith([' high '])]
    public function testTheSettingIsCaseAndWhitespaceInsensitive(string $value): void
    {
        Config::set('laravel-security-checker.minimum_severity', $value);

        $this->assertSame(['PKSA-critical', 'PKSA-null', 'PKSA-missing'], $this->reportedAdvisories());
    }

    #[TestWith([''])]
    #[TestWith([null])]
    public function testAnEmptySettingReportsEverything(?string $value): void
    {
        Config::set('laravel-security-checker.minimum_severity', $value);

        $this->assertCount(5, $this->reportedAdvisories());
    }

    public function testAnInvalidSettingIsIgnoredWithAWarning(): void
    {
        Config::set('laravel-security-checker.minimum_severity', 'severe');

        $this->artisan('security-check:now')
            ->expectsOutputToContain('minimum_severity "severe" is invalid and has been ignored')
            ->assertExitCode(1);

        $this->assertCount(5, $this->reportedAdvisories());
    }

    public function testTheExitCodeFollowsTheFilteredReport(): void
    {
        Config::set('laravel-security-checker.minimum_severity', 'critical');
        $this->artisan('security-check:now')->assertExitCode(1);

        // Nothing at or above "critical" in a report with only a low advisory: exit 0.
        $checker = \Mockery::mock(Checker::class);
        $checker->allows('check')->andReturns(['vendor/low' => [
            'version' => '1.0.0',
            'time' => null,
            'advisories' => ['PKSA-low' => ['title' => 'Low', 'link' => '', 'cve' => null, 'severity' => 'low']],
        ]]);
        $this->app->instance(Checker::class, $checker);

        $this->artisan('security-check:now')
            ->expectsOutputToContain('[OK] 0 packages have known vulnerabilities')
            ->assertExitCode(0);
    }

    public function testTheMailOnlyContainsTheRemainingAdvisories(): void
    {
        Mail::fake();
        Config::set('laravel-security-checker.minimum_severity', 'critical');
        Config::set('laravel-security-checker.recipients', ['security@example.net']);

        $this->artisan('security-check:email')->assertExitCode(0);

        Mail::assertSent(SecurityMail::class, fn (SecurityMail $mail) => array_keys($mail->getCheckResult()) === ['vendor/mixed', 'vendor/unknown']);
    }

    public function testTheTextReportShowsTheSeverity(): void
    {
        $output = new BufferedOutput();
        Artisan::call('security-check:now', [], $output);

        $this->assertStringContainsString(' * [critical] Critical one', $output->fetch());
    }

    public function testSeverityComparison(): void
    {
        $this->assertTrue(Severity::meets('critical', 'high'));
        $this->assertTrue(Severity::meets('high', 'high'));
        $this->assertFalse(Severity::meets('medium', 'high'));
        $this->assertTrue(Severity::meets(null, 'critical'));
        $this->assertTrue(Severity::meets('bogus', 'critical'));
        $this->assertSame('medium', Severity::normalize('Moderate'));
        $this->assertNull(Severity::normalize(3));
    }

    /**
     * @return array<int, string>
     */
    private function reportedAdvisories(): array
    {
        $output = new BufferedOutput();
        Artisan::call('security-check:now', ['--format' => 'json'], $output);

        // a warning may precede the document in a buffered output (no separate stderr)
        $text = $output->fetch();
        $report = json_decode(substr($text, (int) strpos($text, '{')), true, flags: JSON_THROW_ON_ERROR);

        return array_merge([], ...array_values(array_map(
            fn (array $package) => array_keys($package['advisories']),
            $report['packages']
        )));
    }
}
