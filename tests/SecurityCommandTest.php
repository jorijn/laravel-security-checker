<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;
use Symfony\Component\Console\Output\BufferedOutput;

class SecurityCommandTest extends TestCase
{
    public function testFireMethod()
    {
        $this->bindPassingSecurityChecker();

        $this->artisan(
            'security-check:now'
        )->assertExitCode(0);
    }

    public function testFireMethodWithVulnerabilitiesFound()
    {
        $this->bindFailingSecurityChecker();

        $this->artisan(
            'security-check:now'
        )->assertExitCode(1);
    }

    public function testFireMethodPassesConfiguredCheckerOptions()
    {
        Config::set('laravel-security-checker.exclude_dev', true);
        Config::set('laravel-security-checker.allow_list', ['CVE-2024-1234', 'Example vulnerability title']);

        $this->bindPassingSecurityChecker(true, ['CVE-2024-1234', 'Example vulnerability title']);

        $this->artisan(
            'security-check:now'
        )->assertExitCode(0);
    }

    public function testJsonFormatPrintsTheReportAsJson()
    {
        $this->bindFailingSecurityChecker();

        [$exitCode, $json] = $this->runNow(['--format' => 'json']);

        // The exit code does not depend on the format: CI keeps failing on vulnerabilities.
        $this->assertSame(1, $exitCode);
        $this->assertSame([
            'lock_file' => base_path('composer.lock'),
            'vulnerable_package_count' => 1,
            'advisory_count' => 1,
            'packages' => $this->getFakeVulnerabilityReport(),
        ], json_decode($json, true, flags: JSON_THROW_ON_ERROR));
    }

    public function testJsonFormatWithoutVulnerabilitiesKeepsPackagesAnObject()
    {
        $this->bindPassingSecurityChecker();

        [$exitCode, $json] = $this->runNow(['--format' => 'json']);

        $this->assertSame(0, $exitCode);
        // {} rather than []: consumers get the same type whether or not anything was found.
        $this->assertStringContainsString('"packages": {}', $json);
        $this->assertSame(0, json_decode($json, true, flags: JSON_THROW_ON_ERROR)['vulnerable_package_count']);
    }

    public function testJsonFormatReportsACheckThatCouldNotRun()
    {
        $this->bindBrokenSecurityChecker();

        [$exitCode, $output] = $this->runNow(['--format' => 'json']);

        $this->assertSame(2, $exitCode);
        // A buffered output has no separate stderr, so the explanation precedes the document
        // here. In a real terminal it goes to stderr, which the e2e suite covers.
        $document = json_decode(substr($output, (int) strpos($output, '{')), true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame('Could not reach Packagist: connection refused', $document['error']);
        $this->assertArrayNotHasKey('packages', $document);
    }

    public function testUnknownFormatFailsWithoutRunningTheCheck()
    {
        $checker = \Mockery::mock(Checker::class);
        $checker->expects('check')->never();
        $this->app->instance(Checker::class, $checker);

        $this->artisan('security-check:now', ['--format' => 'xml'])
            ->expectsOutputToContain('Unknown --format "xml", expected one of: text, json.')
            ->assertExitCode(2);
    }

    public function testTextFormatIsTheDefault()
    {
        $this->bindFailingSecurityChecker();

        [, $default] = $this->runNow([]);
        [, $text] = $this->runNow(['--format' => 'text']);

        $this->assertStringContainsString('[CRITICAL] 1 package has known vulnerabilities', $default);
        $this->assertSame($default, $text);
    }

    /**
     * Artisan::call() with a BufferedOutput gives the exact bytes, which the JSON tests need;
     * PendingCommand only offers "contains" style assertions.
     *
     * @return array{0: int, 1: string}
     */
    private function runNow(array $parameters): array
    {
        $output = new BufferedOutput();
        $exitCode = Artisan::call('security-check:now', $parameters, $output);

        return [$exitCode, $output->fetch()];
    }
}
