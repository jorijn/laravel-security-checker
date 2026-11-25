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

        // And the advisories really came from the (fake) GitHub archive, not from a cache.
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
     * Characterises today's behaviour when the advisory source is down: the exception bubbles
     * up and the command exits non-zero. Not pretty, but at least not silent; 4.0 will give
     * this its own exit code.
     */
    public function testUnreachableAdvisorySourceFailsLoudly(): void
    {
        $this->breakAdvisorySource('refuse');

        $process = $this->artisan(['security-check:now']);

        $this->assertNotSame(0, $process->getExitCode());
        $this->assertStringNotContainsString('[OK]', $process->getOutput());
    }

    public function testAdvisorySourceHttpErrorFailsLoudly(): void
    {
        $this->breakAdvisorySource('http-error:503');

        $process = $this->artisan(['security-check:now']);

        $this->assertNotSame(0, $process->getExitCode());
        $this->assertStringNotContainsString('[OK]', $process->getOutput());
        $this->assertStringContainsString('503', $process->getOutput().$process->getErrorOutput());
    }
}
