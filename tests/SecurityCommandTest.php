<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;

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

        $this->bindPassingSecurityChecker();

        $this->artisan(
            'security-check:now'
        )->assertExitCode(0);
    }
}
