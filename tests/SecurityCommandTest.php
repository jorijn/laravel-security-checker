<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

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
}
