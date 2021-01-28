<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

class SecurityCommandTest extends TestCase
{
    public function testFireMethod()
    {
        $this->setSafeBasePath();

        $this->assertEquals(0, $this->artisan(
            'security-check:now'
        ));
    }

    public function testFireMethodWithVulnerabilitiesFound()
    {
        $this->setVulnerableBasePath();

        $this->assertEquals(1, $this->artisan(
            'security-check:now'
        ));
    }
}
