<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

class SecurityCommandTest extends TestCase
{
    public function testFireMethod()
    {
        $this->bindPassingSecurityChecker();

        if (method_exists($this, 'withoutMockingConsoleOutput')) {
            $this->withoutMockingConsoleOutput();
        }

        $this->assertEquals(0, $this->artisan(
            'security-check:now'
        ));
    }

    public function testFireMethodWithVulnerabilitiesFound()
    {
        $this->bindFailingSecurityChecker();

        if (method_exists($this, 'withoutMockingConsoleOutput')) {
            $this->withoutMockingConsoleOutput();
        }

        $this->assertEquals(1, $this->artisan(
            'security-check:now'
        ));
    }
}
