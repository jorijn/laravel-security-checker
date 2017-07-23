<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use SensioLabs\Security\SecurityChecker;

class SecurityCommandTest extends TestCase
{
    public function testFireMethod()
    {
        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->shouldReceive('check')->andReturn([]);

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);

        // call the command
        $res = $this->artisan('security-check:now');

        // and check if it returns exit-code 0
        $this->assertEquals($res, 0);
    }
}
