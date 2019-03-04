<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use SensioLabs\Security\Result;
use SensioLabs\Security\SecurityChecker;

class SecurityCommandTest extends TestCase
{
    public function testFireMethod()
    {
        $resultMock = \Mockery::mock(Result::class);
        $resultMock->shouldReceive('__toString')->andReturn(json_encode([]));

        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->shouldReceive('check')->andReturn($resultMock);

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);

        // call the command
        $res = $this->artisan('security-check:now');

        // and check if it returns exit-code 0
        $this->assertEquals($res, 0);
    }
}
