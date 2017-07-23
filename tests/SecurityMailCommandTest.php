<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Mail;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;
use SensioLabs\Security\SecurityChecker;

class SecurityMailCommandTest extends TestCase
{
    public function testFireMethod()
    {
        // declare fake vulnerability
        $exampleCheckOutput = [
            "bugsnag/bugsnag-laravel" => [
                "version" => "v2.0.1",
                "advisories" => [
                    "bugsnag/bugsnag-laravel/CVE-2016-5385.yaml" => [
                        "title" => "HTTP Proxy header vulnerability",
                        "link" => "https://github.com/bugsnag/bugsnag-laravel/releases/tag/v2.0.2",
                        "cve" => "CVE-2016-5385"
                    ]
                ]
            ]
        ];

        // mock the security checker
        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->shouldReceive('check')->andReturn($exampleCheckOutput);

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);

        // declare testing mode on the mailer
        Mail::fake();

        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);

        // execute the command
        $res = $this->artisan('security-check:email');

        Mail::assertSent(SecurityMail::class, function (SecurityMail $mail) use ($exampleCheckOutput) {
            return $mail->hasTo('recipient@example.net')
                && $exampleCheckOutput === $mail->getCheckResult();
        });
        
        // assert that the exit-code is 0
        $this->assertEquals($res, 0);
    }
}
