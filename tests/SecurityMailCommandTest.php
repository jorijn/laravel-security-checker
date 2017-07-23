<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Mail;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;
use SensioLabs\Security\SecurityChecker;

class SecurityMailCommandTest extends TestCase
{
    /**
     * @var array
     */
    protected $exampleCheckOutput;
    
    /**
     * Set Up
     */
    public function setUp()
    {
        parent::setUp();

        // declare fake vulnerability
        $this->exampleCheckOutput = [
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
        $securityCheckerMock->shouldReceive('check')->andReturn($this->exampleCheckOutput);

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);

        // declare testing mode on the mailer
        Mail::fake();
    }

    /**
     * Tests if the email will be sent
     */
    public function testFireMethod()
    {
        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);

        // execute the command
        $res = $this->artisan('security-check:email');

        Mail::assertSent(SecurityMail::class, function (SecurityMail $mail) {
            return $mail->hasTo('recipient@example.net')
                && $this->exampleCheckOutput === $mail->getCheckResult();
        });
        
        // assert that the exit-code is 0
        $this->assertEquals($res, 0);
    }

    /**
     * Tests if the email will cancel if there are no recipients
     */
    public function testFireMethodWithoutRecipients()
    {
        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ ]);

        // execute the command
        $res = $this->artisan('security-check:email');

        // check that the mail wasn't sent
        Mail::assertNotSent(SecurityMail::class);

        // assert that the exit-code is 1
        $this->assertEquals($res, 1);
    }

    /**
     * Tests if the email will cancel if there are no vulnerabilities
     */
    public function testFireMethodWithoutVulnerabilities()
    {
        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);
        Config::set('laravel-security-checker.email_even_without_vulnerabilities', false);

        // we have to re-bind the mockery instance for this since our parent one does hold
        // fake vulnerabilities.
        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->shouldReceive('check')->andReturn([ ]);

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);

        // execute the command
        $res = $this->artisan('security-check:email');

        // check that the mail wasn't sent
        Mail::assertNotSent(SecurityMail::class);

        // assert that the exit-code is 0
        $this->assertEquals($res, 0);
    }

    /**
     * Tests if the email will cancel if there are no vulnerabilities
     */
    public function testFireMethodWithoutVulnerabilitiesWithSending()
    {
        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);
        Config::set('laravel-security-checker.email_even_without_vulnerabilities', true);

        // we have to re-bind the mockery instance for this since our parent one does hold
        // fake vulnerabilities.
        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->shouldReceive('check')->andReturn([ ]);

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);

        // execute the command
        $res = $this->artisan('security-check:email');

        // check that the mail was sent
        Mail::assertSent(SecurityMail::class, function (SecurityMail $mail) {
            return $mail->hasTo('recipient@example.net')
                && [ ] === $mail->getCheckResult();
        });

        // assert that the exit-code is 0
        $this->assertEquals($res, 0);
    }
}
