<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Mail;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;

class SecurityMailCommandTest extends TestCase
{
    /**
     * Tests if the email will be sent
     */
    public function testFireMethod()
    {
        Mail::fake();

        $this->bindFailingSecurityChecker();

        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);

        if (method_exists($this, 'withoutMockingConsoleOutput')) {
            $this->withoutMockingConsoleOutput();
        }

        // execute the command
        $res = $this->artisan('security-check:email');

        Mail::assertSent(SecurityMail::class, function (SecurityMail $mail) {
            return $mail->hasTo('recipient@example.net');
        });
        
        // assert that the exit-code is 0
        $this->assertEquals(0, $res);
    }

    /**
     * Tests if the email will cancel if there are no recipients
     */
    public function testFireMethodWithoutRecipients()
    {
        Mail::fake();

        $this->bindFailingSecurityChecker();

        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ ]);

        if (method_exists($this, 'withoutMockingConsoleOutput')) {
            $this->withoutMockingConsoleOutput();
        }

        // execute the command
        $res = $this->artisan('security-check:email');

        // check that the mail wasn't sent
        Mail::assertNotSent(SecurityMail::class);

        // assert that the exit-code is 1
        $this->assertEquals(1, $res);
    }

    /**
     * Tests if the email will cancel if there are no vulnerabilities
     */
    public function testFireMethodWithoutVulnerabilities()
    {
        Mail::fake();

        $this->bindPassingSecurityChecker();

        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);
        Config::set('laravel-security-checker.notify_even_without_vulnerabilities', false);

        if (method_exists($this, 'withoutMockingConsoleOutput')) {
            $this->withoutMockingConsoleOutput();
        }

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
        Mail::fake();

        $this->bindPassingSecurityChecker();

        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);
        Config::set('laravel-security-checker.notify_even_without_vulnerabilities', true);

        if (method_exists($this, 'withoutMockingConsoleOutput')) {
            $this->withoutMockingConsoleOutput();
        }

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
