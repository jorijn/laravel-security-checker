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
    public function testFireMethod(): void
    {
        Mail::fake();

        $this->bindFailingSecurityChecker();

        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);

        // execute the command
        $this->artisan('security-check:email')->assertExitCode(0);

        Mail::assertSent(SecurityMail::class, function (SecurityMail $mail) {
            return $mail->hasTo('recipient@example.net');
        });
    }

    /**
     * Tests if the email will cancel if there are no recipients
     */
    public function testFireMethodWithoutRecipients(): void
    {
        Mail::fake();

        $this->bindFailingSecurityChecker();

        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ ]);

        $this->artisan('security-check:email')->assertExitCode(1);

        // check that the mail wasn't sent
        Mail::assertNotSent(SecurityMail::class);
    }

    /**
     * Tests if the email will cancel if there are no vulnerabilities
     */
    public function testFireMethodWithoutVulnerabilities(): void
    {
        Mail::fake();

        $this->bindPassingSecurityChecker();

        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);
        Config::set('laravel-security-checker.notify_even_without_vulnerabilities', false);

       $this->artisan('security-check:email')->assertExitCode(0);

        // check that the mail wasn't sent
        Mail::assertNotSent(SecurityMail::class);
    }

    /**
     * Tests if the email will cancel if there are no vulnerabilities
     */
    public function testFireMethodWithoutVulnerabilitiesWithSending(): void
    {
        Mail::fake();

        $this->bindPassingSecurityChecker();

        // set the recipient for testing
        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);
        Config::set('laravel-security-checker.notify_even_without_vulnerabilities', true);

        $this->artisan('security-check:email')->assertExitCode(0);

        // check that the mail was sent
        Mail::assertSent(SecurityMail::class, function (SecurityMail $mail) {
            return $mail->hasTo('recipient@example.net')
                && [ ] === $mail->getCheckResult();
        });
    }
}
