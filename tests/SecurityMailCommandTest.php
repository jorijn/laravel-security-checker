<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;
use PHPUnit\Framework\Attributes\DataProvider;
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
     * Tests if the configured checker options are passed to the security checker
     */
    public function testFireMethodPassesConfiguredCheckerOptions(): void
    {
        Config::set('laravel-security-checker.exclude_dev', true);
        Config::set('laravel-security-checker.allow_list', ['CVE-2024-1234', 'Example vulnerability title']);

        $this->bindPassingSecurityChecker(true, ['CVE-2024-1234', 'Example vulnerability title']);

        $this->artisan('security-check:email')->assertExitCode(0);
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

    /**
     * Config values reach us as strings when they come from .env (or a published config), so the
     * common spellings of "yes" must be honoured, not only a real boolean `true`.
     */
    #[DataProvider('truthyValues')]
    public function testNotifyWithoutVulnerabilitiesAcceptsTruthyValues(mixed $value): void
    {
        Mail::fake();

        $this->bindPassingSecurityChecker();

        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);
        Config::set('laravel-security-checker.notify_even_without_vulnerabilities', $value);

        $this->artisan('security-check:email')->assertExitCode(0);

        Mail::assertSent(SecurityMail::class);
    }

    #[DataProvider('falsyValues')]
    public function testNotifyWithoutVulnerabilitiesIgnoresFalsyValues(mixed $value): void
    {
        Mail::fake();

        $this->bindPassingSecurityChecker();

        Config::set('laravel-security-checker.recipients', [ 'recipient@example.net' ]);
        Config::set('laravel-security-checker.notify_even_without_vulnerabilities', $value);

        $this->artisan('security-check:email')->assertExitCode(0);

        Mail::assertNotSent(SecurityMail::class);
    }

    public static function truthyValues(): array
    {
        return [[true], ['true'], ['1'], [1], ['yes'], ['on'], ['TRUE']];
    }

    public static function falsyValues(): array
    {
        // 'nonsense' guards the safe default: an unrecognised value must not start sending mail
        return [[false], [null], [''], ['false'], ['0'], [0], ['no'], ['off'], ['nonsense']];
    }

    /**
     * LCS_MAIL_TO can only hold a single string, so several recipients end up comma-separated.
     */
    #[DataProvider('recipientConfigurations')]
    public function testRecipientsAreNormalized(mixed $configured, array $expected): void
    {
        Mail::fake();

        $this->bindFailingSecurityChecker();

        Config::set('laravel-security-checker.recipients', $configured);

        $this->artisan('security-check:email')->assertExitCode(0);

        Mail::assertSent(SecurityMail::class, function (SecurityMail $mail) use ($expected) {
            return array_column($mail->to, 'address') === $expected;
        });
    }

    public static function recipientConfigurations(): array
    {
        return [
            'single address' => [['a@example.net'], ['a@example.net']],
            'comma separated' => [['a@example.net,b@example.net'], ['a@example.net', 'b@example.net']],
            'comma and spaces' => [[' a@example.net , b@example.net '], ['a@example.net', 'b@example.net']],
            'semicolon separated' => [['a@example.net;b@example.net'], ['a@example.net', 'b@example.net']],
            'trailing comma' => [['a@example.net,'], ['a@example.net']],
            'duplicates' => [['a@example.net', 'a@example.net,b@example.net'], ['a@example.net', 'b@example.net']],
            'published config as plain string' => ['a@example.net,b@example.net', ['a@example.net', 'b@example.net']],
            'mixed with empty entries' => [[null, '', 'a@example.net'], ['a@example.net']],
        ];
    }

    /**
     * Only separators and blanks must count as "no recipients", so this still fails loudly.
     */
    public function testOnlySeparatorsMeansNoRecipients(): void
    {
        Mail::fake();

        $this->bindFailingSecurityChecker();

        Config::set('laravel-security-checker.recipients', [ ' , ; ' ]);

        $this->artisan('security-check:email')->assertExitCode(1);

        Mail::assertNotSent(SecurityMail::class);
    }
}
