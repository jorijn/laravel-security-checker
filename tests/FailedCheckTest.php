<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityCheckFailedMail;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;
use Jorijn\LaravelSecurityChecker\Notifications\SecurityCheckFailedSlackNotification;
use Jorijn\LaravelSecurityChecker\Notifications\SecuritySlackNotification;
use PHPUnit\Framework\Attributes\TestWith;

/**
 * What every command does when the check itself cannot run: exit code 2, and an alert through
 * the command's own channel, so a broken check never looks like "no vulnerabilities".
 */
class FailedCheckTest extends TestCase
{
    private const WEBHOOK = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX';

    public function testNowCommandExitsWithTwoAndExplainsWhy(): void
    {
        $this->bindBrokenSecurityChecker();

        $this->artisan('security-check:now')
            ->expectsOutputToContain('The security check could not run: Could not reach Packagist: connection refused')
            ->expectsOutputToContain('This does not mean that there are no vulnerabilities')
            ->doesntExpectOutputToContain('[OK]')
            ->assertExitCode(2);
    }

    public function testAnyExceptionFromADriverCountsAsAFailedCheck(): void
    {
        // e.g. a custom driver that does not know about CheckFailedException
        $this->bindBrokenSecurityChecker(new \RuntimeException('custom driver exploded'));

        $this->artisan('security-check:now')
            ->expectsOutputToContain('custom driver exploded')
            ->assertExitCode(2);
    }

    public function testTheFailureIsLogged(): void
    {
        Log::spy();
        $this->bindBrokenSecurityChecker();

        $this->artisan('security-check:now')->assertExitCode(2);

        Log::shouldHaveReceived('error')->withArgs(fn ($message) => str_contains($message, 'could not run'));
    }

    public function testMailCommandMailsACheckCouldNotRunAlert(): void
    {
        Mail::fake();
        $this->bindBrokenSecurityChecker();
        Config::set('laravel-security-checker.recipients', ['a@example.net,b@example.net']);

        $this->artisan('security-check:email')->assertExitCode(2);

        Mail::assertNotSent(SecurityMail::class);
        Mail::assertSent(SecurityCheckFailedMail::class, function (SecurityCheckFailedMail $mail) {
            return array_column($mail->to, 'address') === ['a@example.net', 'b@example.net']
                && $mail->reason === 'Could not reach Packagist: connection refused'
                && $mail->composerLock === base_path('composer.lock');
        });
    }

    public function testSlackCommandPostsACheckCouldNotRunAlert(): void
    {
        Notification::fake();
        $this->bindBrokenSecurityChecker();
        Config::set('laravel-security-checker.slack_webhook_url', self::WEBHOOK);

        $this->artisan('security-check:slack')->assertExitCode(2);

        Notification::assertNotSentTo(new AnonymousNotifiable, SecuritySlackNotification::class);
        Notification::assertSentTo(
            new AnonymousNotifiable,
            SecurityCheckFailedSlackNotification::class,
            fn ($notification, $channels, $notifiable) => $notifiable->routes['slack'] === self::WEBHOOK
                && $notification->reason === 'Could not reach Packagist: connection refused'
        );
    }

    #[TestWith([false])]
    #[TestWith(['false'])]
    #[TestWith(['0'])]
    public function testTheAlertCanBeTurnedOff(mixed $value): void
    {
        Mail::fake();
        Notification::fake();
        $this->bindBrokenSecurityChecker();
        Config::set('laravel-security-checker.notify_on_failure', $value);
        Config::set('laravel-security-checker.recipients', ['a@example.net']);
        Config::set('laravel-security-checker.slack_webhook_url', self::WEBHOOK);

        // the exit code still tells the scheduler that something is wrong
        $this->artisan('security-check:email')->assertExitCode(2);
        $this->artisan('security-check:slack')->assertExitCode(2);

        Mail::assertNothingSent();
        Notification::assertNothingSent();
    }

    public function testAnUnrecognisedNotifyOnFailureValueKeepsTheAlertOn(): void
    {
        Mail::fake();
        $this->bindBrokenSecurityChecker();
        Config::set('laravel-security-checker.notify_on_failure', 'nonsense');
        Config::set('laravel-security-checker.recipients', ['a@example.net']);

        $this->artisan('security-check:email')->assertExitCode(2);

        Mail::assertSent(SecurityCheckFailedMail::class);
    }

    public function testWithoutRecipientsTheFailureIsStillReported(): void
    {
        Mail::fake();
        $this->bindBrokenSecurityChecker();
        Config::set('laravel-security-checker.recipients', []);

        $this->artisan('security-check:email')
            ->expectsOutputToContain('The security check could not run')
            ->assertExitCode(2);

        Mail::assertNothingSent();
    }

    public function testAFailingAlertDoesNotHideTheOriginalProblem(): void
    {
        $this->bindBrokenSecurityChecker();
        Config::set('laravel-security-checker.recipients', ['a@example.net']);
        Mail::shouldReceive('to')->andThrow(new \RuntimeException('SMTP server down'));

        $this->artisan('security-check:email')
            ->expectsOutputToContain('The security check could not run: Could not reach Packagist')
            ->expectsOutputToContain('Sending the alert about this failed as well: SMTP server down')
            ->assertExitCode(2);
    }

    public function testFailedCheckMailRendersTheReason(): void
    {
        Config::set('app.name', 'Test App');

        $mail = new SecurityCheckFailedMail('Could not reach Packagist: connection refused', '/srv/app/composer.lock');
        $html = $mail->render();

        $this->assertSame('[Test App] The security check could not run', $mail->build()->subject);
        $this->assertStringContainsString('Could not reach Packagist: connection refused', $html);
        $this->assertStringContainsString('/srv/app/composer.lock', $html);
        $this->assertMatchesRegularExpression('#<strong[^>]*>not</strong>#', $html);
    }

    public function testFailedCheckMailIsTranslated(): void
    {
        $this->app->setLocale('nl');

        $mail = new SecurityCheckFailedMail('timeout', '/srv/app/composer.lock');

        $this->assertStringContainsString('De beveiligingscheck kon niet draaien', $mail->build()->subject);
    }

    public function testFailedCheckSlackNotificationContainsTheReason(): void
    {
        $notification = new SecurityCheckFailedSlackNotification('Could not reach Packagist: timeout', '/srv/app/composer.lock');
        $message = $notification->toSlack();

        $this->assertSame(['slack'], $notification->via());
        $this->assertSame('error', $message->level);
        $this->assertSame('*The security check could not run*', $message->content);
        $this->assertStringContainsString('> Could not reach Packagist: timeout', $message->attachments[0]->content);
        $this->assertStringContainsString('`/srv/app/composer.lock`', $message->attachments[0]->content);
    }
}
