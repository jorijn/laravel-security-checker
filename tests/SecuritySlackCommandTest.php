<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Notification;
use Jorijn\LaravelSecurityChecker\Notifications\SecuritySlackNotification;
use Illuminate\Notifications\AnonymousNotifiable;

class SecuritySlackCommandTest extends TestCase
{
    /**
     * @var array
     */
    protected $exampleCheckOutput;

    /**
     * Tests if the notification get's sent
     */
    public function testHandleMethod(): void
    {
        Notification::fake();

        $this->bindFailingSecurityChecker();

        // set the recipient for testing
        Config::set(
            'laravel-security-checker.slack_webhook_url',
            'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
        );

        $this->artisan('security-check:slack')->assertExitCode(0);

        // https://github.com/laravel/framework/pull/21379
        Notification::assertSentTo(
            new AnonymousNotifiable,
            SecuritySlackNotification::class,
            function ($notification, $channels, $notifiable) {
                return $notifiable->routes['slack'] === config('laravel-security-checker.slack_webhook_url');
            }
        );
    }

    /**
     * Tests that no notification is sent if a Slack Webhook has not been configured.
     */
    public function testHandleMethodWithoutSlackWebHook(): void
    {
        Notification::fake();

        $this->bindFailingSecurityChecker();

        // set the recipient for testing
        Config::set('laravel-security-checker.slack_webhook_url', null);

        // Class should throw exception if no webhook is configured
        $this->expectException(\Exception::class);

        $this->artisan('security-check:slack')->assertExitCode(1);

        Notification::assertNotSentTo(
            new AnonymousNotifiable,
            SecuritySlackNotification::class
        );
    }

    /**
     * Test that no notification get's sent if there are no vulnerabilities
     */
    public function testHandleMethodWithoutVulnerabilities(): void
    {
        Notification::fake();

        $this->bindPassingSecurityChecker();

        // set the recipient for testing
        Config::set(
            'laravel-security-checker.slack_webhook_url',
            'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
        );

        $this->artisan('security-check:slack')->assertExitCode(0);

        // check that the notification wasn't sent
        Notification::assertNotSentTo(
            new AnonymousNotifiable,
            SecuritySlackNotification::class
        );
    }
}
