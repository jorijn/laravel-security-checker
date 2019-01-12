<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Notification;
use SensioLabs\Security\SecurityChecker;
use Jorijn\LaravelSecurityChecker\Notifications\SecuritySlackNotification;
use Illuminate\Notifications\AnonymousNotifiable;
use Mockery\CountValidator\Exception;

class SecuritySlackCommandTest extends TestCase
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
        $this->exampleCheckOutput = $this->getFakeVulnerabilityReport();

        // mock the security checker
        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->shouldReceive('check')->andReturn($this->exampleCheckOutput);

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);

        // declare testing mode on the notification
        Notification::fake();
    }

    /**
     * Tests if the notification get's sent
     */
    public function testHandleMethod()
    {
        // set the recipient for testing
        Config::set(
            'laravel-security-checker.slack_webhook_url',
            'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
        );

        // execute the command
        $res = $this->artisan('security-check:slack');

        // assert that the exit-code is 0
        $this->assertEquals($res, 0);

        // https://github.com/laravel/framework/pull/21379
        Notification::assertSentTo(
            new AnonymousNotifiable,
            SecuritySlackNotification::class,
            function ($notification, $channels, $notifiable) {
                return $notifiable->routes['slack'] == config('laravel-security-checker.slack_webhook_url');
            }
        );
    }

    /**
     * Tests that no notification is sent if a Slack Webhook has not been configured.
     */
    public function testHandleMethodWithoutSlackWebHook()
    {
        // set the recipient for testing
        Config::set('laravel-security-checker.slack_webhook_url', null);

        // Class should throw exception if no webhook is configured
        $this->expectException(\Exception::class);

        // execute the command
        $res = $this->artisan('security-check:slack');

        // assert that the exit-code is 1
        $this->assertEquals($res, 1);

        Notification::assertNotSentTo(
            new AnonymousNotifiable,
            SecuritySlackNotification::class
        );
    }

    /**
     * Test that no notification get's sent if there are no vulnerabilities
     */
    public function testHandleMethodWithoutVulnerabilities()
    {
        // set the recipient for testing
        Config::set(
            'laravel-security-checker.slack_webhook_url',
            'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
        );

        // we have to re-bind the mockery instance for this since our parent one does hold
        // fake vulnerabilities.
        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->shouldReceive('check')->andReturn([]);

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);

        // execute the command
        $res = $this->artisan('security-check:slack');

        // check that the notification wasn't sent
        Notification::assertNotSentTo(
            new AnonymousNotifiable,
            SecuritySlackNotification::class
        );

        // assert that the exit-code is 0
        $this->assertEquals($res, 0);
    }
}
