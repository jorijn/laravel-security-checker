<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;
use Jorijn\LaravelSecurityChecker\Console\SecurityTeamsCommand;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;

/**
 * security-check:webhook and security-check:teams against a faked receiver.
 */
class WebhookChannelsTest extends TestCase
{
    private const WEBHOOK = 'https://hooks.example.net/security';

    private const TEAMS = 'https://prod-00.westeurope.logic.azure.com/workflows/abc/triggers/manual/paths/invoke';

    protected function setUp(): void
    {
        parent::setUp();

        Sleep::fake();
        Http::preventStrayRequests();
        Config::set('app.name', 'Test App');
        Config::set('laravel-security-checker.webhook.url', self::WEBHOOK);
        Config::set('laravel-security-checker.teams_webhook_url', self::TEAMS);
    }

    public function testWebhookPostsTheJsonReport(): void
    {
        Http::fake([self::WEBHOOK => Http::response('', 204)]);
        $this->bindFailingSecurityChecker();

        $this->artisan('security-check:webhook')->assertExitCode(0);

        Http::assertSent(function (Request $request) {
            $payload = json_decode($request->body(), true);

            return $request->url() === self::WEBHOOK
                && $request->method() === 'POST'
                && $request->hasHeader('Content-Type', 'application/json')
                && !$request->hasHeader('X-Signature-256')
                && $payload['event'] === 'report'
                && $payload['application']['name'] === 'Test App'
                && $payload['vulnerable_package_count'] === 1
                && $payload['packages'] === $this->getFakeVulnerabilityReport();
        });
    }

    public function testWebhookSignsTheBodyWhenASecretIsConfigured(): void
    {
        Config::set('laravel-security-checker.webhook.secret', 's3cret');
        Http::fake([self::WEBHOOK => Http::response('ok')]);
        $this->bindFailingSecurityChecker();

        $this->artisan('security-check:webhook')->assertExitCode(0);

        Http::assertSent(fn (Request $request) => $request->header('X-Signature-256')[0]
            === 'sha256='.hash_hmac('sha256', $request->body(), 's3cret'));
    }

    public function testNothingIsPostedWithoutVulnerabilitiesByDefault(): void
    {
        Http::fake();
        $this->bindPassingSecurityChecker();

        $this->artisan('security-check:webhook')->assertExitCode(0);
        $this->artisan('security-check:teams')->assertExitCode(0);

        Http::assertNothingSent();
    }

    public function testAnAllClearIsPostedWhenConfigured(): void
    {
        Config::set('laravel-security-checker.notify_even_without_vulnerabilities', 'yes');
        Http::fake();
        $this->bindPassingSecurityChecker();

        $this->artisan('security-check:webhook')->assertExitCode(0);
        $this->artisan('security-check:teams')->assertExitCode(0);

        Http::assertSentCount(2);
        Http::assertSent(fn (Request $request) => $request->url() === self::WEBHOOK
            && $request['vulnerable_package_count'] === 0);
        Http::assertSent(fn (Request $request) => $request->url() === self::TEAMS
            && $request['attachments'][0]['content']['body'][0]['text'] === '[Test App] No packages have known vulnerabilities');
    }

    public function testAMissingUrlIsAnErrorWithoutRunningTheCheck(): void
    {
        Config::set('laravel-security-checker.webhook.url', ' ');
        Config::set('laravel-security-checker.teams_webhook_url', null);
        Http::fake();

        $this->artisan('security-check:webhook')
            ->expectsOutputToContain('No webhook URL has been configured, set LCS_WEBHOOK_URL.')
            ->assertExitCode(1);
        $this->artisan('security-check:teams')
            ->expectsOutputToContain('No Teams URL has been configured, set LCS_TEAMS_WEBHOOK.')
            ->assertExitCode(1);

        Http::assertNothingSent();
    }

    public function testARejectedPostFailsTheCommandWithoutRetrying(): void
    {
        Http::fake([self::WEBHOOK => Http::response('invalid payload', 400)]);
        $this->bindFailingSecurityChecker();

        $this->artisan('security-check:webhook')
            ->expectsOutputToContain('Could not deliver the security report via webhook: the receiver answered HTTP 400: invalid payload')
            ->assertExitCode(1);

        Http::assertSentCount(1);
    }

    public function testServerErrorsAreRetried(): void
    {
        Http::fake([self::TEAMS => Http::sequence()->push('', 502)->push('', 202)]);
        $this->bindFailingSecurityChecker();

        $this->artisan('security-check:teams')->assertExitCode(0);

        Http::assertSentCount(2);
    }

    public function testAFailedCheckIsAlertedThroughBothChannels(): void
    {
        Http::fake();
        $this->bindBrokenSecurityChecker();

        $this->artisan('security-check:webhook')->assertExitCode(2);
        $this->artisan('security-check:teams')->assertExitCode(2);

        Http::assertSent(fn (Request $request) => $request->url() === self::WEBHOOK
            && $request['event'] === 'check_failed'
            && $request['error'] === 'Could not reach Packagist: connection refused'
            && !isset($request['packages']));
        Http::assertSent(fn (Request $request) => $request->url() === self::TEAMS
            && $request['attachments'][0]['content']['body'][0]['text'] === '[Test App] The security check could not run'
            && $request['attachments'][0]['content']['body'][2]['text'] === 'Could not reach Packagist: connection refused');
    }

    public function testTheFailureAlertCanBeTurnedOff(): void
    {
        Config::set('laravel-security-checker.notify_on_failure', false);
        Http::fake();
        $this->bindBrokenSecurityChecker();

        $this->artisan('security-check:webhook')->assertExitCode(2);

        Http::assertNothingSent();
    }

    public function testTeamsPostsAnAdaptiveCard(): void
    {
        Http::fake();
        $this->bindFailingSecurityChecker();

        $this->artisan('security-check:teams')->assertExitCode(0);

        Http::assertSent(function (Request $request) {
            $attachment = $request['attachments'][0];
            $texts = array_column($attachment['content']['body'], 'text');

            return $request['type'] === 'message'
                && $attachment['contentType'] === 'application/vnd.microsoft.card.adaptive'
                && $attachment['content']['type'] === 'AdaptiveCard'
                && $texts[0] === '[Test App] 1 package has known vulnerabilities'
                && $texts[2] === '**bugsnag/bugsnag-laravel** (v2.0.1)'
                && $texts[3] === '- CVE-2016-5385: HTTP Proxy header vulnerability ([View](https://github.com/bugsnag/bugsnag-laravel/releases/tag/v2.0.2))';
        });
    }

    public function testTeamsCardsStayBelowTheTeamsSizeLimit(): void
    {
        $advisories = [];

        for ($i = 0; $i < 500; $i++) {
            $advisories["PKSA-$i"] = ['title' => str_repeat('Long title ', 10).$i, 'link' => 'https://example.com/'.$i, 'cve' => "CVE-2099-$i", 'severity' => 'high'];
        }

        $checker = \Mockery::mock(Checker::class);
        $checker->allows('check')->andReturns(['vendor/huge' => ['version' => '1.0.0', 'time' => null, 'advisories' => $advisories]]);
        $this->app->instance(Checker::class, $checker);
        Http::fake();

        $this->artisan('security-check:teams')->assertExitCode(0);

        Http::assertSent(function (Request $request) {
            $body = $request['attachments'][0]['content']['body'];
            $last = end($body)['text'];
            $listed = count($body) - 4; // title, path, package line, and the note

            return strlen($request->body()) <= SecurityTeamsCommand::MAX_BYTES
                && $last === (500 - $listed).' more advisories are not listed here, run `php artisan security-check:now` for the full report.';
        });
    }
}
