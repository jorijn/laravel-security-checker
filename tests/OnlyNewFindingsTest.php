<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Http\Client\Request;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Sleep;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;
use Jorijn\LaravelSecurityChecker\Notifications\SecuritySlackNotification;

/**
 * LCS_NOTIFY_ONLY_NEW: every channel reports a finding once.
 */
class OnlyNewFindingsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Sleep::fake();
        // The array store lives as long as the test, so it plays a persistent cache between runs.
        Config::set('cache.default', 'array');
        Config::set('laravel-security-checker.notify_only_new', true);
        Config::set('laravel-security-checker.recipients', ['security@example.net']);
        Config::set('laravel-security-checker.slack_webhook_url', 'https://hooks.slack.com/services/T0/B0/X');
        Config::set('laravel-security-checker.webhook.url', 'https://hooks.example.net/security');
    }

    public function testTheFirstRunReportsEverythingAndTheNextOnlyWhatIsNew(): void
    {
        Mail::fake();

        $this->findings(['vendor/a' => ['PKSA-1']]);
        $this->artisan('security-check:email')->assertExitCode(0);

        // Same findings: nothing is sent.
        $this->artisan('security-check:email')->assertExitCode(0);

        // A new advisory for a known package, and a new package: only those are sent.
        $this->findings(['vendor/a' => ['PKSA-1', 'PKSA-2'], 'vendor/b' => ['PKSA-3']]);
        $this->artisan('security-check:email')->assertExitCode(0);

        $sent = Mail::sent(SecurityMail::class)->map(fn (SecurityMail $mail) => $this->ids($mail->getCheckResult()))->all();
        $this->assertSame([['vendor/a|PKSA-1'], ['vendor/a|PKSA-2', 'vendor/b|PKSA-3']], $sent);
    }

    public function testAFindingThatDisappearsAndComesBackIsNewAgain(): void
    {
        Mail::fake();

        $this->findings(['vendor/a' => ['PKSA-1']]);
        $this->artisan('security-check:email');
        $this->findings([]);
        $this->artisan('security-check:email');
        $this->findings(['vendor/a' => ['PKSA-1']]);
        $this->artisan('security-check:email');

        Mail::assertSentCount(2);
    }

    public function testEveryChannelHasItsOwnMemory(): void
    {
        Mail::fake();
        Notification::fake();
        Http::fake();

        $this->findings(['vendor/a' => ['PKSA-1']]);
        $this->artisan('security-check:email');
        $this->artisan('security-check:email');
        $this->artisan('security-check:slack');
        $this->artisan('security-check:webhook');

        Mail::assertSentCount(1);
        Notification::assertSentToTimes(new AnonymousNotifiable(), SecuritySlackNotification::class, 1);
        Http::assertSent(fn (Request $request) => $request['only_new_findings'] === true
            && array_keys($request['packages']) === ['vendor/a']);
    }

    public function testAFailedDeliveryKeepsTheFindingsNew(): void
    {
        Http::fakeSequence('hooks.example.net/*')->push('nope', 400)->push('', 204);

        $this->findings(['vendor/a' => ['PKSA-1']]);
        $this->artisan('security-check:webhook')->assertExitCode(1);
        $this->artisan('security-check:webhook')->assertExitCode(0);

        Http::assertSentCount(2);
        Http::assertSent(fn (Request $request) => isset($request['packages']['vendor/a']));
    }

    public function testNothingIsRememberedWhenTheCheckFails(): void
    {
        Mail::fake();

        $this->findings(['vendor/a' => ['PKSA-1']]);
        $this->artisan('security-check:email');
        $this->bindBrokenSecurityChecker();
        $this->artisan('security-check:email')->assertExitCode(2);
        $this->findings(['vendor/a' => ['PKSA-1']]);
        $this->artisan('security-check:email');

        // Only the first report (plus the "could not run" alert); the failed run kept the state.
        Mail::assertSent(SecurityMail::class, 1);
    }

    public function testAnAllClearIsStillSentWhenConfigured(): void
    {
        Mail::fake();
        Config::set('laravel-security-checker.notify_even_without_vulnerabilities', true);

        $this->findings([]);
        $this->artisan('security-check:email');
        $this->artisan('security-check:email');

        Mail::assertSentCount(2);
    }

    public function testAnUnavailableCacheReportsEverything(): void
    {
        Mail::fake();
        Config::set('laravel-security-checker.state_cache_store', 'does-not-exist');

        $this->findings(['vendor/a' => ['PKSA-1']]);
        $this->artisan('security-check:email')->assertExitCode(0);
        $this->artisan('security-check:email')->assertExitCode(0);

        Mail::assertSentCount(2);
    }

    public function testTheStateLivesInTheConfiguredStore(): void
    {
        Mail::fake();
        Config::set('cache.stores.security', ['driver' => 'array']);
        Config::set('laravel-security-checker.state_cache_store', 'security');

        $this->findings(['vendor/a' => ['PKSA-1']]);
        $this->artisan('security-check:email');

        $key = 'laravel-security-checker:reported:security-check:email:'.sha1(realpath(base_path('composer.lock')) ?: base_path('composer.lock'));
        $this->assertSame(['vendor/a|PKSA-1'], Cache::store('security')->get($key));
        $this->assertNull(Cache::store('array')->get($key));
    }

    public function testOffByDefault(): void
    {
        Mail::fake();
        Config::set('laravel-security-checker.notify_only_new', false);

        $this->findings(['vendor/a' => ['PKSA-1']]);
        $this->artisan('security-check:email');
        $this->artisan('security-check:email');

        Mail::assertSentCount(2);
    }

    /**
     * @param array<string, array<int, string>> $findings package => advisory ids
     */
    private function findings(array $findings): void
    {
        $report = [];

        foreach ($findings as $package => $ids) {
            $report[$package] = ['version' => '1.0.0', 'time' => null, 'advisories' => []];

            foreach ($ids as $id) {
                $report[$package]['advisories'][$id] = ['title' => "Advisory $id", 'link' => '', 'cve' => null, 'severity' => null];
            }
        }

        $checker = \Mockery::mock(Checker::class);
        $checker->allows('check')->andReturns($report);
        $this->app->instance(Checker::class, $checker);
    }

    /**
     * @return array<int, string>
     */
    private function ids(array $report): array
    {
        $ids = [];

        foreach ($report as $package => $details) {
            foreach (array_keys($details['advisories']) as $id) {
                $ids[] = "$package|$id";
            }
        }

        return $ids;
    }
}
