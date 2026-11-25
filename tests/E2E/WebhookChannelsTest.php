<?php

namespace Jorijn\LaravelSecurityChecker\Tests\E2E;

/**
 * `php artisan security-check:webhook` and `security-check:teams`: the POSTs as they really
 * leave the application.
 */
class WebhookChannelsTest extends E2ETestCase
{
    public function testWebhookPostsTheSameDocumentAsTheJsonOutput(): void
    {
        $url = 'http://127.0.0.1:'.static::$slackPort.'/hooks/security';
        $process = $this->artisan(['security-check:webhook'], [
            'LCS_WEBHOOK_URL' => $url,
            'LCS_WEBHOOK_SECRET' => 'e2e-secret',
        ]);

        $this->assertSame(0, $process->getExitCode(), $process->getOutput().$process->getErrorOutput());

        $requests = $this->slackRequests();
        $this->assertCount(1, $requests);
        $this->assertSame('POST', $requests[0]['method']);
        $this->assertSame('/hooks/security', $requests[0]['uri']);
        $this->assertStringStartsWith('application/json', (string) $requests[0]['content_type']);
        $this->assertStringStartsWith('jorijn/laravel-security-checker', (string) $requests[0]['user_agent']);
        // The receiver can verify the body with the shared secret.
        $this->assertSame('sha256='.hash_hmac('sha256', $requests[0]['body'], 'e2e-secret'), $requests[0]['signature']);

        $payload = json_decode($requests[0]['body'], true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame('report', $payload['event']);
        $this->assertSame(['name' => 'E2E App', 'url' => 'http://e2e.test', 'environment' => 'local'], $payload['application']);

        $json = json_decode($this->artisan(['security-check:now', '--format=json'])->getOutput(), true, flags: JSON_THROW_ON_ERROR);
        $this->assertFalse($payload['only_new_findings']);
        unset($payload['event'], $payload['application'], $payload['only_new_findings']);
        $this->assertSame($json, $payload);
    }

    public function testWebhookReportsARejectedPost(): void
    {
        $process = $this->artisan(['security-check:webhook'], [
            'LCS_WEBHOOK_URL' => 'http://127.0.0.1:'.static::$slackPort.'/hooks/status/410',
        ]);

        $this->assertSame(1, $process->getExitCode());
        $this->assertStringContainsString('Could not deliver the security report via webhook: the receiver answered HTTP 410', $process->getOutput().$process->getErrorOutput());
        $this->assertStringContainsString('could not deliver the security report via webhook', $this->appLog());
    }

    public function testWebhookAlertsWhenTheCheckCannotRun(): void
    {
        $this->breakAdvisorySource('refuse');

        $process = $this->artisan(['security-check:webhook'], [
            'LCS_WEBHOOK_URL' => 'http://127.0.0.1:'.static::$slackPort.'/hooks/security',
        ]);

        $this->assertSame(2, $process->getExitCode());

        $payload = json_decode($this->slackRequests()[0]['body'] ?? 'null', true);
        $this->assertSame('check_failed', $payload['event']);
        $this->assertStringContainsString('Could not reach Packagist', $payload['error']);
    }

    public function testTeamsPostsAnAdaptiveCard(): void
    {
        $process = $this->artisan(['security-check:teams'], [
            'LCS_TEAMS_WEBHOOK' => 'http://127.0.0.1:'.static::$slackPort.'/workflows/abc/triggers/manual/paths/invoke',
        ]);

        $this->assertSame(0, $process->getExitCode(), $process->getOutput().$process->getErrorOutput());

        $requests = $this->slackRequests();
        $this->assertCount(1, $requests);

        $payload = json_decode($requests[0]['body'], true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame('message', $payload['type']);
        $this->assertSame('application/vnd.microsoft.card.adaptive', $payload['attachments'][0]['contentType']);

        $card = $payload['attachments'][0]['content'];
        $this->assertSame('AdaptiveCard', $card['type']);

        $texts = array_column($card['body'], 'text');
        $this->assertSame('[E2E App] 2 packages have known vulnerabilities', $texts[0]);
        $this->assertSame('Security Check Report: `'.static::$appPath.'/composer.lock`', $texts[1]);
        $this->assertMatchesRegularExpression('/^\*\*laravel\/framework\*\* \(\d+\.\d+\.\d+\)$/', $texts[2]);
        $this->assertContains(
            '- [critical] CVE-2099-0001: E2E fixture: framework advisory with a CVE ([View](https://example.com/advisories/CVE-2099-0001))',
            $texts
        );
        $this->assertContains(
            '- E2E fixture: framework advisory without a CVE ([View](https://example.com/advisories/no-cve))',
            $texts
        );
    }

    public function testTeamsWithoutAUrlFails(): void
    {
        $process = $this->artisan(['security-check:teams']);

        $this->assertSame(1, $process->getExitCode());
        $this->assertStringContainsString('No Teams URL has been configured, set LCS_TEAMS_WEBHOOK.', $process->getOutput().$process->getErrorOutput());
        $this->assertSame([], $this->slackRequests());
        $this->assertSame([], $this->advisoryRequests(), 'the check must not run without a place to report to');
    }
}
