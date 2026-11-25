<?php

namespace Jorijn\LaravelSecurityChecker\Tests\E2E;

/**
 * `php artisan security-check:slack`: the webhook POST as laravel/slack-notification-channel
 * really sends it.
 */
class SlackCommandTest extends E2ETestCase
{
    public function testPostsTheReportToTheWebhook(): void
    {
        $process = $this->artisan(['security-check:slack'], ['LCS_SLACK_WEBHOOK' => $this->slackWebhookUrl()]);

        $this->assertSame(0, $process->getExitCode(), $process->getOutput().$process->getErrorOutput());

        $requests = $this->slackRequests();
        $this->assertCount(1, $requests);
        $this->assertSame('POST', $requests[0]['method']);
        $this->assertSame('/services/T000/B000/XXXX', $requests[0]['uri']);
        $this->assertStringStartsWith('application/json', (string) $requests[0]['content_type']);

        $payload = json_decode($requests[0]['body'], true);
        $this->assertSame('http://e2e.test', $payload['username']);
        $this->assertSame('*Security Check Report:* `'.static::$appPath.'/composer.lock`', $payload['text']);

        $attachment = $payload['attachments'][0]['text'];
        $this->assertStringStartsWith('2 packages have known vulnerabilities', $attachment);
        $this->assertMatchesRegularExpression('/^\*laravel\/framework \(\d+\.\d+\.\d+\)\*$/m', $attachment);
        $this->assertStringContainsString(' * [critical] CVE-2099-0001 E2E fixture: framework advisory with a CVE https://example.com/advisories/CVE-2099-0001', $attachment);
        $this->assertStringContainsString(' * E2E fixture: framework advisory without a CVE https://example.com/advisories/no-cve', $attachment);
        $this->assertStringContainsString('CVE-2099-0003', $attachment);
        $this->assertStringNotContainsString('CVE-2099-0009', $attachment);
        $this->assertSame(['text'], $payload['attachments'][0]['mrkdwn_in']);
    }

    public function testPostsNothingWithoutVulnerabilitiesByDefault(): void
    {
        $this->useAdvisories('clean');

        $process = $this->artisan(['security-check:slack'], ['LCS_SLACK_WEBHOOK' => $this->slackWebhookUrl()]);

        $this->assertSame(0, $process->getExitCode());
        $this->assertSame([], $this->slackRequests());
        $this->assertStringContainsString('no vulnerabilities were found, not sending a slack notification', $this->appLog());
    }

    public function testNotifyWithoutVulnerabilitiesPostsAnAllClear(): void
    {
        $this->useAdvisories('clean');

        $process = $this->artisan(['security-check:slack'], [
            'LCS_SLACK_WEBHOOK' => $this->slackWebhookUrl(),
            'LCS_NOTIFY_WITHOUT_VULNERABILITIES' => 'true',
        ]);

        $this->assertSame(0, $process->getExitCode());

        $requests = $this->slackRequests();
        $this->assertCount(1, $requests);
        $payload = json_decode($requests[0]['body'], true);
        $this->assertSame('No packages have known vulnerabilities', $payload['attachments'][0]['text']);
    }

    public function testNotifyWithoutVulnerabilitiesAcceptsCommonTruthyValues(): void
    {
        $this->useAdvisories('clean');

        $this->artisan(['security-check:slack'], [
            'LCS_SLACK_WEBHOOK' => $this->slackWebhookUrl(),
            'LCS_NOTIFY_WITHOUT_VULNERABILITIES' => '1',
        ]);

        // Used the same `!== true` comparison as the mail command, see MailCommandTest.
        $this->assertCount(1, $this->slackRequests());
    }

    public function testFailsWithoutAWebhook(): void
    {
        $process = $this->artisan(['security-check:slack']);

        $this->assertNotSame(0, $process->getExitCode());
        $this->assertStringContainsString('No Slack Webhook has been specified.', $process->getOutput().$process->getErrorOutput());
        $this->assertSame([], $this->advisoryRequests(), 'the check should not even start without a webhook');
    }

    public function testUnreachableAdvisorySourcePostsACheckCouldNotRunAlert(): void
    {
        $this->breakAdvisorySource('refuse');

        $process = $this->artisan(['security-check:slack'], ['LCS_SLACK_WEBHOOK' => $this->slackWebhookUrl()]);

        $this->assertSame(2, $process->getExitCode(), $process->getOutput().$process->getErrorOutput());

        $requests = $this->slackRequests();
        $this->assertCount(1, $requests);

        $payload = json_decode($requests[0]['body'], true);
        $this->assertSame('*The security check could not run*', $payload['text']);
        $this->assertSame('danger', $payload['attachments'][0]['color'] ?? null, 'posted as an error');
        $this->assertStringContainsString('`'.static::$appPath.'/composer.lock`', $payload['attachments'][0]['text']);
        $this->assertStringContainsString('Could not reach Packagist', $payload['attachments'][0]['text']);
    }
}
