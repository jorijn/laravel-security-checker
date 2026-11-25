<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use Jorijn\LaravelSecurityChecker\Formatter\JsonFormatter;

/**
 * POSTs the report as JSON to any URL, for receivers this package has no dedicated command for:
 * an incident tool, a chat bot, an automation platform, or your own endpoint.
 */
class SecurityWebhookCommand extends WebhookChannelCommand
{
    /**
     * @var string
     */
    protected $name = 'security-check:webhook';

    /**
     * @var string
     */
    protected $description = 'POSTs the vulnerability report as JSON to a URL of your choice.';

    protected function channelName(): string
    {
        return 'webhook';
    }

    protected function urlConfigKey(): string
    {
        return 'webhook.url';
    }

    protected function urlEnvironmentVariable(): string
    {
        return 'LCS_WEBHOOK_URL';
    }

    /**
     * The document `security-check:now --format=json` prints, so one parser handles both,
     * plus what a receiver needs to tell events and applications apart.
     */
    protected function reportPayload(array $report, string $composerLock): array
    {
        return $this->envelope('report')
            + app(JsonFormatter::class)->document($composerLock, $report, $this->ignoredAdvisories);
    }

    protected function failurePayload(CheckFailedException $e, string $composerLock): array
    {
        return $this->envelope('check_failed')
            + app(JsonFormatter::class)->errorDocument($composerLock, $e->getMessage());
    }

    /**
     * Signs the body when a secret is configured, the way GitHub signs its webhooks, so the
     * receiver can verify the request came from this application and was not altered:
     *
     *     hash_equals('sha256='.hash_hmac('sha256', $body, $secret), $header)
     */
    protected function headersFor(string $body): array
    {
        $secret = config('laravel-security-checker.webhook.secret');

        if (!is_string($secret) || $secret === '') {
            return [];
        }

        return ['X-Signature-256' => 'sha256='.hash_hmac('sha256', $body, $secret)];
    }

    /**
     * @return array<string, mixed>
     */
    private function envelope(string $event): array
    {
        return [
            // "report" (whether or not anything was found) or "check_failed"
            'event' => $event,
            'application' => [
                'name' => config('app.name'),
                'url' => config('app.url'),
                'environment' => $this->laravel->environment(),
            ],
        ];
    }
}
