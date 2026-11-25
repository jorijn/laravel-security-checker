<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;

/**
 * Posts the report to a Microsoft Teams channel as an Adaptive Card.
 *
 * Expects a Workflows webhook URL ("When a Teams webhook request is received", or the template
 * "Send webhook alerts to a channel"): Microsoft retired the connector-based incoming webhooks
 * in May 2026, and Workflows webhooks take Adaptive Cards.
 * https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook
 */
class SecurityTeamsCommand extends WebhookChannelCommand
{
    /**
     * Teams rejects messages over 28 KB. The card stops listing advisories well before that, and
     * says how many it left out, instead of not arriving at all.
     */
    public const MAX_BYTES = 24_000;

    /**
     * @var string
     */
    protected $name = 'security-check:teams';

    /**
     * @var string
     */
    protected $description = 'Posts vulnerabilities to a Microsoft Teams channel.';

    protected function channelName(): string
    {
        return 'Teams';
    }

    protected function urlConfigKey(): string
    {
        return 'teams_webhook_url';
    }

    protected function urlEnvironmentVariable(): string
    {
        return 'LCS_TEAMS_WEBHOOK';
    }

    protected function reportPayload(array $report, string $composerLock): array
    {
        $packageCount = count($report);
        $title = trans_choice('laravel-security-checker::messages.subject_new_vulnerabilities', $packageCount, [
            'count' => $packageCount,
        ]);

        $header = [
            $this->text('['.config('app.name').'] '.$title, [
                'weight' => 'Bolder',
                'size' => 'Medium',
                'color' => $packageCount > 0 ? 'Attention' : 'Good',
            ]),
            $this->text(
                'Security Check Report: `'.(realpath($composerLock) ?: $composerLock).'`',
                ['isSubtle' => true]
            ),
        ];

        if ($packageCount === 0) {
            $header[] = $this->text(__('laravel-security-checker::messages.body_no_vulnerabilities'));

            return $this->card($header);
        }

        $lines = [];

        foreach ($report as $package => $details) {
            $lines[] = ['advisory' => false, 'block' => $this->text(
                sprintf('**%s** (%s)', $package, $details['version'] ?? '?'),
                ['spacing' => 'Medium']
            )];

            foreach ($details['advisories'] ?? [] as $advisory) {
                $lines[] = [
                    'advisory' => true,
                    'block' => $this->text($this->advisoryLine($advisory), ['spacing' => 'None']),
                ];
            }
        }

        return $this->card(array_merge($header, $this->withinSizeLimit($header, $lines)));
    }

    protected function failurePayload(CheckFailedException $e, string $composerLock): array
    {
        return $this->card([
            $this->text('['.config('app.name').'] '.__('laravel-security-checker::messages.subject_check_failed'), [
                'weight' => 'Bolder',
                'size' => 'Medium',
                'color' => 'Attention',
            ]),
            $this->text(__('laravel-security-checker::messages.body_check_failed', ['path' => '`'.$composerLock.'`'])),
            $this->text($e->getMessage(), ['fontType' => 'Monospace']),
            $this->text(__('laravel-security-checker::messages.body_check_failed_hint'), ['isSubtle' => true]),
        ]);
    }

    /**
     * @param array<string, mixed> $advisory
     */
    private function advisoryLine(array $advisory): string
    {
        $line = '- ';

        if (!empty($advisory['severity'])) {
            $line .= '['.$advisory['severity'].'] ';
        }

        if (!empty($advisory['cve'])) {
            $line .= $advisory['cve'].': ';
        }

        $line .= $advisory['title'] ?? '';

        if (!empty($advisory['link'])) {
            $line .= ' (['.__('laravel-security-checker::messages.view').']('.$advisory['link'].'))';
        }

        return $line;
    }

    /**
     * Adds report lines until the card would get too big, then a note about what is left out.
     *
     * @param array<int, array<string, mixed>> $header
     * @param array<int, array{advisory: bool, block: array<string, mixed>}> $lines
     * @return array<int, array<string, mixed>>
     */
    private function withinSizeLimit(array $header, array $lines): array
    {
        $body = [];
        // Reserve room for the "N more" note.
        $size = strlen($this->encode($this->card($header))) + 300;

        foreach ($lines as $index => $line) {
            $lineSize = strlen($this->encode($line['block'])) + 1;

            if ($size + $lineSize > self::MAX_BYTES) {
                $left = count(array_filter(array_slice($lines, $index), fn (array $line) => $line['advisory']));
                $body[] = $this->text(sprintf(
                    '%d more %s not listed here, run `php artisan security-check:now` for the full report.',
                    $left,
                    $left === 1 ? 'advisory is' : 'advisories are'
                ), ['spacing' => 'Medium', 'isSubtle' => true]);

                break;
            }

            $body[] = $line['block'];
            $size += $lineSize;
        }

        return $body;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    private function text(string $text, array $options = []): array
    {
        return ['type' => 'TextBlock', 'text' => $text, 'wrap' => true] + $options;
    }

    /**
     * The message format Workflows webhooks accept: one Adaptive Card as an attachment.
     *
     * @param array<int, array<string, mixed>> $body
     * @return array<string, mixed>
     */
    private function card(array $body): array
    {
        return [
            'type' => 'message',
            'attachments' => [[
                'contentType' => 'application/vnd.microsoft.card.adaptive',
                'content' => [
                    '$schema' => 'http://adaptivecards.io/schemas/adaptive-card.json',
                    'type' => 'AdaptiveCard',
                    // Everything used here exists since 1.0; 1.2 is supported by every Teams client.
                    'version' => '1.2',
                    'body' => $body,
                    // Reports are lists of long titles; the default card width wraps them badly.
                    'msteams' => ['width' => 'Full'],
                ],
            ]],
        ];
    }
}
