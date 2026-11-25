<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Illuminate\Console\Command;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Log;
use Jorijn\LaravelSecurityChecker\Console\Concerns\ChecksForVulnerabilities;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use RuntimeException;
use Throwable;

/**
 * The flow every "post the report to a URL" command shares (security-check:webhook and
 * security-check:teams): the same rules as security-check:email and :slack for when to send,
 * and the same "the check could not run" alert.
 *
 * These channels use Laravel's HTTP client directly instead of a notification channel, so
 * they need no extra package (unlike Slack, which needs laravel/slack-notification-channel).
 */
abstract class WebhookChannelCommand extends Command
{
    use ChecksForVulnerabilities;

    /**
     * Exit code when the report could not be delivered, or no URL is configured: the same code
     * security-check:email uses when it has no recipients. Nobody was told anything.
     */
    public const NOT_DELIVERED = 1;

    /**
     * For log messages and errors, e.g. "Teams" ("No Teams URL...", "...via Teams").
     */
    abstract protected function channelName(): string;

    /**
     * The config key (below laravel-security-checker.) that holds the URL to post to.
     */
    abstract protected function urlConfigKey(): string;

    /**
     * The environment variable users set, for the error message when it is missing.
     */
    abstract protected function urlEnvironmentVariable(): string;

    /**
     * @param array<string, array<string, mixed>> $report
     * @return array<string, mixed>
     */
    abstract protected function reportPayload(array $report, string $composerLock): array;

    /**
     * @return array<string, mixed>
     */
    abstract protected function failurePayload(CheckFailedException $e, string $composerLock): array;

    public function handle(): int
    {
        $url = $this->url();

        if ($url === null) {
            Log::error(sprintf('the %s channel was requested but no URL is configured', $this->channelName()));
            $this->error(sprintf(
                'No %s URL has been configured, set %s.',
                $this->channelName(),
                $this->urlEnvironmentVariable()
            ));

            return self::NOT_DELIVERED;
        }

        $composerLock = base_path('composer.lock');

        Log::debug('about to check for vulnerabilities');

        try {
            $report = $this->checkForVulnerabilities($composerLock);
        } catch (CheckFailedException $e) {
            return $this->handleFailedCheck($e, $composerLock);
        }

        if (count($report) === 0 && !$this->notifyWithoutVulnerabilities()) {
            Log::info(sprintf('no vulnerabilities were found, not posting via %s', $this->channelName()));

            return self::SUCCESS;
        }

        try {
            $this->post($url, $this->reportPayload($report, $composerLock));
        } catch (Throwable $e) {
            $reason = sprintf('the security report via %s: %s', $this->channelName(), $e->getMessage());

            Log::error('could not deliver '.$reason, ['exception' => $e]);
            $this->error('Could not deliver '.$reason);

            return self::NOT_DELIVERED;
        }

        Log::warning(sprintf('security report posted via %s', $this->channelName()));

        return self::SUCCESS;
    }

    protected function notifyAboutFailedCheck(CheckFailedException $e, string $composerLock): void
    {
        // handle() only gets here with a URL configured.
        $this->post((string) $this->url(), $this->failurePayload($e, $composerLock));

        Log::warning(sprintf('the security check could not run, alert posted via %s', $this->channelName()));
    }

    /**
     * Extra request headers for the given body, e.g. a signature.
     *
     * @return array<string, string>
     */
    protected function headersFor(string $body): array
    {
        return [];
    }

    /**
     * @param array<string, mixed> $payload
     */
    protected function encode(array $payload): string
    {
        return json_encode(
            $payload,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR
        );
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @throws RuntimeException When the receiver did not accept the payload
     */
    private function post(string $url, array $payload): void
    {
        // Encoded here, once: a signature must cover exactly the bytes that are sent.
        $body = $this->encode($payload);

        $response = $this->laravel->make(Factory::class)
            ->withHeaders($this->headersFor($body))
            ->withUserAgent('jorijn/laravel-security-checker (+https://github.com/jorijn/laravel-security-checker)')
            ->connectTimeout(10)
            ->timeout(30)
            // One network hiccup must not cost a weekly alert, so retry twice. A 4xx means the
            // receiver rejected the payload (or the URL is wrong), and repeating will not help.
            ->retry(
                3,
                1000,
                fn (Throwable $e) => !$e instanceof RequestException
                    || $e->response->serverError()
                    || $e->response->status() === 429,
                throw: false
            )
            ->withBody($body, 'application/json')
            ->post($url);

        if (!$response->successful()) {
            throw new RuntimeException(sprintf(
                'the receiver answered HTTP %d%s',
                $response->status(),
                // A short excerpt helps to tell a wrong URL from a rejected payload.
                trim($response->body()) !== '' ? ': '.mb_strimwidth(trim($response->body()), 0, 200, '...') : ''
            ));
        }
    }

    private function url(): ?string
    {
        $url = config('laravel-security-checker.'.$this->urlConfigKey());

        return is_string($url) && trim($url) !== '' ? trim($url) : null;
    }
}
