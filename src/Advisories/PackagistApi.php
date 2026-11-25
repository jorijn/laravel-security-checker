<?php

namespace Jorijn\LaravelSecurityChecker\Advisories;

use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\RequestException;
use Illuminate\Http\Client\Response;
use Jorijn\LaravelSecurityChecker\Contracts\AdvisorySource;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use Throwable;

/**
 * Shared plumbing for both ways of querying Packagist's security advisories API.
 *
 * This is the same API `composer audit` uses. It is called directly over HTTP instead of
 * shelling out to the composer CLI, which is often not installed on production servers and
 * would make the result depend on the user's global Composer configuration.
 */
abstract class PackagistApi implements AdvisorySource
{
    public const DEFAULT_URL = 'https://packagist.org';

    public function __construct(
        protected readonly Factory $http,
        protected readonly string $baseUrl = self::DEFAULT_URL,
        protected readonly int $timeout = 30,
    ) {
    }

    protected function request(): PendingRequest
    {
        return $this->http
            ->baseUrl(rtrim($this->baseUrl, '/'))
            ->acceptJson()
            // Packagist asks automated clients to identify themselves, so they can be contacted
            // instead of blocked when something misbehaves.
            ->withUserAgent('jorijn/laravel-security-checker (+https://github.com/jorijn/laravel-security-checker)')
            ->connectTimeout(10)
            ->timeout($this->timeout)
            // A scheduled check that fails on a single network hiccup would raise a false alarm,
            // so retry twice. Only connection problems and server errors are worth retrying.
            ->retry(
                3,
                1000,
                fn (Throwable $e) => !$e instanceof RequestException || $e->response->serverError(),
                throw: false
            );
    }

    /**
     * Turns a response into the "advisories" map, or explains why it cannot.
     *
     * @return array<string, array<int, array<string, mixed>>>
     *
     * @throws CheckFailedException
     */
    protected function advisoriesFrom(Response $response, string $what): array
    {
        if (!$response->successful()) {
            throw CheckFailedException::because(
                "Packagist answered HTTP {$response->status()} while fetching $what.",
                $response->toException()
            );
        }

        $advisories = $response->json('advisories');

        // json() returns null for an invalid body. A missing or malformed "advisories" key means
        // the API changed: failing loudly beats silently reporting zero vulnerabilities.
        if (!is_array($advisories)) {
            throw CheckFailedException::because("Packagist returned an unexpected response while fetching $what.");
        }

        $grouped = [];

        foreach ($advisories as $package => $packageAdvisories) {
            if (is_string($package) && is_array($packageAdvisories)) {
                $grouped[strtolower($package)] = array_values(array_filter($packageAdvisories, 'is_array'));
            }
        }

        return $grouped;
    }

    /**
     * @throws CheckFailedException
     */
    protected function send(callable $request, string $what): Response
    {
        try {
            return $request($this->request());
        } catch (Throwable $e) {
            // Connection errors (DNS, TLS, timeouts) end up here; HTTP errors are returned as
            // responses because of `throw: false` and handled by advisoriesFrom().
            throw CheckFailedException::because(
                "Could not reach Packagist while fetching $what: {$e->getMessage()}",
                $e
            );
        }
    }
}
