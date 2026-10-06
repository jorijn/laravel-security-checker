<?php

namespace Jorijn\LaravelSecurityChecker\Console\Concerns;

use Illuminate\Support\Facades\Log;

/**
 * Shared by all security-check commands so the configured checker options are
 * normalized in exactly one place before they reach the Enlightn SecurityChecker.
 *
 * Expects the using class to have a `$checker` property holding the SecurityChecker.
 */
trait ChecksForVulnerabilities
{
    /**
     * Run the security checker against the given composer.lock using the configured options.
     *
     * @param string $composerLock
     * @return array
     */
    protected function checkForVulnerabilities(string $composerLock): array
    {
        return $this->checker->check(
            $composerLock,
            $this->excludeDevDependencies(),
            $this->allowedVulnerabilities()
        );
    }

    /**
     * @return bool
     */
    protected function excludeDevDependencies(): bool
    {
        // env() already casts "true"/"false", but a published config file may contain
        // strings like "1" or "yes"; FILTER_VALIDATE_BOOLEAN handles both cases.
        return filter_var(
            config('laravel-security-checker.exclude_dev', false),
            FILTER_VALIDATE_BOOLEAN
        );
    }

    /**
     * Returns the allow list as a clean list of strings, whatever shape the config value has.
     *
     * Enlightn type-hints the allow list as `array`, so passing anything else crashes the whole
     * check. A malformed allow list is therefore ignored (with a warning) instead: reporting
     * too many vulnerabilities is a much safer failure mode than running no check at all.
     *
     * @return array<int, string>
     */
    protected function allowedVulnerabilities(): array
    {
        $allowList = config('laravel-security-checker.allow_list', []);

        // .env files can only hold strings, so LCS_ALLOW_LIST arrives as a JSON-encoded array.
        if (is_string($allowList)) {
            if (trim($allowList) === '') {
                return [];
            }

            $allowList = json_decode($allowList, true);

            // invalid JSON decodes to null, and valid JSON may still be a scalar (e.g. "123")
            if (!is_array($allowList)) {
                $this->warnAboutInvalidAllowList();

                return [];
            }
        }

        if ($allowList === null) {
            return [];
        }

        if (!is_array($allowList)) {
            $this->warnAboutInvalidAllowList();

            return [];
        }

        // Enlightn matches entries with a strict in_array(), so stray whitespace or non-string
        // values would silently never match anything.
        $allowList = array_map(fn ($entry) => is_string($entry) ? trim($entry) : $entry, $allowList);

        return array_values(array_filter($allowList, fn ($entry) => is_string($entry) && $entry !== ''));
    }

    /**
     * @return void
     */
    private function warnAboutInvalidAllowList(): void
    {
        $message = 'The laravel-security-checker allow_list is invalid and has been ignored, '
            .'expected a JSON array like LCS_ALLOW_LIST=\'["CVE-2024-1234"]\'.';

        Log::warning($message);
        $this->warn($message);
    }
}
