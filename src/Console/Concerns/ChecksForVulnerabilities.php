<?php

namespace Jorijn\LaravelSecurityChecker\Console\Concerns;

use Illuminate\Support\Facades\Log;
use Jorijn\LaravelSecurityChecker\CheckerManager;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use Jorijn\LaravelSecurityChecker\Severity;
use Throwable;

/**
 * Shared by all security-check commands: the configured checker options are normalized in
 * exactly one place, and a check that could not run is handled the same way everywhere.
 */
trait ChecksForVulnerabilities
{
    /**
     * Exit code when vulnerabilities were found (unchanged since 1.x).
     */
    public const VULNERABILITIES_FOUND = 1;

    /**
     * Exit code when the check itself could not run, e.g. Packagist was unreachable.
     *
     * Before 4.0 such failures surfaced as an uncaught exception with exit code 1, which a
     * cron wrapper or CI step could not tell apart from "vulnerabilities found".
     */
    public const CHECK_FAILED = 2;

    /**
     * Run the configured checker against the given composer.lock using the configured options.
     *
     * @return array<string, array<string, mixed>> The report, in the shape described on Checker
     *
     * @throws CheckFailedException
     */
    protected function checkForVulnerabilities(string $composerLock): array
    {
        $this->warnAboutDeprecatedDriver();

        try {
            $report = $this->laravel->make(Checker::class)->check(
                $composerLock,
                $this->excludeDevDependencies(),
                $this->allowedVulnerabilities()
            );
        } catch (CheckFailedException $e) {
            throw $e;
        } catch (Throwable $e) {
            // Custom drivers (or a bug) may throw anything; whatever it is, the check did not run
            // and must be reported as such, never as "no vulnerabilities".
            throw CheckFailedException::because($e->getMessage(), $e);
        }

        return $this->withoutAdvisoriesBelow($this->minimumSeverity(), $report);
    }

    /**
     * Drops the advisories below the configured minimum severity, and the packages left without
     * any advisory.
     *
     * Done here rather than in the drivers, so it works the same for every driver (custom ones
     * included) without changing the Checker interface. Advisories of unknown severity are
     * always kept, see Severity.
     *
     * @param array<string, array<string, mixed>> $report
     * @return array<string, array<string, mixed>>
     */
    private function withoutAdvisoriesBelow(?string $minimum, array $report): array
    {
        if ($minimum === null) {
            return $report;
        }

        foreach ($report as $package => $details) {
            $details['advisories'] = array_filter(
                $details['advisories'] ?? [],
                fn ($advisory) => Severity::meets(
                    is_array($advisory) ? ($advisory['severity'] ?? null) : null,
                    $minimum
                )
            );

            if ($details['advisories'] === []) {
                unset($report[$package]);
            } else {
                $report[$package] = $details;
            }
        }

        return $report;
    }

    /**
     * The configured minimum severity, or null to report everything (the default).
     *
     * An unknown value is ignored with a warning, like an invalid allow list: a typo must not
     * silently hide advisories, so it falls back to reporting more rather than less.
     */
    protected function minimumSeverity(): ?string
    {
        $minimum = config('laravel-security-checker.minimum_severity');

        if ($minimum === null || (is_string($minimum) && trim($minimum) === '')) {
            return null;
        }

        $severity = Severity::normalize($minimum);

        if ($severity === null) {
            $message = sprintf(
                'The laravel-security-checker minimum_severity "%s" is invalid and has been ignored, '
                    .'expected one of: %s.',
                is_scalar($minimum) ? $minimum : get_debug_type($minimum),
                implode(', ', Severity::LEVELS)
            );

            Log::warning($message);
            $this->warn($message);
        }

        return $severity;
    }

    /**
     * Logs and prints why the check could not run, alerts the configured channel and returns
     * the exit code. Alerting is the command's job, see notifyAboutFailedCheck().
     */
    protected function handleFailedCheck(CheckFailedException $e, string $composerLock): int
    {
        Log::error('the security check could not run: '.$e->getMessage(), ['exception' => $e]);

        $this->error('The security check could not run: '.$e->getMessage());
        $this->error('This does not mean that there are no vulnerabilities: nothing was checked.');

        if ($this->notifyOnFailure()) {
            try {
                $this->notifyAboutFailedCheck($e, $composerLock);
            } catch (Throwable $notifyError) {
                // The alert itself failing must not hide the original problem or the exit code.
                Log::error('could not send the "security check could not run" alert: '.$notifyError->getMessage(), [
                    'exception' => $notifyError,
                ]);
                $this->error('Sending the alert about this failed as well: '.$notifyError->getMessage());
            }
        }

        return self::CHECK_FAILED;
    }

    /**
     * Sends the "security check could not run" alert. Commands that notify someone override this.
     */
    protected function notifyAboutFailedCheck(CheckFailedException $e, string $composerLock): void
    {
    }

    /**
     * Whether a failed check sends an alert through the command's channel (default: yes).
     */
    protected function notifyOnFailure(): bool
    {
        // An unrecognised value keeps the safe default: rather one alert too many than a silent failure.
        return filter_var(
            config('laravel-security-checker.notify_on_failure', true),
            FILTER_VALIDATE_BOOLEAN,
            FILTER_NULL_ON_FAILURE
        ) ?? true;
    }

    private function warnAboutDeprecatedDriver(): void
    {
        if ($this->laravel->make(CheckerManager::class)->getDefaultDriver() !== 'enlightn') {
            return;
        }

        $message = 'The "enlightn" driver of laravel-security-checker is deprecated and will be removed in 5.0. '
            .'Remove LCS_DRIVER (or set it to "packagist") to use the Packagist advisory database.';

        Log::warning($message);
        $this->warn($message);
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
     * Whether a report should also be sent when no vulnerabilities were found.
     *
     * env() only casts the literal strings "true"/"(true)" to a boolean, so a strict `=== true`
     * check silently ignored common .env values like "1", "yes" or "on". FILTER_VALIDATE_BOOLEAN
     * accepts those, and still treats anything unrecognised as false: an unexpected value
     * should never start spamming all-clear reports.
     *
     * @return bool
     */
    protected function notifyWithoutVulnerabilities(): bool
    {
        return filter_var(
            config('laravel-security-checker.notify_even_without_vulnerabilities', false),
            FILTER_VALIDATE_BOOLEAN
        );
    }

    /**
     * Returns the allow list as a clean list of strings, whatever shape the config value has.
     *
     * Drivers expect a list of strings (Enlightn even type-hints `array`, so anything else
     * crashed the whole check). A malformed allow list is therefore ignored (with a warning)
     * instead: reporting too many vulnerabilities is a much safer failure mode than running
     * no check at all.
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

        // Entries are matched exactly, so stray whitespace or non-string values would silently
        // never match anything.
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
