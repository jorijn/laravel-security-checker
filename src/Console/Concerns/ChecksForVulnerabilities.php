<?php

namespace Jorijn\LaravelSecurityChecker\Console\Concerns;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Log;
use Jorijn\LaravelSecurityChecker\CheckerManager;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;
use Jorijn\LaravelSecurityChecker\Contracts\ReportsIgnoredAdvisories;
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
     * What the last check left out because of the allow list, in the report shape plus
     * 'allowed_by' and 'reason' per advisory. Empty when the driver cannot tell (see
     * ReportsIgnoredAdvisories).
     *
     * @var array<string, array<string, mixed>>
     */
    protected array $ignoredAdvisories = [];

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

        $this->ignoredAdvisories = [];
        // Read once: an invalid allow list must only be warned about once.
        $allowList = $this->allowList();

        try {
            $checker = $this->laravel->make(Checker::class);
            $report = $checker->check($composerLock, $this->excludeDevDependencies(), array_keys($allowList));
        } catch (CheckFailedException $e) {
            throw $e;
        } catch (Throwable $e) {
            // Custom drivers (or a bug) may throw anything; whatever it is, the check did not run
            // and must be reported as such, never as "no vulnerabilities".
            throw CheckFailedException::because($e->getMessage(), $e);
        }

        if ($checker instanceof ReportsIgnoredAdvisories) {
            $this->ignoredAdvisories = $this->withReasons($checker->ignoredAdvisories(), $allowList);
        }

        return $this->withoutAdvisoriesBelow($this->minimumSeverity(), $report);
    }

    /**
     * Adds the reason from the allow list to every ignored advisory.
     *
     * @param array<string, array<string, mixed>> $ignored
     * @param array<string, ?string> $allowList
     * @return array<string, array<string, mixed>>
     */
    private function withReasons(array $ignored, array $allowList): array
    {
        foreach ($ignored as $package => $details) {
            foreach ($details['advisories'] ?? [] as $id => $advisory) {
                $ignored[$package]['advisories'][$id]['reason'] = $allowList[$advisory['allowed_by'] ?? ''] ?? null;
            }
        }

        return $ignored;
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
     * With LCS_NOTIFY_ONLY_NEW, returns only the findings this channel has not reported before.
     *
     * "Before" means: in the last run that completed. The state is the set of findings of that
     * run (not everything ever seen), so an advisory that disappears (e.g. after an update) and
     * comes back later is new again. Without any state yet (first run, cleared cache) every
     * finding is new: when in doubt, this sends too much rather than too little.
     *
     * @param array<string, array<string, mixed>> $report
     * @return array<string, array<string, mixed>>
     */
    protected function newFindings(array $report, string $composerLock): array
    {
        if (!$this->notifyOnlyNew()) {
            return $report;
        }

        $previous = $this->previousFindings($composerLock);

        if ($previous === null) {
            return $report;
        }

        $previous = array_flip($previous);

        foreach ($report as $package => $details) {
            $details['advisories'] = array_filter(
                $details['advisories'] ?? [],
                fn ($id) => !isset($previous[$this->fingerprint($package, (string) $id)]),
                ARRAY_FILTER_USE_KEY
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
     * Stores the findings of this run as the state the next run compares against.
     *
     * Commands call this only once the report was delivered (or there was nothing to deliver),
     * so a failed delivery is tried again, as new, on the next run.
     *
     * @param array<string, array<string, mixed>> $report The full report, not only the new findings
     */
    protected function rememberFindings(array $report, string $composerLock): void
    {
        if (!$this->notifyOnlyNew()) {
            return;
        }

        $fingerprints = [];

        foreach ($report as $package => $details) {
            foreach (array_keys($details['advisories'] ?? []) as $id) {
                $fingerprints[] = $this->fingerprint($package, (string) $id);
            }
        }

        try {
            $this->stateStore()->forever($this->stateKey($composerLock), $fingerprints);
        } catch (Throwable $e) {
            // The report itself went out; a cache that is down must not turn that into a failure.
            // The next run will then report everything again, which is the safe side.
            Log::warning('could not store which vulnerabilities were reported: '.$e->getMessage(), ['exception' => $e]);
        }
    }

    /**
     * Whether only findings that were not reported by the previous run are sent (default: no).
     */
    protected function notifyOnlyNew(): bool
    {
        return filter_var(config('laravel-security-checker.notify_only_new', false), FILTER_VALIDATE_BOOLEAN);
    }

    /**
     * @return ?array<int, string> null when there is no state yet
     */
    private function previousFindings(string $composerLock): ?array
    {
        try {
            $previous = $this->stateStore()->get($this->stateKey($composerLock));
        } catch (Throwable $e) {
            Log::warning('could not read which vulnerabilities were reported before, reporting all of them: '
                .$e->getMessage(), ['exception' => $e]);

            return null;
        }

        return is_array($previous) ? array_values(array_filter($previous, 'is_string')) : null;
    }

    /**
     * The state lives in Laravel's cache: shared between servers when the cache is (Redis,
     * database, ...), and nothing to migrate. LCS_STATE_CACHE_STORE picks another store, e.g.
     * one that a deploy does not clear.
     */
    private function stateStore(): CacheRepository
    {
        $store = config('laravel-security-checker.state_cache_store');

        return $this->laravel->make('cache')->store(is_string($store) && trim($store) !== '' ? trim($store) : null);
    }

    /**
     * One state per channel (email and Slack each report a finding once) and per lock file.
     */
    private function stateKey(string $composerLock): string
    {
        return 'laravel-security-checker:reported:'.$this->getName().':'.sha1(realpath($composerLock) ?: $composerLock);
    }

    /**
     * A finding is an advisory for a package, whatever version is installed: upgrading to a
     * version that is still affected does not make the same advisory new.
     */
    private function fingerprint(string $package, string $advisoryId): string
    {
        return $package.'|'.$advisoryId;
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
     * Returns the allow list as a clean list of identifiers, whatever shape the config value has.
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
        return array_keys($this->allowList());
    }

    /**
     * The allow list as identifier => reason (null when the entry has no reason).
     *
     * An entry is either a plain string (the only format before 4.1), or an array like
     * ['id' => 'GHSA-...', 'reason' => 'Why this does not affect us']. Composer's own
     * `audit.ignore` puts the reason in the array value instead ('CVE-...' => 'reason'), but
     * that shape already meant something else here: string keys have always been free-form
     * labels with the identifier as the value ('laravel-xss' => 'CVE-...'), and existing
     * configs must keep working.
     *
     * @return array<string, ?string>
     */
    protected function allowList(): array
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

        $entries = [];

        foreach ($allowList as $entry) {
            [$identifier, $reason] = is_array($entry)
                ? [$entry['id'] ?? null, $entry['reason'] ?? null]
                : [$entry, null];

            // Entries are matched exactly, so stray whitespace or non-string values would
            // silently never match anything.
            $identifier = is_string($identifier) ? trim($identifier) : '';
            $reason = is_string($reason) && trim($reason) !== '' ? trim($reason) : null;

            if ($identifier === '') {
                continue;
            }

            // The same identifier twice (e.g. once with and once without a reason) is one entry.
            $entries[$identifier] = $reason ?? $entries[$identifier] ?? null;
        }

        return $entries;
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
