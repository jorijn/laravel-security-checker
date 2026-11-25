<?php

namespace Jorijn\LaravelSecurityChecker;

use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;

/**
 * Reads the installed packages from a composer.lock file.
 *
 * Only the lock file is read, never vendor/ or the composer CLI: that keeps the check fast,
 * works on servers without composer installed, and checks exactly what will be deployed.
 */
final class LockFile
{
    /**
     * @param array<string, string> $packages
     * @param array<string, string> $devPackages
     * @param array<string, string> $times
     */
    private function __construct(
        private readonly array $packages,
        private readonly array $devPackages,
        private readonly array $times,
    ) {
    }

    /**
     * @throws CheckFailedException
     */
    public static function read(string $path): self
    {
        if (!is_file($path) || !is_readable($path)) {
            throw CheckFailedException::missingLockFile($path);
        }

        try {
            $lock = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw CheckFailedException::because("The lock file $path is not valid JSON: {$e->getMessage()}", $e);
        }

        if (!is_array($lock) || !isset($lock['packages']) || !is_array($lock['packages'])) {
            throw CheckFailedException::because("The lock file $path does not look like a composer.lock file.");
        }

        $devEntries = is_array($lock['packages-dev'] ?? null) ? $lock['packages-dev'] : [];

        return new self(
            self::column($lock['packages'], 'version'),
            self::column($devEntries, 'version'),
            self::column($devEntries, 'time') + self::column($lock['packages'], 'time'),
        );
    }

    /**
     * Returns the installed packages as lower-case name => version (as written in the lock file).
     *
     * @return array<string, string>
     */
    public function packages(bool $excludeDev = false): array
    {
        // `+` rather than array_merge: should a package somehow be listed in both sections,
        // the non-dev entry wins, as it is the one that reaches production.
        return $excludeDev ? $this->packages : $this->packages + $this->devPackages;
    }

    /**
     * The release date Composer recorded for a package, if any.
     */
    public function time(string $package): ?string
    {
        return $this->times[strtolower($package)] ?? null;
    }

    /**
     * @param array<int, mixed> $entries
     * @return array<string, string> lower-case package name => the value of $field
     */
    private static function column(array $entries, string $field): array
    {
        $values = [];

        foreach ($entries as $entry) {
            if (!is_array($entry) || !is_string($entry['name'] ?? null) || !is_string($entry['version'] ?? null)) {
                continue;
            }

            if (is_string($entry[$field] ?? null)) {
                // Package names are case-insensitive in Composer and always lower case on Packagist.
                $values[strtolower($entry['name'])] = $entry[$field];
            }
        }

        return $values;
    }
}
