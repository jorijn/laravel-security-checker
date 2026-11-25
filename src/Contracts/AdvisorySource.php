<?php

namespace Jorijn\LaravelSecurityChecker\Contracts;

use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;

/**
 * Where the Packagist checker gets its advisories from.
 *
 * Advisories use the format of Packagist's security advisories API
 * (https://packagist.org/apidoc#list-security-advisories), the same data `composer audit` uses.
 */
interface AdvisorySource
{
    /**
     * Returns the known advisories, grouped by lower-case package name.
     *
     * A source may return more packages than asked for (the full feed does); callers only
     * look up the packages they need.
     *
     * @param array<int, string> $packageNames The installed packages
     * @return array<string, array<int, array<string, mixed>>>
     *
     * @throws CheckFailedException When the advisories could not be fetched
     */
    public function advisoriesFor(array $packageNames): array;
}
