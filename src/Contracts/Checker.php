<?php

namespace Jorijn\LaravelSecurityChecker\Contracts;

use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;

/**
 * A driver that checks a composer.lock file for known vulnerabilities.
 *
 * Every driver returns the same report shape, because the console output, the mail view (which
 * users may have published) and the Slack message all read it directly:
 *
 *     [
 *         'vendor/package' => [
 *             'version' => '1.2.3',             // from composer.lock, without a "v" prefix
 *             'time' => '2024-01-31T12:00:00+00:00', // release date from composer.lock, or null
 *             'advisories' => [
 *                 '<advisory id>' => [
 *                     'title' => 'Description of the vulnerability',
 *                     'link' => 'https://...',  // '' when unknown
 *                     'cve' => 'CVE-2024-1234', // null when the advisory has no CVE
 *                 ],
 *             ],
 *         ],
 *     ]
 *
 * Only packages with at least one reported advisory are listed. An empty array means the check
 * ran and found nothing; a check that could not run must throw instead, never return [].
 */
interface Checker
{
    /**
     * @param string $composerLock Absolute path to composer.lock
     * @param bool $excludeDev Skip the packages under "packages-dev"
     * @param array<int, string> $allowList Advisory identifiers or exact titles that must not be reported
     * @return array<string, array{
     *     version: string,
     *     time: ?string,
     *     advisories: array<string, array{title: string, link: string, cve: ?string}>
     * }>
     *
     * @throws CheckFailedException When the check could not run, e.g. the advisory source is unreachable
     */
    public function check(string $composerLock, bool $excludeDev = false, array $allowList = []): array;
}
