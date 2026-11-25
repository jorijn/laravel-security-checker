<?php

namespace Jorijn\LaravelSecurityChecker\Contracts;

/**
 * Optional for drivers: tells which advisories the last check() left out because of the allow
 * list, so the commands can show what is being ignored, and why.
 *
 * A separate interface rather than a change to Checker, so custom drivers written for 4.0 keep
 * working unchanged; for them, the commands simply show nothing about ignored advisories.
 */
interface ReportsIgnoredAdvisories
{
    /**
     * The advisories the last check() ignored, in the report shape described on Checker, with
     * one extra key per advisory: 'allowed_by', the allow list entry that matched it.
     *
     * @return array<string, array{
     *     version: string,
     *     time: ?string,
     *     advisories: array<string, array{
     *         title: string,
     *         link: string,
     *         cve: ?string,
     *         severity?: ?string,
     *         allowed_by: string
     *     }>
     * }>
     */
    public function ignoredAdvisories(): array;
}
