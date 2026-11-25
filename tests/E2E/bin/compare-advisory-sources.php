<?php

/**
 * Nightly sanity check for the Packagist drivers against the live API.
 *
 *   php tests/E2E/bin/compare-advisory-sources.php <app-dir> <composer.lock> [<composer.lock> ...]
 *
 * <app-dir> is an app created with tests/E2E/bin/create-app.sh; its autoloader provides this
 * package (from the checkout) and its dependencies. For every lock file it checks that:
 *
 *  1. the full feed contains every advisory that per-package querying returns (raw API data),
 *  2. the default driver ("packagist", full feed) reports exactly what the opt-in
 *     "packagist-per-package" driver reports, so the private default never reports less, and
 *  3. the default driver reports exactly the advisories `composer audit` reports, an independent
 *     implementation of the same matching (skipped when composer is not on the PATH).
 *
 * Exits 1 on any difference, which fails the workflow and so alerts the maintainer.
 */

use Illuminate\Http\Client\Factory;
use Jorijn\LaravelSecurityChecker\Advisories\PackagistFullFeed;
use Jorijn\LaravelSecurityChecker\Advisories\PackagistPerPackage;
use Jorijn\LaravelSecurityChecker\Checkers\PackagistChecker;
use Jorijn\LaravelSecurityChecker\LockFile;

// The full feed held ~7,900 advisories in November 2026 and only grows. A much smaller number
// means a truncated or broken response, even if every comparison below happens to pass.
const MINIMUM_EXPECTED_ADVISORIES = 5000;

[$script, $appDir] = $argv + [null, null];
$lockFiles = array_slice($argv, 2);

if ($appDir === null || !is_file($appDir.'/vendor/autoload.php') || $lockFiles === []) {
    fwrite(STDERR, "usage: php compare-advisory-sources.php <app-dir> <composer.lock> [<composer.lock> ...]\n");
    exit(2);
}

require $appDir.'/vendor/autoload.php';

$http = new Factory();
$fullFeed = new PackagistFullFeed($http);
$perPackage = new PackagistPerPackage($http);
$failures = [];

$feed = $fullFeed->advisoriesFor([]);
$feedCount = array_sum(array_map('count', $feed));
printf("Full feed: %d advisories for %d packages\n", $feedCount, count($feed));

if ($feedCount < MINIMUM_EXPECTED_ADVISORIES) {
    $failures[] = sprintf('The full feed returned only %d advisories (expected at least %d)', $feedCount, MINIMUM_EXPECTED_ADVISORIES);
}

foreach ($lockFiles as $lockFile) {
    echo "\n== $lockFile\n";
    $packages = array_keys(LockFile::read($lockFile)->packages());

    // 1. Raw API data: is anything missing from the full feed?
    $missing = [];
    foreach ($perPackage->advisoriesFor($packages) as $package => $advisories) {
        $inFeed = array_column($feed[$package] ?? [], 'advisoryId');

        foreach ($advisories as $advisory) {
            if (!in_array($advisory['advisoryId'], $inFeed, true)) {
                $missing[] = "$package: {$advisory['advisoryId']} {$advisory['title']}";
            }
        }
    }

    if ($missing !== []) {
        $failures[] = "The full feed misses advisories that per-package querying returns for $lockFile:\n - ".implode("\n - ", $missing);
    }

    // 2. Driver level: both drivers must produce the very same report.
    $defaultReport = (new PackagistChecker($fullFeed))->check($lockFile);
    $perPackageReport = (new PackagistChecker($perPackage))->check($lockFile);
    $defaultIds = advisoryIds($defaultReport);
    $perPackageIds = advisoryIds($perPackageReport);

    printf("packagist driver: %d advisories, packagist-per-package driver: %d advisories\n", count($defaultIds), count($perPackageIds));

    if ($defaultReport !== $perPackageReport) {
        $failures[] = describeDifference("packagist vs packagist-per-package for $lockFile", $defaultIds, $perPackageIds);
    }

    // 3. Independent reference: composer audit.
    $auditIds = composerAudit($lockFile);

    if ($auditIds === null) {
        echo "composer audit: skipped (composer not available)\n";
    } else {
        printf("composer audit: %d advisories\n", count($auditIds));

        if ($auditIds !== $defaultIds) {
            $failures[] = describeDifference("packagist driver vs composer audit for $lockFile", $defaultIds, $auditIds);
        }
    }
}

if ($failures !== []) {
    foreach ($failures as $failure) {
        // GitHub turns ::error:: lines into annotations on the workflow run.
        echo "\n::error::".str_replace("\n", '%0A', $failure)."\n";
    }

    exit(1);
}

echo "\nOK: all advisory sources agree.\n";
exit(0);

/**
 * @return array<int, string> sorted "package ADVISORY-ID" lines
 */
function advisoryIds(array $report): array
{
    $ids = [];

    foreach ($report as $package => $details) {
        foreach (array_keys($details['advisories']) as $id) {
            $ids[] = "$package $id";
        }
    }

    sort($ids);

    return $ids;
}

function describeDifference(string $what, array $expected, array $actual): string
{
    $onlyExpected = array_diff($expected, $actual);
    $onlyActual = array_diff($actual, $expected);

    return "$what differ:\n"
        .' only in the first: '.($onlyExpected === [] ? 'none' : implode(', ', $onlyExpected))."\n"
        .' only in the second: '.($onlyActual === [] ? 'none' : implode(', ', $onlyActual));
}

/**
 * @return array<int, string>|null sorted "package ADVISORY-ID" lines, null without composer
 */
function composerAudit(string $lockFile): ?array
{
    exec('command -v composer', $output, $status);

    if ($status !== 0) {
        return null;
    }

    // composer audit wants a project directory; the lock file is all it reads with --locked.
    $dir = sys_get_temp_dir().'/lsc-audit-'.bin2hex(random_bytes(4));
    mkdir($dir);
    copy($lockFile, $dir.'/composer.lock');
    file_put_contents($dir.'/composer.json', '{"name": "lsc/audit", "require": {}}');

    // Exit codes 1 (vulnerable) and 2 (abandoned packages) are expected; only the JSON matters.
    $json = shell_exec('cd '.escapeshellarg($dir).' && composer audit --locked --format=json --no-interaction --abandoned=ignore 2>/dev/null');
    exec('rm -rf '.escapeshellarg($dir));

    $audit = json_decode((string) $json, true);

    if (!is_array($audit) || !isset($audit['advisories'])) {
        fwrite(STDERR, "composer audit did not return JSON: $json\n");
        exit(1);
    }

    $ids = [];

    foreach ($audit['advisories'] as $package => $advisories) {
        foreach ($advisories as $advisory) {
            $ids[] = "$package {$advisory['advisoryId']}";
        }
    }

    sort($ids);

    return $ids;
}
