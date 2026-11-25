<?php

/**
 * Nightly sanity check for the 4.0 data source: does the full Packagist advisory feed
 * contain everything the per-package API returns?
 *
 *   php tests/E2E/bin/compare-packagist-feeds.php path/to/composer.lock
 *
 * 4.0 will by default download the full feed (`?updatedSince=0`) and match versions locally,
 * so the list of packages an app uses never leaves the server (privacy). Per-package
 * querying stays available as an option. This script fails (exit 1) when the full feed
 * misses an advisory that per-package querying returns for the packages in the lock file,
 * which would mean the privacy-friendly default silently reports less.
 *
 * Both requests hit https://packagist.org/api/security-advisories/, the same endpoint
 * `composer audit` uses.
 */

const ENDPOINT = 'https://packagist.org/api/security-advisories/';

// The full feed held ~7,900 advisories in November 2026 and only grows. A much smaller
// number means a truncated or broken response, even if the comparison below happens to pass.
const MINIMUM_EXPECTED_ADVISORIES = 5000;

$lockFile = $argv[1] ?? null;

if ($lockFile === null || !is_file($lockFile)) {
    fwrite(STDERR, "usage: php compare-packagist-feeds.php <composer.lock>\n");
    exit(2);
}

$lock = json_decode((string) file_get_contents($lockFile), true, flags: JSON_THROW_ON_ERROR);
$packages = array_column(array_merge($lock['packages'] ?? [], $lock['packages-dev'] ?? []), 'name');

$full = request(ENDPOINT.'?updatedSince=0')['advisories'];
$fullCount = array_sum(array_map('count', $full));

// Batched POSTs: a lock file can list hundreds of packages, too many for one query string.
$perPackage = [];
foreach (array_chunk($packages, 100) as $chunk) {
    $body = http_build_query(['packages' => $chunk]);
    $perPackage += request(ENDPOINT, $body)['advisories'];
}

$missing = [];
$perPackageCount = 0;

foreach ($perPackage as $package => $advisories) {
    $inFullFeed = array_column($full[$package] ?? [], 'advisoryId');

    foreach ($advisories as $advisory) {
        $perPackageCount++;

        if (!in_array($advisory['advisoryId'], $inFullFeed, true)) {
            $missing[] = $package.': '.$advisory['advisoryId'].' '.$advisory['title'];
        }
    }
}

printf("Full feed: %d advisories for %d packages\n", $fullCount, count($full));
printf("Per-package: %d advisories for the %d packages in %s\n", $perPackageCount, count($packages), $lockFile);

$failed = false;

if ($fullCount < MINIMUM_EXPECTED_ADVISORIES) {
    printf("::error::The full feed returned only %d advisories (expected at least %d)\n", $fullCount, MINIMUM_EXPECTED_ADVISORIES);
    $failed = true;
}

if ($missing !== []) {
    printf("::error::The full feed misses %d advisories that per-package querying returns:\n", count($missing));
    echo ' - '.implode("\n - ", $missing)."\n";
    $failed = true;
}

if (!$failed) {
    echo "OK: the full feed contains every per-package advisory.\n";
}

exit($failed ? 1 : 0);

function request(string $url, ?string $postBody = null): array
{
    $context = stream_context_create(['http' => [
        'method' => $postBody === null ? 'GET' : 'POST',
        'header' => implode("\r\n", array_filter([
            // Packagist asks automated clients to identify themselves.
            'User-Agent: jorijn/laravel-security-checker nightly feed check',
            $postBody === null ? null : 'Content-Type: application/x-www-form-urlencoded',
        ])),
        'content' => $postBody ?? '',
        'timeout' => 60,
        'ignore_errors' => true,
    ]]);

    $response = file_get_contents($url, false, $context);
    $status = isset($http_response_header[0]) ? (int) explode(' ', $http_response_header[0])[1] : 0;

    if ($response === false || $status !== 200) {
        fwrite(STDERR, "Request to $url failed with HTTP $status\n");
        exit(1);
    }

    return json_decode($response, true, flags: JSON_THROW_ON_ERROR);
}
