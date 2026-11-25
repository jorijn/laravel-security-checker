<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Laravel Security Checker — Driver
    |--------------------------------------------------------------------------
    |
    | Where the advisories come from and how composer.lock is matched against them.
    |
    |   "packagist"             (default) Downloads the full security advisory feed from
    |                           Packagist, the source `composer audit` uses, and matches
    |                           versions locally. The list of packages your application uses
    |                           never leaves the server.
    |   "packagist-per-package" Asks Packagist about your installed packages only. Smaller
    |                           downloads, but Packagist learns which packages you use,
    |                           including the names of private packages.
    |   "enlightn"              Deprecated, removed in 5.0. The 3.x behaviour: the FriendsOfPHP
    |                           database through enlightn/security-checker, which you then need
    |                           to require yourself. It misses most advisories Packagist knows.
    |
    */

    'driver' => env('LCS_DRIVER', 'packagist'),

    /*
    |--------------------------------------------------------------------------
    | Laravel Security Checker — Packagist
    |--------------------------------------------------------------------------
    |
    | Settings for both Packagist drivers. The URL only needs changing for a
    | mirror that serves the same /api/security-advisories/ endpoint.
    | The timeout (in seconds) applies to each request.
    |
    */

    'packagist' => [
        'url' => env('LCS_PACKAGIST_URL', 'https://packagist.org'),
        'timeout' => env('LCS_PACKAGIST_TIMEOUT', 30),
    ],

    /*
    |--------------------------------------------------------------------------
    | Laravel Security Checker — Recipients
    |--------------------------------------------------------------------------
    |
    | This will tell the package where to send its security mails.
    |
    */

    'recipients' => [
        env('LCS_MAIL_TO', null)
    ],

    /*
     |--------------------------------------------------------------------------
     | Laravel Security Checker — Email settings
     |--------------------------------------------------------------------------
     |
     | Decides whether the package should send an email even if there aren't
     | any vulnerabilities found.
     |
     */

    'notify_even_without_vulnerabilities' => env('LCS_NOTIFY_WITHOUT_VULNERABILITIES', false),

    /*
     |--------------------------------------------------------------------------
     | Laravel Security Checker — Alert when the check could not run
     |--------------------------------------------------------------------------
     |
     | When the check itself fails (for example because Packagist cannot be
     | reached), security-check:email, :slack, :teams and :webhook send a
     | "check could not run" message, so a broken check never looks like a
     | quiet week.
     | security-check:now exits with code 2 in that case.
     |
     */

    'notify_on_failure' => env('LCS_NOTIFY_ON_FAILURE', true),

    /*
     |--------------------------------------------------------------------------
     | Laravel Security Checker — Slack Webhook URL
     |--------------------------------------------------------------------------
     |
     | Which Slack Webhook URL should we post to when using Slack notifications?
     |
     */

    'slack_webhook_url' => env('LCS_SLACK_WEBHOOK', null),

    /*
     |--------------------------------------------------------------------------
     | Laravel Security Checker — Microsoft Teams
     |--------------------------------------------------------------------------
     |
     | The Workflows webhook URL security-check:teams posts to. Create one in
     | Teams with the Workflows app: "Send webhook alerts to a channel".
     |
     */

    'teams_webhook_url' => env('LCS_TEAMS_WEBHOOK'),

    /*
     |--------------------------------------------------------------------------
     | Laravel Security Checker — Webhook
     |--------------------------------------------------------------------------
     |
     | security-check:webhook POSTs the report as JSON (the same document as
     | security-check:now --format=json) to this URL. With a secret, every
     | request carries an X-Signature-256 header: "sha256=" followed by the
     | HMAC-SHA256 of the body, so the receiver can verify where it came from.
     |
     */

    'webhook' => [
        'url' => env('LCS_WEBHOOK_URL'),
        'secret' => env('LCS_WEBHOOK_SECRET'),
    ],
    /*
     |--------------------------------------------------------------------------
     | Laravel Security Checker — Temp dir
     |--------------------------------------------------------------------------
     |
     | Only used by the deprecated "enlightn" driver.
     | Decides where enlightn/security-checker will place its temp files.
     | Useful when using this package with multiple users/permissions on a single server.
     | See: https://github.com/enlightn/security-checker/issues/17
     |      https://github.com/Jorijn/laravel-security-checker/issues/35
     | Value:
     |   An absolute path to a directory to place the temp files in.
     |   null = default /tmp directory
     |
     */
    'temp_dir' => null,

    /*
     |--------------------------------------------------------------------------
     | Laravel Security Checker — Exclude dev dependencies
     |--------------------------------------------------------------------------
     |
     | Skip the packages listed under "packages-dev" in composer.lock. Useful when
     | dev dependencies never reach your production environment.
     |
     */
    'exclude_dev' => env('LCS_EXCLUDE_DEV', false),

    /*
     |--------------------------------------------------------------------------
     | Laravel Security Checker — Minimum severity
     |--------------------------------------------------------------------------
     |
     | Only report advisories of at least this severity: "low", "medium",
     | "high" or "critical". Empty (the default) reports everything.
     |
     | Applies to every command, including the exit code of security-check:now.
     | Advisories without a known severity are always reported, because they
     | might be critical. With the deprecated "enlightn" driver no advisory has
     | a known severity, so this setting has no effect there.
     |
     */
    'minimum_severity' => env('LCS_MINIMUM_SEVERITY'),

    /*
     |--------------------------------------------------------------------------
     | Laravel Security Checker — Allow list
     |--------------------------------------------------------------------------
     |
     | Vulnerabilities that should not be reported, identified by their CVE
     | identifier or by their exact advisory title (matching is case-sensitive).
     | With the Packagist drivers, the GitHub advisory id (GHSA-...) or the
     | Packagist advisory id (PKSA-...) work as well, which helps for advisories
     | without a CVE.
     | Note that an allowed title is ignored for every package that uses it.
     |
     | In your .env file, use a single-quoted JSON array:
     |   LCS_ALLOW_LIST='["CVE-2024-1234","GHSA-xxxx-xxxx-xxxx","Example vulnerability title"]'
     |
     | When publishing this file you can use a regular PHP array instead:
     |   'allow_list' => ['CVE-2024-1234', 'Example vulnerability title'],
     |
     | An entry can also record why it is allowed. security-check:now lists
     | the ignored advisories with that reason:
     |   ['id' => 'GHSA-xxxx-xxxx-xxxx', 'reason' => 'We never call the affected method'],
     | or in your .env file:
     |   LCS_ALLOW_LIST='[{"id":"GHSA-xxxx-xxxx-xxxx","reason":"Not reachable"}]'
     |
     | An invalid value is ignored (and logged) so the check always runs.
     |
     */
    'allow_list' => env('LCS_ALLOW_LIST', []),
];
