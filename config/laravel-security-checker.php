<?php

return [
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
     | Laravel Security Checker — Slack Webhook URL
     |--------------------------------------------------------------------------
     |
     | Which Slack Webhook URL should we post to when using Slack notifications?
     |
     */

    'slack_webhook_url' => env('LCS_SLACK_WEBHOOK', null),
    /*
     |--------------------------------------------------------------------------
     | Laravel Security Checker — Temp dir
     |--------------------------------------------------------------------------
     |
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
     | Laravel Security Checker — Allow list
     |--------------------------------------------------------------------------
     |
     | Vulnerabilities that should not be reported, identified by their CVE
     | identifier or by their exact advisory title (matching is case-sensitive).
     | Note that an allowed title is ignored for every package that uses it.
     |
     | In your .env file, use a single-quoted JSON array:
     |   LCS_ALLOW_LIST='["CVE-2024-1234","Example vulnerability title"]'
     |
     | When publishing this file you can use a regular PHP array instead:
     |   'allow_list' => ['CVE-2024-1234', 'Example vulnerability title'],
     |
     | An invalid value is ignored (and logged) so the check always runs.
     |
     */
    'allow_list' => env('LCS_ALLOW_LIST', []),
];
