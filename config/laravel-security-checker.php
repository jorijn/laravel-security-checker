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
    'temp_dir' => null
];
