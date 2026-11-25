<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Laravel Security Checker
    |--------------------------------------------------------------------------
    |
    | This file will load all the translations for this package.
    |
    */

    'subject_new_vulnerabilities' => '{0} No packages have known vulnerabilities|{1} 1 package has known vulnerabilities|[2,*] :count packages have known vulnerabilities',
    'title' => 'Title',
    'view' => 'View',
    'cve' => 'CVE',
    'information' => 'Information',
    'no_recipients_configured' => 'No recipients has been configured yet!',
    'body_no_vulnerabilities' => 'It seems that no packages have any known vulnerabilities. You can read more about disabling this message [here](https://github.com/jorijn/laravel-security-checker#configuration).',
    'subject_check_failed' => 'The security check could not run',
    'body_check_failed' => 'The security check of :path could not run, so this application has **not** been checked for known vulnerabilities. The error was:',
    'body_check_failed_hint' => 'The check runs again at its next scheduled time. If this message keeps coming back, make sure the server can reach packagist.org.',
];