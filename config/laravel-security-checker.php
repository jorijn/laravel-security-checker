<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Laravel Security Checker — Recipients
    |--------------------------------------------------------------------------
    |
    | This file will tell the package where to send it's security mails to.
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
     | Decides wether the package should send email to you even if there aren't
     | any vulnerabilities found.
     |
     */

    'email_even_without_vulnerabilities' => env('LCS_EMAIL_WITHOUT_VULNERABILITIES', false),
];
