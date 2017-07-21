<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Laravel Security Checker
    |--------------------------------------------------------------------------
    |
    | This file will tell the package where to send it's security mails to.
    |
    */

    'recipients' => [
        env('LCS_MAIL_TO', null)
    ]
];
