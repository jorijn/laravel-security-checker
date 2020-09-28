# Changelog for Laravel Security Checker

## v2.1.0 (2020-09-28)
* dropped support for PHP 7.1, minimum version is now PHP 7.2
* upgraded `guzzlehttp/guzzle` to a new major version (^v7.0.0)
* added support for Laravel 8 (thanks @romanstingler, @nessimabadi!)

## v2.0.0 (2020-03-04)
* dropped support for PHP 7.0, minimum version is now PHP 7.1.3
* upgraded `sensiolabs/security-checker` to a new major version (^v6.0.0)
* added support for Laravel 7 (thanks @cino!)

## v1.2.0 (2020-03-03)
* improved the `security:now` command to return exit code 1 when vulnerabilities were found, this enables integration into CI flows

## v1.1.1 (2019-09-23)
* added support for Laravel 6.0 (thanks @davejamesmiller!)

## v1.1.0 (2019-03-09)
* added support for Laravel 5.8 (thanks @DevDavido!)
* added logging for email and slack commands

## v1.0.0 (2019-01-12)
* @DevDavido notified me about the SensioLabs Security Checker upgrade, I implemented their changes
* bumped the package to a stable tag, I think it has matured enough now. :-) 

## v0.3.0 (2018-08-03)
* updated to work on Laravel 5.5.x, 5.6.x and 5.7.x, thanks @jorgenb
* dropped support for PHP 5.x
* added Slack notifications on vulnerabilities, thanks @jorgenb
* renamed LCS_EMAIL_WITHOUT_VULNERABILITIES TO LCS_NOTIFY_WITHOUT_VULNERABILITIES to reflect the Slack notification

## v0.2.2 (2017-07-23)
* wrote tests to cover 100% of the package functionality

## v0.2.1 (2017-07-23)
* fixed a bug in the email where the CVE wasn't displayed correctly
* added DE and NL languages. thanks @mijndert

## v0.2.0 (2017-07-22)
* added configuration option that won't email you when there are no vulnerabilities and it is enabled by default.
* code improvements
