# Changelog for Laravel Security Checker

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
