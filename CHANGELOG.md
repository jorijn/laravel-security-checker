# Changelog for Laravel Security Checker

## [4.0.0](https://github.com/jorijn/laravel-security-checker/compare/v3.1.1...v4.0.0) (2026-11-25)


### ⚠ BREAKING CHANGES

* exit with code 2 and send a "the security check could not run" alert by mail or Slack when the check itself fails (`LCS_NOTIFY_ON_FAILURE=false` turns the alert off)
* require PHP 8.3 or newer; `enlightn/security-checker` is no longer installed and only needed for the deprecated `enlightn` driver
* check against Packagist's security advisory database (the data `composer audit` uses) instead of FriendsOfPHP only, so far more vulnerabilities are reported; see [UPGRADING.md](https://github.com/jorijn/laravel-security-checker/blob/master/UPGRADING.md)

### Features

* add the `packagist-per-package` driver and custom drivers through `CheckerManager::extend()` ([c38037d](https://github.com/jorijn/laravel-security-checker/commit/c38037d16b1c135631b6a6a90b435cbebb96f09f))
* allow advisories by their GitHub (`GHSA-...`) or Packagist (`PKSA-...`) advisory id ([c38037d](https://github.com/jorijn/laravel-security-checker/commit/c38037d16b1c135631b6a6a90b435cbebb96f09f))
* allow installing on Laravel 14 ([c38037d](https://github.com/jorijn/laravel-security-checker/commit/c38037d16b1c135631b6a6a90b435cbebb96f09f))
* check against Packagist's security advisory database (the data `composer audit` uses) instead of FriendsOfPHP only, so far more vulnerabilities are reported; see [UPGRADING.md](https://github.com/jorijn/laravel-security-checker/blob/master/UPGRADING.md) ([c38037d](https://github.com/jorijn/laravel-security-checker/commit/c38037d16b1c135631b6a6a90b435cbebb96f09f))
* exit with code 2 and send a "the security check could not run" alert by mail or Slack when the check itself fails (`LCS_NOTIFY_ON_FAILURE=false` turns the alert off) ([c38037d](https://github.com/jorijn/laravel-security-checker/commit/c38037d16b1c135631b6a6a90b435cbebb96f09f))
* require PHP 8.3 or newer; `enlightn/security-checker` is no longer installed and only needed for the deprecated `enlightn` driver ([c38037d](https://github.com/jorijn/laravel-security-checker/commit/c38037d16b1c135631b6a6a90b435cbebb96f09f))


### Bug Fixes

* show the number of packages in the Spanish translation ([c38037d](https://github.com/jorijn/laravel-security-checker/commit/c38037d16b1c135631b6a6a90b435cbebb96f09f))

## [3.1.1](https://github.com/jorijn/laravel-security-checker/compare/v3.1.0...v3.1.1) (2026-11-25)


### Bug Fixes

* accept 1, yes and on for LCS_NOTIFY_WITHOUT_VULNERABILITIES ([6eabf12](https://github.com/jorijn/laravel-security-checker/commit/6eabf12db4e07ff9605c4e42af19a0b49eca8779))
* publish translations to the app's own lang directory instead of resources/lang ([6eabf12](https://github.com/jorijn/laravel-security-checker/commit/6eabf12db4e07ff9605c4e42af19a0b49eca8779))
* show the CVE identifier in the mail report instead of "1" ([6eabf12](https://github.com/jorijn/laravel-security-checker/commit/6eabf12db4e07ff9605c4e42af19a0b49eca8779))
* support several comma-separated addresses in LCS_MAIL_TO ([6eabf12](https://github.com/jorijn/laravel-security-checker/commit/6eabf12db4e07ff9605c4e42af19a0b49eca8779))

## v3.1.0 (2026-10-06)
* added `exclude_dev` (`LCS_EXCLUDE_DEV`) to leave dev dependencies out of the check (thanks @gavg-vaioni!)
* added `allow_list` (`LCS_ALLOW_LIST`) to stop known vulnerabilities from being reported, by CVE identifier or advisory title (thanks @gavg-vaioni!)

## v3.0.0 (2026-04-30)
* added support for PHP 8.5 and Laravel 13 (thanks @DevDavido!)
* **BREAKING:** dropped support for unsupported dependencies, including Laravel 11 and below; minimum supported version is now Laravel 12 — see https://laravel.com/docs/13.x/releases#support-policy
* simplified the test workflow following the dependency cleanup

## v2.6.0 (2025-03-23)
* added support for PHP 8.4 and Laravel 12 (thanks @DevDavido!)

## v2.5.0 (2024-06-02)
* add support for Laravel 11, PHP 8.3

## v2.4.0 (2023-04-28)
* add support for Laravel 10, PHP 8.2

## v2.3.0 (2022-03-02)
* add support for Laravel 9, PHP 8.1
* dropped support for PHP 7.3, minimum version is now 7.4

## v2.2.1 (2021-03-10)
FIXED
* a permission failure when using this package with multiple users on the same server by adding `temp-dir` to available config options (thanks @thomasderoo4!)

## v2.2.0 (2021-02-03)
A big thank you to @paras-malhotra and Enlightn for helping out this release.

* switched out travis with github actions, tests will now run in a matrix from Laravel 6 to 8 in combination with PHP 7.3 to 8
* `sensiolabs/security-checker` is abandoned, replaced with successor `enlightn/security-checker`
* allowed PHP 8 in the version constraints
* removed support for Laravel < 6.0, supported versions are now: 6.x to 8.x
* added Spanish language files (thanks @gfmr806)

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
