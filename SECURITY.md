# Security Policy

## Supported versions

| Version | Supported                                                        |
| ------- | ---------------------------------------------------------------- |
| 4.x     | :white_check_mark:                                               |
| 3.x     | :white_check_mark: Security fixes only, until February 2027      |
| < 3.0   | :x:                                                              |

## Reporting a vulnerability

Please **do not** open a public issue for security problems in this package.

Report them privately through GitHub instead: open the repository's **Security** tab and
choose **Report a vulnerability**
(<https://github.com/jorijn/laravel-security-checker/security/advisories/new>).

Please include the package version, your Laravel and PHP versions, and steps to reproduce.
You can expect a first response within a week. Once a fix is available, a GitHub security
advisory is published and the issue is credited to you, unless you prefer otherwise.

## Scope

This package reports vulnerabilities *in your dependencies*; it does not fix them. A
vulnerability that this package fails to report (a false negative), or a way to make it
report nothing while it should, is in scope and very welcome. Vulnerabilities in the
dependencies themselves belong with their maintainers, who can publish them through the
[GitHub Advisory Database](https://github.com/advisories) (which Packagist includes).
