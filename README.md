## Laravel Security Checker
[![Latest Stable Version](https://img.shields.io/packagist/v/jorijn/laravel-security-checker.svg)](https://packagist.org/packages/jorijn/laravel-security-checker)
[![Total Downloads](https://img.shields.io/packagist/dt/jorijn/laravel-security-checker.svg)](https://packagist.org/packages/jorijn/laravel-security-checker)
[![License](https://img.shields.io/github/license/jorijn/laravel-security-checker.svg)](https://packagist.org/packages/jorijn/laravel-security-checker)
![Tests](https://github.com/Jorijn/laravel-security-checker/workflows/tests/badge.svg)

This package provides an effortless way for you to check your local `composer.lock` against the [Security Advisories Database](https://github.com/FriendsOfPHP/security-advisories). 
It can either display the results in your console or email them to you on a scheduled basis. It uses Laravel's markdown system, so it should fit nicely in your styling. 

> [!WARNING]
> **Version 3.x only sees about a quarter of the known PHP security advisories.**
> It checks your `composer.lock` against the FriendsOfPHP database (through [Enlightn Security Checker](https://github.com/enlightn/security-checker)).
> Most advisories nowadays are only published through the GitHub Advisory Database, which FriendsOfPHP does not include.
> Of the 7,866 advisories that [Packagist](https://packagist.org/apiDoc#list-security-advisories) knew about in November 2026, only 1,970 came from FriendsOfPHP, so roughly 75% will **not** be reported by this version.
>
> Version 4.0 will switch to Packagist's security advisory data, the same source that [`composer audit`](https://getcomposer.org/doc/03-cli.md#audit) uses.
> Until then, consider running `composer audit` as well, for example in your CI pipeline.

#### Screenshot
<img width="647" alt="screenshot-email" src="https://user-images.githubusercontent.com/85466/28497517-9e41580e-6f89-11e7-9c4e-0ebf713add6a.png">

## Installation
Require this package with composer using the following command:

```bash
composer require jorijn/laravel-security-checker
```

### Configuration

#### Email
If you want the package to send reports by email, you'll need to specify a recipient.

##### Option 1
Add it to your `.env` file.

```
LCS_MAIL_TO="someone@example.net"
```

To send the report to more than one address, separate them with commas:

```
LCS_MAIL_TO="someone@example.net,someone-else@example.net"
```

##### Option 2
Publish the configuration file and change it there.

```bash
php artisan vendor:publish --provider="Jorijn\LaravelSecurityChecker\ServiceProvider" --tag="config"
```

If you want to control on how the email is formatted you can have Laravel export the view for you using:

```bash
php artisan vendor:publish --provider="Jorijn\LaravelSecurityChecker\ServiceProvider" --tag="views"
```

If you published the views with an earlier version of this package, the CVE column of your copy of `security-mail.blade.php` shows `1` instead of the CVE identifier.
To fix it, replace `{{ $information['cve'] or '' }}` with `{{ $information['cve'] ?? '' }}` in that file.

By default, the package won't email you when there are no vulnerabilities found. You can change this setting by adding the following entry to your `.env` file.

```
LCS_NOTIFY_WITHOUT_VULNERABILITIES=true
```

Values like `1`, `yes` and `on` work as well. This setting also applies to Slack.

#### Slack
If you want the package to send the report to a Slack channel, you will need to specify a Slack Webhook
in your `.env` file.

E.g.:

```
LCS_SLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
```

#### Excluding dev dependencies
If your dev dependencies never reach production, you can leave them out of the check by adding the following entry to your `.env` file.

```
LCS_EXCLUDE_DEV=true
```

#### Allowing known vulnerabilities
Sometimes a reported vulnerability doesn't affect you, or you've accepted the risk. You can stop it from being reported by
adding its CVE identifier or its exact advisory title to the allow list. In your `.env` file, use a **single-quoted** JSON array:

```
LCS_ALLOW_LIST='["CVE-2024-1234","Example vulnerability title"]'
```

If you have published the configuration file, you can use a regular PHP array for `allow_list` instead.

Keep in mind:
* Entries must match exactly, including case.
* An allowed title is ignored for every package with an advisory by that name.
* An invalid allow list is ignored and logged as a warning, so the check always runs and nothing is hidden by mistake.

### Scheduling
The package exposes a new command for you:

```bash
php artisan security-check:email
```

You can hook it up into a regular crontab or add it to the Laravel Scheduler in `routes/console.php` like this:

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('security-check:email')->weekly();
```

Use `security-check:slack` instead to send the report to Slack.

## Running as a command
This package provides a wrapper around the [Enlightn Security Checker](https://github.com/enlightn/security-checker) command. You can call it using `php artisan security-check:now`.
 
![screenshot-console](https://user-images.githubusercontent.com/85466/28452254-17f3476e-6df2-11e7-9e5e-1c3d52b57722.png)

## Translations
If you need to translate this package into your own language you can do so by publishing the translation files:

```bash
php artisan vendor:publish --provider="Jorijn\LaravelSecurityChecker\ServiceProvider" --tag="translations"
```

The files are published to `lang/vendor/laravel-security-checker` (or `resources/lang/vendor/laravel-security-checker` if your application still uses `resources/lang`).

Please consider helping out by creating a pull request with your language to help out others.
