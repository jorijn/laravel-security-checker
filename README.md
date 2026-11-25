## Laravel Security Checker
[![Latest Stable Version](https://img.shields.io/packagist/v/jorijn/laravel-security-checker.svg)](https://packagist.org/packages/jorijn/laravel-security-checker)
[![Total Downloads](https://img.shields.io/packagist/dt/jorijn/laravel-security-checker.svg)](https://packagist.org/packages/jorijn/laravel-security-checker)
[![License](https://img.shields.io/github/license/jorijn/laravel-security-checker.svg)](https://packagist.org/packages/jorijn/laravel-security-checker)
![Tests](https://github.com/Jorijn/laravel-security-checker/workflows/tests/badge.svg)

This package checks your application's `composer.lock` for packages with known security vulnerabilities, using
[Packagist's security advisory database](https://packagist.org/apidoc#list-security-advisories): the same data
[`composer audit`](https://getcomposer.org/doc/03-cli.md#audit) uses, which includes the GitHub Advisory Database and FriendsOfPHP.
It can display the results in your console, or email them or post them to Slack on a schedule. Mails use Laravel's markdown system, so they fit nicely in your styling.

> [!NOTE]
> **Upgrading from 3.x?** Version 3.x checked against the FriendsOfPHP database only, which holds about a quarter of the
> advisories Packagist knows about. Expect 4.x to report vulnerabilities that 3.x never mentioned.
> See [UPGRADING.md](UPGRADING.md) for everything that changed; for most applications it is just `composer require jorijn/laravel-security-checker:^4.0`.

#### Screenshot
<img width="600" alt="The security report mail, listing three vulnerable packages with their advisories and CVE identifiers" src="https://raw.githubusercontent.com/jorijn/laravel-security-checker/master/.github/images/screenshot-mail.png">

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

In copies published with 4.0.0 or earlier, every package after the first shows up as a literal `## vendor/package` line instead of a heading.
To fix it, add an empty line between `@endcomponent` and `@endforeach` near the end of the package loop.

By default, the package won't email you when there are no vulnerabilities found. You can change this setting by adding the following entry to your `.env` file.

```
LCS_NOTIFY_WITHOUT_VULNERABILITIES=true
```

Values like `1`, `yes` and `on` work as well. This setting also applies to Slack.

#### When the check itself cannot run
If the check cannot run, for example because Packagist cannot be reached or `composer.lock` is missing,
`security-check:email` and `security-check:slack` send a "the security check could not run" message instead, so a broken
check never looks like a quiet week without vulnerabilities. To turn that message off, add:

```
LCS_NOTIFY_ON_FAILURE=false
```

The commands exit with code `2` in that case either way (see [Exit codes](#exit-codes)), and the error is logged.

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

#### Minimum severity
Packagist knows the severity of most advisories: `low`, `medium`, `high` or `critical`. To only be told about the more
serious ones, add the lowest severity you want to see to your `.env` file:

```
LCS_MINIMUM_SEVERITY=high
```

Keep in mind:
* This applies to every command, including the exit code of `security-check:now`.
* Advisories without a known severity (a few percent of them) are always reported, because they might be critical.
  The deprecated `enlightn` driver knows no severities at all, so the setting has no effect there.
* An invalid value is ignored and logged as a warning, so nothing is hidden by a typo.

The severity is shown in every report, when it is known.

#### Allowing known vulnerabilities
Sometimes a reported vulnerability doesn't affect you, or you've accepted the risk. You can stop it from being reported by
adding its CVE identifier or its exact advisory title to the allow list. Many advisories have no CVE; those can be allowed by their
GitHub advisory id (`GHSA-...`) or Packagist advisory id (`PKSA-...`) as well. In your `.env` file, use a **single-quoted** JSON array:

```
LCS_ALLOW_LIST='["CVE-2024-1234","GHSA-xxxx-xxxx-xxxx","Example vulnerability title"]'
```

If you have published the configuration file, you can use a regular PHP array for `allow_list` instead.

To remember (and tell your colleagues) why an advisory is allowed, write the entry as an object with an `id` and a `reason`.
Both forms can be mixed:

```
LCS_ALLOW_LIST='[{"id":"GHSA-xxxx-xxxx-xxxx","reason":"We never call the affected method"},"CVE-2024-1234"]'
```

```php
'allow_list' => [
    ['id' => 'GHSA-xxxx-xxxx-xxxx', 'reason' => 'We never call the affected method'],
    'CVE-2024-1234',
],
```

`security-check:now` lists the advisories the allow list hides, with their reason, so an accepted risk does not disappear
from sight (also in the [JSON output](#json-output), under `ignored`). This works with the Packagist drivers.

Keep in mind:
* Entries must match exactly, including case.
* An allowed title is ignored for every package with an advisory by that name.
* An invalid allow list is ignored and logged as a warning, so the check always runs and nothing is hidden by mistake.

#### Advisory data and privacy
By default, the package downloads Packagist's complete advisory feed (about 0.7 MB, compressed) and matches it against your
`composer.lock` on your own server. The request is the same for every application, so **the list of packages you use never
leaves your server**. Nothing calls the `composer` command line tool, so it works on servers without Composer as well.

If you prefer smaller downloads, you can ask Packagist about your installed packages only:

```
LCS_DRIVER=packagist-per-package
```

Keep in mind that Packagist then learns which packages your application uses, including the names of private packages.

| Driver | Data source | What leaves your server |
|---|---|---|
| `packagist` (default) | Packagist (GitHub Advisory Database, FriendsOfPHP, and more) | nothing about your application |
| `packagist-per-package` | Packagist, for your installed packages only | the names of your installed packages |
| `enlightn` (deprecated) | FriendsOfPHP only, through `enlightn/security-checker` | nothing about your application |

The `enlightn` driver is the 3.x behaviour. It is deprecated, misses most advisories, and will be removed in 5.0. To keep using it for now,
install its dependency yourself with `composer require enlightn/security-checker` and set `LCS_DRIVER=enlightn`.

If your server can only reach a mirror of Packagist that serves the same `/api/security-advisories/` endpoint, set `LCS_PACKAGIST_URL`.
`LCS_PACKAGIST_TIMEOUT` sets the timeout per request in seconds (default: 30).

#### Adding your own driver
A driver implements `Jorijn\LaravelSecurityChecker\Contracts\Checker` and returns the same report shape as the built-in ones
(see the interface for the details). Register it from a service provider and select it with `LCS_DRIVER`:

```php
use Jorijn\LaravelSecurityChecker\CheckerManager;

public function boot(): void
{
    $this->app->make(CheckerManager::class)->extend('my-driver', fn ($app) => new MyChecker());
}
```

A driver that cannot run must throw an exception (preferably `Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException`)
instead of returning an empty report, so the failure is reported as such.

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
You can run the check yourself with `php artisan security-check:now`, for example in a CI pipeline or a deploy script.

<img width="784" alt="Output of php artisan security-check:now, listing three vulnerable packages with their advisories and CVE identifiers" src="https://raw.githubusercontent.com/jorijn/laravel-security-checker/master/.github/images/screenshot-console.png">

### JSON output
Add `--format=json` to get the report as JSON, for example to process it in a CI pipeline:

```bash
php artisan security-check:now --format=json > security-report.json
```

```json
{
    "lock_file": "/var/www/app/composer.lock",
    "vulnerable_package_count": 1,
    "advisory_count": 1,
    "packages": {
        "laravel/framework": {
            "version": "12.0.0",
            "time": "2025-02-24T13:40:17+00:00",
            "advisories": {
                "PKSA-xxxx-xxxx-xxxx": {
                    "title": "Example vulnerability title",
                    "link": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
                    "cve": "CVE-2025-1234",
                    "severity": "high"
                }
            }
        }
    },
    "ignored": {}
}
```

* `packages` and `ignored` are always objects, also when they are empty (`{}`).
* `ignored` lists the advisories hidden by the allow list, in the same shape, with `allowed_by` (the matching allow list entry)
  and `reason` added to each advisory.
* `severity` is `low`, `medium`, `high`, `critical`, or `null` when unknown.
* Only the JSON document is written to stdout. Warnings and errors go to stderr.
* When the check could not run, the document holds an `error` message instead of `packages`, and the exit code is `2`.
* The exit codes are the same as for the text output.

### Exit codes
| Exit code | Meaning |
|---|---|
| `0` | The check ran and found no vulnerabilities (or the mail/Slack report was sent). |
| `1` | `security-check:now` found vulnerabilities, or `security-check:email` has no recipients configured. |
| `2` | The check could not run, for example because Packagist could not be reached. This does **not** mean there are no vulnerabilities. |

## Translations
If you need to translate this package into your own language you can do so by publishing the translation files:

```bash
php artisan vendor:publish --provider="Jorijn\LaravelSecurityChecker\ServiceProvider" --tag="translations"
```

The files are published to `lang/vendor/laravel-security-checker` (or `resources/lang/vendor/laravel-security-checker` if your application still uses `resources/lang`).

Please consider helping out by creating a pull request with your language to help out others.
