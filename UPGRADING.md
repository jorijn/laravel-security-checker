# Upgrading

## From 3.x to 4.0

4.0 replaces the data source. 3.x checked your `composer.lock` against the FriendsOfPHP database
(through `enlightn/security-checker`), which holds about a quarter of the PHP advisories known
today. 4.0 uses Packagist's security advisory database, the same data `composer audit` uses.

For most applications, upgrading is one command and no code or config changes:

```bash
composer require jorijn/laravel-security-checker:^4.0
```

Then read the points below to see whether any of them apply to you.

### Requirements

| | 3.x | 4.0 |
|---|---|---|
| PHP | ^8.2 | **^8.3** |
| Laravel | 12, 13 | 12, 13 (and 14 once released) |
| `enlightn/security-checker` | required | **no longer installed**; only needed for the deprecated `enlightn` driver |

`enlightn/security-checker` does not support Symfony 8, which Laravel 14 requires. Dropping it is
what makes 4.0 ready for Laravel 14.

If nothing else in your application uses `enlightn/security-checker`, Composer removes it
during the upgrade.

### Expect more vulnerabilities to be reported

This is the point of the release, but it can be a surprise: packages that were "clean" for years
may suddenly be reported, because their advisories were only ever published in the GitHub
Advisory Database. The results now match `composer audit --locked`.

If you use the allow list for advisories without a CVE, you can now also allow them by their
GitHub advisory id (`GHSA-...`) or Packagist advisory id (`PKSA-...`). CVE identifiers and exact
titles keep working as before.

### Network access

The check now downloads `https://packagist.org/api/security-advisories/?updatedSince=0`
instead of `https://codeload.github.com/FriendsOfPHP/security-advisories/zip/master`.
If your server can only reach allow-listed hosts, allow `packagist.org`.

This request is the same for every application: the list of packages you use is not sent to
Packagist. Set `LCS_DRIVER=packagist-per-package` if you would rather download only the advisories
for your own packages, at the cost of telling Packagist which packages you use.

### Exit code 2 when the check could not run

In 3.x, an unreachable advisory source or a missing `composer.lock` ended in an uncaught
exception, and the command exited with code `1`, the same as "vulnerabilities found".

In 4.0, all three commands exit with code **`2`** when the check could not run, and print why.
If a script or CI step treats any non-zero exit code as "vulnerabilities found", nothing changes
for you. If it checks for `1` specifically, decide what `2` should mean there; it does **not**
mean the application is free of vulnerabilities.

| Exit code | Meaning |
|---|---|
| `0` | No vulnerabilities found (or the mail or Slack report was sent) |
| `1` | Vulnerabilities found (`security-check:now`), or no mail recipients configured |
| `2` | The check could not run |

### A "check could not run" message by default

`security-check:email` and `security-check:slack` now send a "the security check could not run"
message to the configured recipients or webhook when the check fails. In 3.x nothing was sent,
so a broken check looked exactly like a quiet week without vulnerabilities.

To turn it off, set `LCS_NOTIFY_ON_FAILURE=false`.

### Published config, views and translations

Nothing has to be republished.

- **Config:** the new keys (`driver`, `packagist`, `notify_on_failure`) fall back to their defaults
  when your published `config/laravel-security-checker.php` does not have them. `temp_dir` is now
  only used by the deprecated `enlightn` driver.
- **Views:** the `security-mail` view receives the same variables as before. The failure message
  uses a new view, `security-check-failed`.
- **Translations:** new lines for the failure message fall back to the package's own translations
  when your published files do not have them.

The report shape that views and custom code receive is unchanged: package name => `version`,
`time` and `advisories` (each with `title`, `link` and `cve`). Advisories are now keyed by their
Packagist advisory id instead of a FriendsOfPHP file path.

### Keeping the old data source for now

The 3.x behaviour is still available as the `enlightn` driver. It is deprecated, logs a warning on
every run, and will be removed in 5.0:

```bash
composer require enlightn/security-checker
```

```
LCS_DRIVER=enlightn
```

### Code that extends the package

These only matter if your code uses the package's classes directly:

- The commands no longer take `Enlightn\SecurityChecker\SecurityChecker` in their constructor and
  the package no longer binds that class in the container. Commands resolve
  `Jorijn\LaravelSecurityChecker\Contracts\Checker` when they run.
- In tests, bind a fake `Jorijn\LaravelSecurityChecker\Contracts\Checker` instead of mocking
  `Enlightn\SecurityChecker\SecurityChecker`.
- You can add your own driver with `CheckerManager::extend()`; see the README.

### Support for 3.x

3.x receives security fixes only, until February 2027.
