## Laravel Security Checker
[![Latest Stable Version](https://img.shields.io/packagist/v/jorijn/laravel-security-checker.svg)](https://packagist.org/packages/jorijn/laravel-security-checker)
[![Total Downloads](https://img.shields.io/packagist/dt/jorijn/laravel-security-checker.svg)](https://packagist.org/packages/jorijn/laravel-security-checker)
[![License](https://img.shields.io/github/license/jorijn/laravel-security-checker.svg)](https://packagist.org/packages/jorijn/laravel-security-checker)
![Tests](https://github.com/Jorijn/laravel-security-checker/workflows/tests/badge.svg)

This package provides an effortless way for you to check your local `composer.lock` against the [Security Advisories Database](https://github.com/FriendsOfPHP/security-advisories). 
It can either display the results in your console or email them to you on a scheduled basis. It uses Laravel's markdown system, so it should fit nicely in your styling. 

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

##### Option 2
Publish the configuration file and change it there.

```bash
php artisan vendor:publish --provider="Jorijn\LaravelSecurityChecker\ServiceProvider" --tag="config"
```

If you want to control on how the email is formatted you can have Laravel export the view for you using:

```bash
php artisan vendor:publish --provider="Jorijn\LaravelSecurityChecker\ServiceProvider" --tag="views"
```

By default, the package won't email you when there are no vulnerabilities found. You can change this setting by adding the following entry to your `.env` file.

```
LCS_NOTIFY_WITHOUT_VULNERABILITIES=true
```

#### Slack
If you want the package to send the report to a Slack channel, you will need to specify a Slack Webhook
in your `.env` file.

E.g.:

```
LCS_SLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
```

### Scheduling
The package exposes a new command for you:

```bash
php artisan security-check:email
```

You can hook it up into a regular crontab or add it into the Laravel Scheduler (`app/Console/Kernel.php`) like this:

```php
protected function schedule(Schedule $schedule)
{
    $schedule->command(\Jorijn\LaravelSecurityChecker\Console\SecurityMailCommand::class)
        ->weekly();
}
```

## Running as a command
This package provides a wrapper around the [Enlightn Security Checker](https://github.com/enlightn/security-checker) command. You can call it using `php artisan security-check:now`.
 
![screenshot-console](https://user-images.githubusercontent.com/85466/28452254-17f3476e-6df2-11e7-9e5e-1c3d52b57722.png)

## Translations
If you need to translate this package into your own language you can do so by publishing the translation files:

```bash
php artisan vendor:publish --provider="Jorijn\LaravelSecurityChecker\ServiceProvider" --tag="translations"
```

Please consider helping out by creating a pull request with your language to help out others.
