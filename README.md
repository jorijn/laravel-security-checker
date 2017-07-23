## Laravel Security Checker
[![Latest Stable Version](https://poser.pugx.org/jorijn/laravel-security-checker/version)](https://packagist.org/packages/jorijn/laravel-security-checker)
[![Total Downloads](https://poser.pugx.org/jorijn/laravel-security-checker/downloads)](https://packagist.org/packages/jorijn/laravel-security-checker)
[![Latest Unstable Version](https://poser.pugx.org/jorijn/laravel-security-checker/v/unstable)](//packagist.org/packages/jorijn/laravel-security-checker)
[![License](https://poser.pugx.org/jorijn/laravel-security-checker/license)](https://packagist.org/packages/jorijn/laravel-security-checker)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Jorijn/laravel-security-checker/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Jorijn/laravel-security-checker/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/Jorijn/laravel-security-checker/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/Jorijn/laravel-security-checker/?branch=master)
[![Build Status](https://travis-ci.org/Jorijn/laravel-security-checker.svg?branch=master)](https://travis-ci.org/Jorijn/laravel-security-checker)

This package provides an easy way for you to check your local `composer.lock` against the [Symfony Security Advisories Checker](https://security.sensiolabs.org/). 
It can either display the results in your console of email them to you on a scheduled basis. It uses Laravel's markdown system so it should fit nicely in your own styling. 

#### Screenshot
![screenshot-email](https://user-images.githubusercontent.com/85466/28497517-9e41580e-6f89-11e7-9c4e-0ebf713add6a.png)

## Installation
Require this package with composer using the following command:

```bash
composer require jorijn/laravel-security-checker
```

After updating composer, add the service provider to the `providers` array in `config/app.php`

```php
Jorijn\LaravelSecurityChecker\ServiceProvider::class,
```

_Note: On Laravel 5.5 and up, this package will use auto discovery and the above step is no longer required._

### Configuration
If you want to have the package email the reports to you, you need to tell the package to who it should send it to. 

#### Option 1
Add it to your `.env` file.

```
LCS_MAIL_TO="someone@example.net"
```

#### Option 2
Publish the configuration file and change it there.

```bash
php artisan vendor:publish --provider="Jorijn\LaravelSecurityChecker\ServiceProvider" --tag="config"
```

If you want control on how the email is formatted you can have Laravel export the view for you using:

```bash
php artisan vendor:publish --provider="Jorijn\LaravelSecurityChecker\ServiceProvider" --tag="views"
```

By default, the package won't email you when there are no vulnerabilities found. You can change this setting by adding the following entry to your `.env` file.

```
LCS_EMAIL_WITHOUT_VULNERABILITIES=true
```

### Scheduling
The packages exposes a new command for you:

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
This package provides a wrapper around the SensioLab's Security Checker command. You can call it using `php artisan security-check:now`.
 
![screenshot-console](https://user-images.githubusercontent.com/85466/28452254-17f3476e-6df2-11e7-9e5e-1c3d52b57722.png)

## Translations
If you need to translate this package into your own language you can do so by publishing the translation files:

```bash
php artisan vendor:publish --provider="Jorijn\LaravelSecurityChecker\ServiceProvider" --tag="translations"
```

Please consider helping out by creating a pull request with your own language to help out others.