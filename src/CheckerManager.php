<?php

namespace Jorijn\LaravelSecurityChecker;

use Illuminate\Http\Client\Factory;
use Illuminate\Support\Manager;
use Jorijn\LaravelSecurityChecker\Advisories\PackagistApi;
use Jorijn\LaravelSecurityChecker\Advisories\PackagistFullFeed;
use Jorijn\LaravelSecurityChecker\Advisories\PackagistPerPackage;
use Jorijn\LaravelSecurityChecker\Checkers\EnlightnChecker;
use Jorijn\LaravelSecurityChecker\Checkers\PackagistChecker;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;

/**
 * Creates the configured checker driver (config key `driver`, env LCS_DRIVER).
 *
 * Built on Laravel's Manager, so an application can add its own driver from a service provider:
 *
 *     $this->app->make(CheckerManager::class)->extend('osv', fn ($app) => new OsvChecker());
 *
 * @method array check(string $composerLock, bool $excludeDev = false, array $allowList = [])
 */
class CheckerManager extends Manager
{
    public const DEFAULT_DRIVER = 'packagist';

    public function getDefaultDriver(): string
    {
        $driver = $this->config->get('laravel-security-checker.driver');

        // An empty LCS_DRIVER= in .env must not break the check; it means "the default".
        return is_string($driver) && trim($driver) !== '' ? trim($driver) : self::DEFAULT_DRIVER;
    }

    public function driver($driver = null): Checker
    {
        return parent::driver($driver);
    }

    /**
     * Default: downloads the full advisory feed and matches locally, so no package names leave the server.
     */
    protected function createPackagistDriver(): Checker
    {
        return new PackagistChecker(new PackagistFullFeed(...$this->packagistOptions()));
    }

    /**
     * Opt-in: asks Packagist only about the installed packages (smaller download, less private).
     */
    protected function createPackagistPerPackageDriver(): Checker
    {
        return new PackagistChecker(new PackagistPerPackage(...$this->packagistOptions()));
    }

    /**
     * @deprecated since 4.0, removed in 5.0
     */
    protected function createEnlightnDriver(): Checker
    {
        $tempDir = $this->config->get('laravel-security-checker.temp_dir');

        return new EnlightnChecker(is_string($tempDir) && $tempDir !== '' ? $tempDir : null);
    }

    /**
     * @return array{0: Factory, 1: string, 2: int}
     */
    private function packagistOptions(): array
    {
        $url = $this->config->get('laravel-security-checker.packagist.url');
        $timeout = filter_var($this->config->get('laravel-security-checker.packagist.timeout'), FILTER_VALIDATE_INT);

        return [
            $this->container->make(Factory::class),
            is_string($url) && trim($url) !== '' ? trim($url) : PackagistApi::DEFAULT_URL,
            $timeout !== false && $timeout > 0 ? $timeout : 30,
        ];
    }
}
