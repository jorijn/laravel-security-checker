<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Enlightn\SecurityChecker\SecurityChecker;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Jorijn\LaravelSecurityChecker\CheckerManager;
use Jorijn\LaravelSecurityChecker\Checkers\EnlightnChecker;
use Jorijn\LaravelSecurityChecker\Checkers\PackagistChecker;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use PHPUnit\Framework\Attributes\RequiresMethod;
use PHPUnit\Framework\Attributes\TestWith;

/**
 * Which driver runs, and how drivers can be swapped.
 */
class DriverTest extends TestCase
{
    #[TestWith([null])]
    #[TestWith([''])]
    #[TestWith(['  '])]
    #[TestWith(['packagist'])]
    public function testPackagistIsTheDefault(mixed $configured): void
    {
        Config::set('laravel-security-checker.driver', $configured);

        $this->assertInstanceOf(PackagistChecker::class, $this->app->make(Checker::class));
    }

    public function testThePackageConfigDefaultsToPackagist(): void
    {
        $this->assertSame('packagist', config('laravel-security-checker.driver'));
        $this->assertTrue(config('laravel-security-checker.notify_on_failure'));
    }

    public function testPerPackageDriver(): void
    {
        Config::set('laravel-security-checker.driver', 'packagist-per-package');

        $this->assertInstanceOf(PackagistChecker::class, $this->app->make(Checker::class));
    }

    public function testAnApplicationCanAddItsOwnDriver(): void
    {
        $custom = \Mockery::mock(Checker::class);
        $custom->expects('check')->andReturns([]);

        $this->app->make(CheckerManager::class)->extend('custom', fn () => $custom);
        Config::set('laravel-security-checker.driver', 'custom');

        $this->artisan('security-check:now')->assertExitCode(0);
    }

    public function testAnUnknownDriverMeansTheCheckFailed(): void
    {
        Config::set('laravel-security-checker.driver', 'does-not-exist');

        $this->artisan('security-check:now')
            ->expectsOutputToContain('Driver [does-not-exist] not supported')
            ->assertExitCode(2);
    }

    #[RequiresMethod(SecurityChecker::class, 'check')]
    public function testTheEnlightnDriverStillWorksButWarnsThatItIsDeprecated(): void
    {
        Log::spy();
        Http::fake();
        Config::set('laravel-security-checker.driver', 'enlightn');
        $this->withLockFileInTheApplication();

        $enlightn = \Mockery::mock(SecurityChecker::class);
        $enlightn->expects('check')->with(base_path('composer.lock'), false, [])->andReturns($this->getFakeVulnerabilityReport());
        $this->app->instance(SecurityChecker::class, $enlightn);

        $this->artisan('security-check:now')
            ->expectsOutputToContain('"enlightn" driver of laravel-security-checker is deprecated')
            ->expectsOutputToContain('CVE-2016-5385')
            ->assertExitCode(1);

        Log::shouldHaveReceived('warning')->withArgs(fn ($message) => str_contains($message, 'deprecated'));
        Http::assertNothingSent();
    }

    #[RequiresMethod(SecurityChecker::class, 'check')]
    public function testTheEnlightnDriverTurnsItsExceptionsIntoAFailedCheck(): void
    {
        Config::set('laravel-security-checker.driver', 'enlightn');
        $this->withLockFileInTheApplication();

        $enlightn = \Mockery::mock(SecurityChecker::class);
        $enlightn->allows('check')->andThrow(new \RuntimeException('codeload.github.com returned 503'));
        $this->app->instance(SecurityChecker::class, $enlightn);

        $this->artisan('security-check:now')
            ->expectsOutputToContain('The Enlightn security checker failed: codeload.github.com returned 503')
            ->assertExitCode(2);
    }

    #[RequiresMethod(SecurityChecker::class, 'check')]
    public function testTheEnlightnDriverFailsClearlyWithoutALockFile(): void
    {
        $this->expectException(CheckFailedException::class);
        $this->expectExceptionMessage('Cannot read the lock file');

        (new EnlightnChecker())->check('/does/not/exist/composer.lock');
    }

    /**
     * enlightn/security-checker is only suggested; CI also runs without it (it blocks Symfony 8).
     */
    public function testTheEnlightnDriverExplainsHowToInstallItsDependency(): void
    {
        if (class_exists(SecurityChecker::class)) {
            $this->markTestSkipped('enlightn/security-checker is installed');
        }

        Config::set('laravel-security-checker.driver', 'enlightn');
        $this->withLockFileInTheApplication();

        $this->artisan('security-check:now')
            ->expectsOutputToContain('composer require enlightn/security-checker')
            ->assertExitCode(2);
    }

    private function withLockFileInTheApplication(): void
    {
        copy(__DIR__.'/fixtures/installed.lock', base_path('composer.lock'));
        $this->beforeApplicationDestroyed(fn () => @unlink(base_path('composer.lock')));
    }
}
