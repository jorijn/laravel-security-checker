<?php

namespace Jorijn\LaravelSecurityChecker\Tests\E2E;

use Symfony\Component\Process\Process;

/**
 * `php artisan vendor:publish` for the config, views and translations tags.
 *
 * These tests write into the e2e app, so every test removes what it published again.
 */
class PublishTest extends E2ETestCase
{
    private const PUBLISHED_PATHS = [
        'config/laravel-security-checker.php',
        'resources/views/vendor/laravel-security-checker',
        'resources/lang',
        'lang/vendor',
    ];

    protected function setUp(): void
    {
        parent::setUp();
        $this->removePublishedFiles();
    }

    protected function tearDown(): void
    {
        $this->removePublishedFiles();
        parent::tearDown();
    }

    public function testPublishedConfigIsUsed(): void
    {
        $this->publish('config');

        $this->assertFileExists(static::$appPath.'/config/laravel-security-checker.php');

        // Edit the published file like a user would: a PHP array instead of the JSON env value.
        $config = static::$appPath.'/config/laravel-security-checker.php';
        file_put_contents($config, str_replace(
            "'allow_list' => env('LCS_ALLOW_LIST', []),",
            "'allow_list' => ['CVE-2099-0001', 'CVE-2099-0003'],",
            (string) file_get_contents($config)
        ));

        $output = $this->artisan(['security-check:now'])->getOutput();

        $this->assertStringNotContainsString('CVE-2099-0001', $output);
        $this->assertStringNotContainsString('CVE-2099-0003', $output);
        $this->assertStringContainsString('E2E fixture: framework advisory without a CVE', $output);
    }

    public function testPublishedViewIsUsedForTheMail(): void
    {
        $this->publish('views');

        $view = static::$appPath.'/resources/views/vendor/laravel-security-checker/security-mail.blade.php';
        $this->assertFileExists($view);

        file_put_contents($view, "@component('mail::message')\n# Customised by the app\n@endcomponent\n");

        $this->artisan(['security-check:email'], ['LCS_MAIL_TO' => 'security@example.com']);

        $this->assertStringContainsString('Customised by the app', $this->mailHtml($this->sentMails()[0] ?? ''));
    }

    public function testPublishedTranslationsAreUsed(): void
    {
        $this->publish('translations');

        $published = $this->publishedTranslationsDirectory();
        $this->assertNotNull($published, 'translations were not published anywhere');

        file_put_contents($published.'/en/messages.php', str_replace(
            ':count packages have known vulnerabilities',
            ':count packages need attention',
            (string) file_get_contents($published.'/en/messages.php')
        ));

        $this->artisan(['security-check:email'], ['LCS_MAIL_TO' => 'security@example.com']);

        $this->assertSame('[E2E App] 2 packages need attention', $this->mailHeader($this->sentMails()[0] ?? '', 'Subject'));
    }

    /**
     * The package publishes to resource_path('lang/...'). Since Laravel 9 an app's translations
     * live in lang/, and Laravel only falls back to resources/lang when that directory exists.
     * So publishing creates resources/lang and the app silently loses its own translations.
     */
    public function testPublishingTranslationsKeepsTheAppsLanguagePath(): void
    {
        $this->assertSame('translated by the app', $this->translate('e2e.marker'), 'precondition: app translation works');

        $this->publish('translations');

        $this->assertKnownBug('publishing the translations changes the app\'s language path', function () {
            $this->assertSame('translated by the app', $this->translate('e2e.marker'));
            $this->assertDirectoryDoesNotExist(static::$appPath.'/resources/lang');
            $this->assertDirectoryExists(static::$appPath.'/lang/vendor/laravel-security-checker');
        });
    }

    private function publish(string $tag): void
    {
        $process = $this->artisan([
            'vendor:publish',
            '--provider=Jorijn\LaravelSecurityChecker\ServiceProvider',
            '--tag='.$tag,
        ]);

        $this->assertSame(0, $process->getExitCode(), $process->getOutput().$process->getErrorOutput());
    }

    private function translate(string $key): string
    {
        // tinker ships with every laravel/laravel skeleton and boots the app like artisan does.
        $process = $this->artisan(['tinker', '--execute=echo __('.var_export($key, true).');']);

        return trim($process->getOutput());
    }

    private function publishedTranslationsDirectory(): ?string
    {
        foreach (['lang/vendor/laravel-security-checker', 'resources/lang/vendor/laravel-security-checker'] as $candidate) {
            if (is_dir(static::$appPath.'/'.$candidate)) {
                return static::$appPath.'/'.$candidate;
            }
        }

        return null;
    }

    private function removePublishedFiles(): void
    {
        foreach (self::PUBLISHED_PATHS as $path) {
            (new Process(['rm', '-rf', static::$appPath.'/'.$path]))->run();
        }
    }
}
