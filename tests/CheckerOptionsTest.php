<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Covers how the exclude_dev and allow_list config values are normalized before they reach the
 * Enlightn checker. All commands share this logic, so security-check:now is used to drive it.
 */
class CheckerOptionsTest extends TestCase
{
    public function testDefaultsWhenNothingIsConfigured(): void
    {
        $this->bindPassingSecurityChecker(false, []);

        $this->artisan('security-check:now')->assertExitCode(0);
    }

    public static function validAllowListProvider(): array
    {
        return [
            // LCS_ALLOW_LIST from .env always arrives as a string
            'json string from .env' => ['["CVE-2024-1234","Example vulnerability title"]', ['CVE-2024-1234', 'Example vulnerability title']],
            'empty .env value' => ['', []],
            'whitespace .env value' => ['   ', []],
            'empty json array' => ['[]', []],
            // a published config file can hold a PHP array
            'php array' => [['CVE-2024-1234'], ['CVE-2024-1234']],
            'keyed php array' => [['laravel-xss' => 'CVE-2024-1234'], ['CVE-2024-1234']],
            'null' => [null, []],
            // Enlightn compares strictly, so clean up entries that could never match
            'entries are trimmed and non-strings dropped' => [[' CVE-2024-1234 ', '', 42, null, ['nested']], ['CVE-2024-1234']],
        ];
    }

    #[DataProvider('validAllowListProvider')]
    public function testValidAllowListIsPassedToTheChecker(mixed $configured, array $expected): void
    {
        Config::set('laravel-security-checker.allow_list', $configured);

        $this->bindPassingSecurityChecker(false, $expected);

        $this->artisan('security-check:now')->assertExitCode(0);
    }

    public static function invalidAllowListProvider(): array
    {
        return [
            // these used to reach Enlightn as null/stdClass and crash with a TypeError
            'plain cve string' => ['CVE-2024-1234'],
            'comma separated string' => ['CVE-2024-1234,CVE-2024-5678'],
            'broken json' => ['["CVE-2024-1234"'],
            'json scalar' => ['123'],
            'non array value' => [123],
        ];
    }

    #[DataProvider('invalidAllowListProvider')]
    public function testInvalidAllowListIsIgnoredWithAWarningSoTheCheckStillRuns(mixed $configured): void
    {
        Log::spy();
        Config::set('laravel-security-checker.allow_list', $configured);

        // vulnerabilities must still be reported: an invalid allow list must never hide anything
        $this->bindFailingSecurityChecker(false, []);

        $this->artisan('security-check:now')
            ->expectsOutputToContain('allow_list is invalid')
            ->assertExitCode(1);

        Log::shouldHaveReceived('warning')->once();
    }

    public static function excludeDevProvider(): array
    {
        return [
            'bool true' => [true, true],
            'bool false' => [false, false],
            'string "1" from a published config' => ['1', true],
            'string "yes"' => ['yes', true],
            'string "false"' => ['false', false],
            'null' => [null, false],
        ];
    }

    #[DataProvider('excludeDevProvider')]
    public function testExcludeDevIsCastToABoolean(mixed $configured, bool $expected): void
    {
        Config::set('laravel-security-checker.exclude_dev', $configured);

        $this->bindPassingSecurityChecker($expected, []);

        $this->artisan('security-check:now')->assertExitCode(0);
    }
}
