<?php

namespace Jorijn\LaravelSecurityChecker\Checkers;

use Enlightn\SecurityChecker\SecurityChecker;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use Throwable;

/**
 * The 3.x data source: enlightn/security-checker with the FriendsOfPHP advisory database.
 *
 * @deprecated since 4.0, removed in 5.0. The FriendsOfPHP database covers only a fraction of the
 *             advisories Packagist knows about, and enlightn/security-checker does not support
 *             Symfony 8. Kept for one major so nobody is forced to switch in the same upgrade.
 */
class EnlightnChecker implements Checker
{
    public function __construct(private readonly ?string $tempDir = null)
    {
    }

    public function check(string $composerLock, bool $excludeDev = false, array $allowList = []): array
    {
        if (!class_exists(SecurityChecker::class)) {
            throw CheckFailedException::because(
                'The "enlightn" driver needs enlightn/security-checker: '
                .'run `composer require enlightn/security-checker`, or switch to the default "packagist" driver.'
            );
        }

        if (!is_file($composerLock)) {
            throw CheckFailedException::missingLockFile($composerLock);
        }

        try {
            // Resolved through the container so applications (and tests) can still swap it.
            $checker = app()->bound(SecurityChecker::class)
                ? app(SecurityChecker::class)
                : new SecurityChecker($this->tempDir);

            return $checker->check($composerLock, $excludeDev, $allowList);
        } catch (Throwable $e) {
            throw CheckFailedException::because("The Enlightn security checker failed: {$e->getMessage()}", $e);
        }
    }
}
