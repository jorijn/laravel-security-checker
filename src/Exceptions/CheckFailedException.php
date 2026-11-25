<?php

namespace Jorijn\LaravelSecurityChecker\Exceptions;

use RuntimeException;
use Throwable;

/**
 * The security check could not run, so nothing is known about the vulnerabilities.
 *
 * This is deliberately a separate outcome from "no vulnerabilities found": treating a failed
 * check as an all-clear would be the most dangerous thing this package could do. The commands
 * turn it into exit code 2 and, for the mail and Slack commands, a "check could not run" alert.
 */
class CheckFailedException extends RuntimeException
{
    public static function because(string $reason, ?Throwable $previous = null): self
    {
        return new self($reason, 0, $previous);
    }

    public static function missingLockFile(string $path): self
    {
        return new self("Cannot read the lock file $path. Run composer install or composer update to create it.");
    }
}
