<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Illuminate\Console\Command;
use Jorijn\LaravelSecurityChecker\Console\Concerns\ChecksForVulnerabilities;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use Jorijn\LaravelSecurityChecker\Formatter\SimpleFormatter;

class SecurityCommand extends Command
{
    use ChecksForVulnerabilities;

    /**
     * @var string
     */
    protected $name = 'security-check:now';

    /**
     * @var string
     */
    protected $description = 'Checks composer.lock for known vulnerabilities. '
        .'Exits with 1 when vulnerabilities are found, 2 when the check could not run.';

    /**
     * Execute the command
     */
    public function handle(): int
    {
        // get the path to composer.lock
        $composerLock = base_path('composer.lock');

        try {
            $checkResult = $this->checkForVulnerabilities($composerLock);
        } catch (CheckFailedException $e) {
            // The console output and exit code 2 are the alert here; see handleFailedCheck().
            return $this->handleFailedCheck($e, $composerLock);
        }

        // then display it using the formatter provided
        app(SimpleFormatter::class)->displayResults($this->getOutput(), $composerLock, $checkResult);

        return count($checkResult) > 0 ? self::VULNERABILITIES_FOUND : self::SUCCESS;
    }
}
