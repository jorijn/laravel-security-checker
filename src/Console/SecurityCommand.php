<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Illuminate\Console\Command;
use Jorijn\LaravelSecurityChecker\Formatter\SimpleFormatter;
use SensioLabs\Security\SecurityChecker;

class SecurityCommand extends Command
{
    /**
     * @var string
     */
    protected $name = 'security-check:now';

    /**
     * @var string
     */
    protected $description = 'Checks composer.lock for any vulnerabilities against the SensioLabs checker.';

    /**
     * @var SecurityChecker
     */
    protected $checker;

    /**
     * SecurityCommand constructor.
     *
     * @param SecurityChecker $checker
     */
    public function __construct(SecurityChecker $checker)
    {
        parent::__construct();

        $this->checker = $checker;
    }

    /**
     * Execute the command
     */
    public function handle()
    {
        // get the path to composer.lock
        $composerLock = base_path('composer.lock');

        // and feed it into the SecurityChecker
        $checkResult = json_decode((string)$this->checker->check($composerLock), true);

        // then display it using the formatter provided for Symfony
        app(SimpleFormatter::class)->displayResults($this->getOutput(), $composerLock, $checkResult);

        return 0;
    }
}
