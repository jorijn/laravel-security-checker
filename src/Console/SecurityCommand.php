<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Illuminate\Console\Command;
use SensioLabs\Security\Formatters\SimpleFormatter;
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
     * @param SecurityChecker $checker
     */
    public function __construct(SecurityChecker $checker)
    {
        parent::__construct();

        $this->checker = $checker;
    }

    /**
     *
     */
    public function fire()
    {
        // get the path to composer.lock
        $composerLock = base_path('composer.lock');

        // and feed it into the SecurityChecker
        $checkResult = $this->checker->check($composerLock);

        // then display it using the formatter provided for Symfony
        app(SimpleFormatter::class)->displayResults($this->getOutput(), $composerLock, $checkResult);
    }
}