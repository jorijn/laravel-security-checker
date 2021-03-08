<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Enlightn\SecurityChecker\SecurityChecker;
use Illuminate\Console\Command;
use Jorijn\LaravelSecurityChecker\Formatter\SimpleFormatter;

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
    public function __construct()
    {
        parent::__construct();

        $temp_dir = config('laravel-security-checker.temp_dir', null);

        $this->checker = new SecurityChecker($temp_dir);
    }

    /**
     * Execute the command
     */
    public function handle()
    {
        // get the path to composer.lock
        $composerLock = base_path('composer.lock');

        // and feed it into the SecurityChecker
        $checkResult = $this->checker->check($composerLock);

        // then display it using the formatter provided
        app(SimpleFormatter::class)->displayResults($this->getOutput(), $composerLock, $checkResult);

        return (int) (count($checkResult) > 0);
    }
}
