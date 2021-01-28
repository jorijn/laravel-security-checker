<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Enlightn\SecurityChecker\AdvisoryAnalyzer;
use Enlightn\SecurityChecker\AdvisoryFetcher;
use Enlightn\SecurityChecker\AdvisoryParser;
use Enlightn\SecurityChecker\Composer;
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
     * Execute the command
     */
    public function handle()
    {
        // get the path to composer.lock
        $composerLock = base_path('composer.lock');

        $parser = new AdvisoryParser((new AdvisoryFetcher)->fetchAdvisories());

        $dependencies = (new Composer)->getDependencies($composerLock);

        // and feed it into the AdvisoryAnalyzer
        $checkResult = (new AdvisoryAnalyzer($parser->getAdvisories()))->analyzeDependencies($dependencies);

        // then display it using the formatter provided
        app(SimpleFormatter::class)->displayResults($this->getOutput(), $composerLock, $checkResult);

        return (int) (count($checkResult) > 0);
    }
}
