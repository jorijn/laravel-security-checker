<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Enlightn\SecurityChecker\AdvisoryAnalyzer;
use Enlightn\SecurityChecker\AdvisoryFetcher;
use Enlightn\SecurityChecker\AdvisoryParser;
use Enlightn\SecurityChecker\Composer;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Jorijn\LaravelSecurityChecker\Notifications\SecuritySlackNotification;

class SecuritySlackCommand extends Command
{
    /**
     * @var string
     */
    protected $name = 'security-check:slack';

    /**
     * @var string
     */
    protected $description = 'Send vulnerabilities to a Slack channel.';

    /**
     * Execute the command
     */
    public function handle()
    {
        // require that the user specifies a slack channel in the .env file
        if (!config('laravel-security-checker.slack_webhook_url')) {
            Log::error('checking for vulnerabilities using slack was requested but no hook is configured');
            throw new \Exception('No Slack Webhook has been specified.');
        }

        // get the path to composer.lock
        $composerLock = base_path('composer.lock');

        // and feed it into the SecurityChecker
        Log::debug('about to check for vulnerabilities');
        $parser = new AdvisoryParser((new AdvisoryFetcher)->fetchAdvisories());
        $dependencies = (new Composer)->getDependencies($composerLock);
        $vulnerabilities = (new AdvisoryAnalyzer($parser->getAdvisories()))->analyzeDependencies($dependencies);

        // cancel execution here if user does not want to be notified when there are 0 vulns.
        $proceed = config('laravel-security-checker.notify_even_without_vulnerabilities', false);
        if (count($vulnerabilities) === 0 && $proceed !== true) {
            Log::info('no vulnerabilities were found, not sending a slack notification');

            return 0;
        }

        Log::warning('vulnerabilities were found, sending slack notification to configured hook');
        Notification::route('slack', config('laravel-security-checker.slack_webhook_url', null))
            ->notify(new SecuritySlackNotification($vulnerabilities, realpath($composerLock)));
    }
}
