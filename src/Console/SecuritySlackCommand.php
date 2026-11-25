<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Jorijn\LaravelSecurityChecker\Console\Concerns\ChecksForVulnerabilities;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use Jorijn\LaravelSecurityChecker\Notifications\SecurityCheckFailedSlackNotification;
use Jorijn\LaravelSecurityChecker\Notifications\SecuritySlackNotification;

class SecuritySlackCommand extends Command
{
    use ChecksForVulnerabilities;

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

        try {
            $vulnerabilities = $this->checkForVulnerabilities($composerLock);
        } catch (CheckFailedException $e) {
            return $this->handleFailedCheck($e, $composerLock);
        }

        // cancel execution here if user does not want to be notified when there are 0 vulns.
        if (count($vulnerabilities) === 0 && !$this->notifyWithoutVulnerabilities()) {
            Log::info('no vulnerabilities were found, not sending a slack notification');
            $this->rememberFindings($vulnerabilities, $composerLock);

            return 0;
        }

        $newVulnerabilities = $this->newFindings($vulnerabilities, $composerLock);

        if (count($vulnerabilities) > 0 && count($newVulnerabilities) === 0) {
            Log::info('no new vulnerabilities since the last run, not sending a slack notification');
            $this->rememberFindings($vulnerabilities, $composerLock);

            return 0;
        }

        Log::warning('vulnerabilities were found, sending slack notification to configured hook');
        Notification::route('slack', config('laravel-security-checker.slack_webhook_url', null))
            ->notify(new SecuritySlackNotification($newVulnerabilities, realpath($composerLock)));
        $this->rememberFindings($vulnerabilities, $composerLock);

        return 0;
    }

    /**
     * Posts the "security check could not run" alert to the configured Slack webhook.
     */
    protected function notifyAboutFailedCheck(CheckFailedException $e, string $composerLock): void
    {
        Notification::route('slack', config('laravel-security-checker.slack_webhook_url'))
            ->notify(new SecurityCheckFailedSlackNotification($e->getMessage(), $composerLock));

        Log::warning('the security check could not run, alert sent to the configured slack hook');
    }
}
