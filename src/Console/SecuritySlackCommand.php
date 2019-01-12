<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Notification;
use Jorijn\LaravelSecurityChecker\Notifications\SecuritySlackNotification;
use SensioLabs\Security\SecurityChecker;

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
        // require that the user specifies a slack channel in the .env file
        if (!config('laravel-security-checker.slack_webhook_url')) {
            throw new \Exception('No Slack Webhook has been specified.');
        }

        // get the path to composer.lock
        $composerLock = base_path('composer.lock');

        // and feed it into the SecurityChecker
        $vulnerabilities = json_decode((string)$this->checker->check($composerLock), true);

        // cancel execution here if user does not want to be notified when there are 0 vulns.
        $proceed = config('laravel-security-checker.notify_even_without_vulnerabilities', false);
        if (count($vulnerabilities) === 0 && $proceed !== true) {
            return 0;
        }

        Notification::route('slack', config('laravel-security-checker.slack_webhook_url', null))
            ->notify(new SecuritySlackNotification($vulnerabilities, realpath($composerLock)));
    }
}
