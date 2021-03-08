<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Enlightn\SecurityChecker\SecurityChecker;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;

class SecurityMailCommand extends Command
{
    /**
     * @var string
     */
    protected $name = 'security-check:email';

    /**
     * @var string
     */
    protected $description = 'Emails any vulnerabilities for packages you have in your composer.lock file.';

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
        Log::debug('about to check for vulnerabilities');
        $checkResult = $this->checker->check($composerLock);

        // if the user didn't want any email if there are no results,
        // cancel execution here.
        $proceed = config('laravel-security-checker.notify_even_without_vulnerabilities', false);
        if ($proceed !== true && \count($checkResult) === 0) {
            Log::info('no vulnerabilities were found, not sending any email');
            return 0;
        }

        // get the recipients and filter out any configuration mistakes
        $recipients = collect(config('laravel-security-checker.recipients', [ ]))->filter(function ($recipient) {
            return $recipient !== null && !empty($recipient);
        });

        if ($recipients->count() === 0) {
            Log::error('vulnerabilities were found, but there are no recipients configured');
            $this->error(
                /** @scrutinizer ignore-type */__('laravel-security-checker::messages.no_recipients_configured')
            );
            return 1;
        }

        Log::warning('vulnerabilities were found, emailed to configured recipients');
        Mail::to($recipients->toArray())->send(new SecurityMail($checkResult));

        return 0;
    }
}
