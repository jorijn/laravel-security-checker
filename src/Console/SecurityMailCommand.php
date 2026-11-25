<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Jorijn\LaravelSecurityChecker\Console\Concerns\ChecksForVulnerabilities;
use Jorijn\LaravelSecurityChecker\Exceptions\CheckFailedException;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityCheckFailedMail;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;

class SecurityMailCommand extends Command
{
    use ChecksForVulnerabilities;

    /**
     * @var string
     */
    protected $name = 'security-check:email';

    /**
     * @var string
     */
    protected $description = 'Emails any vulnerabilities for packages you have in your composer.lock file.';

    /**
     * Execute the command
     */
    public function handle()
    {
        // get the path to composer.lock
        $composerLock = base_path('composer.lock');

        // and feed it into the SecurityChecker
        Log::debug('about to check for vulnerabilities');

        try {
            $checkResult = $this->checkForVulnerabilities($composerLock);
        } catch (CheckFailedException $e) {
            return $this->handleFailedCheck($e, $composerLock);
        }

        // if the user didn't want any email if there are no results,
        // cancel execution here.
        if (!$this->notifyWithoutVulnerabilities() && \count($checkResult) === 0) {
            Log::info('no vulnerabilities were found, not sending any email');
            $this->rememberFindings($checkResult, $composerLock);
            return 0;
        }

        $newVulnerabilities = $this->newFindings($checkResult, $composerLock);

        if (\count($checkResult) > 0 && \count($newVulnerabilities) === 0) {
            Log::info('no new vulnerabilities since the last run, not sending any email');
            $this->rememberFindings($checkResult, $composerLock);
            return 0;
        }

        $recipients = $this->recipients();

        if ($recipients->count() === 0) {
            Log::error('vulnerabilities were found, but there are no recipients configured');
            $this->error(__('laravel-security-checker::messages.no_recipients_configured'));
            return 1;
        }

        Log::warning('vulnerabilities were found, emailed to configured recipients');
        Mail::to($recipients->toArray())->send(new SecurityMail($newVulnerabilities));
        $this->rememberFindings($checkResult, $composerLock);

        return 0;
    }

    /**
     * Mails the "security check could not run" alert to the configured recipients.
     */
    protected function notifyAboutFailedCheck(CheckFailedException $e, string $composerLock): void
    {
        $recipients = $this->recipients();

        if ($recipients->count() === 0) {
            Log::error('the security check could not run, and there are no recipients configured to alert');

            return;
        }

        Mail::to($recipients->toArray())->send(new SecurityCheckFailedMail($e->getMessage(), $composerLock));
        Log::warning('the security check could not run, alert emailed to configured recipients');
    }

    /**
     * Returns the configured recipients as a flat list of addresses.
     *
     * .env files can only hold one string, so people naturally write
     * LCS_MAIL_TO="a@example.com,b@example.com". Handed to the mailer as is, that whole string is
     * treated as a single (invalid) address and the command crashes, so nobody gets the report.
     * Splitting is done here rather than in the config file, so configs that were already
     * published keep working without changes.
     *
     * @return \Illuminate\Support\Collection<int, string>
     */
    protected function recipients()
    {
        return collect(config('laravel-security-checker.recipients', []))
            // a published config may also hold a single string instead of an array
            ->flatten()
            // a plain address never contains a comma or semicolon (only exotic quoted local parts could)
            ->flatMap(fn ($recipient) => is_string($recipient) ? preg_split('/[,;]/', $recipient) : [])
            ->map(fn (string $recipient) => trim($recipient))
            // drop configuration leftovers like an unset LCS_MAIL_TO or a trailing comma
            ->filter(fn (string $recipient) => $recipient !== '')
            ->unique()
            ->values();
    }
}
