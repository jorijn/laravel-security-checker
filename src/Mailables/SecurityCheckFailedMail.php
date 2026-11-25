<?php

namespace Jorijn\LaravelSecurityChecker\Mailables;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

/**
 * Sent by security-check:email when the check itself could not run.
 *
 * Without it a broken check (Packagist unreachable, a missing composer.lock) looked exactly like
 * a quiet week without vulnerabilities, because by default no mail is sent in that case.
 */
class SecurityCheckFailedMail extends Mailable
{
    use SerializesModels;
    use Queueable;

    public function __construct(public readonly string $reason, public readonly string $composerLock)
    {
    }

    /**
     * @return $this
     */
    public function build()
    {
        $title = __('laravel-security-checker::messages.subject_check_failed');

        return $this->subject('['.config('app.name').'] '.$title)
            ->markdown('laravel-security-checker::security-check-failed', [
                'title' => $title,
                'reason' => $this->reason,
                'composerLock' => $this->composerLock,
            ]);
    }
}
