<?php

namespace Jorijn\LaravelSecurityChecker\Mailables;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class SecurityMail extends Mailable
{
    use SerializesModels;
    use Queueable;

    protected $checkResult;

    /**
     * SecurityMail constructor.
     *
     * @param array $checkResult results from the Security Checker
     */
    public function __construct($checkResult)
    {
        $this->checkResult = $checkResult;
    }

    /**
     * Build the message.
     *
     * @return $this
     */
    public function build()
    {
        $packageCount = count($this->checkResult);
        $title = trans_choice('laravel-security-checker::messages.subject_new_vulnerabilities', $packageCount, [
            'count' => $packageCount
        ]);
        $subject = '['.config('app.name').'] '.$title;

        return $this->subject($subject)
            ->markdown('laravel-security-checker::security-mail', [
                'title'    => $title,
                'packages' => $this->checkResult
            ]);
    }

    /**
     * @return array
     */
    public function getCheckResult()
    {
        return $this->checkResult;
    }
}
