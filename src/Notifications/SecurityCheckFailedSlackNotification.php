<?php

namespace Jorijn\LaravelSecurityChecker\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\SlackMessage;
use Illuminate\Notifications\Notification;

/**
 * Posted by security-check:slack when the check itself could not run.
 */
class SecurityCheckFailedSlackNotification extends Notification
{
    use Queueable;

    public function __construct(public readonly string $reason, public readonly string $composerLock)
    {
    }

    /**
     * @return array<int, string>
     */
    public function via(): array
    {
        return ['slack'];
    }

    public function toSlack(): SlackMessage
    {
        return (new SlackMessage())
            ->error()
            ->from(config('app.url'))
            ->content('*'.__('laravel-security-checker::messages.subject_check_failed').'*')
            ->attachment(function ($attachment) {
                $attachment
                    ->content(implode(PHP_EOL.PHP_EOL, [
                        __('laravel-security-checker::messages.body_check_failed', [
                            'path' => '`'.$this->composerLock.'`',
                        ]),
                        '> '.$this->reason,
                        __('laravel-security-checker::messages.body_check_failed_hint'),
                    ]))
                    ->markdown(['text']);
            });
    }

    /**
     * @return array{reason: string, composer_lock: string}
     */
    public function toArray(): array
    {
        return ['reason' => $this->reason, 'composer_lock' => $this->composerLock];
    }
}
