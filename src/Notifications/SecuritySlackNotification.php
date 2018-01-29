<?php

namespace Jorijn\LaravelSecurityChecker\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Queue\SerializesModels;
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Messages\SlackMessage;

class SecuritySlackNotification extends Notification
{
    use SerializesModels, Queueable;

    /**
     *
     * @var array
     */
    protected $vulnerabilities;

    /**
     *
     * @var string
     */
    protected $composerLockPath;

    /**
     * Create a new notification instance.
     *
     * @return void
     */
    public function __construct($vulnerabilities, $composerLockPath)
    {
        $this->vulnerabilities = $vulnerabilities;
        $this->composerLockPath = $composerLockPath;
    }

    /**
     * Get the notification's delivery channels.
     *
     * @param  mixed  $notifiable
     * @return array
     */
    public function via($notifiable)
    {
        return ['slack'];
    }

    /**
     * Get the slack representation of the notification.
     *
     * @param  mixed  $notifiable
     * @return \Illuminate\Notifications\Messages\SlackMessage
     */
    public function toSlack($notifiable)
    {
        $vulnerabilities = $this->vulnerabilities;

        return (new SlackMessage)
            ->from(config('app.url'))
            ->content("*Security Check Report:* `{$this->composerLockPath}`")
            ->attachment(function ($attachment) {
                $attachment->content($this->textFormatter())
                ->markdown(['pretext']);
            });
    }

    /**
     * Get the array representation of the notification.
     *
     * @param  mixed  $notifiable
     * @return array
     */
    public function toArray($notifiable)
    {
        return $this->vulnerabilities;
    }

    protected function textFormatter()
    {
        $count = count($this->vulnerabilities);

        $txt = sprintf("%d %s known vulnerabilities\n", $count, 1 === $count ? 'package has' : 'packages have');

        if (0 !== $count) {
            foreach ($this->vulnerabilities as $dependency => $issues) {
                $dependencyFullName = $dependency . ' (' . $issues['version'] . ')';
                $txt .= "\n";
                $txt .= "*{$dependencyFullName}*" . "\n" . str_repeat('-', strlen($dependencyFullName)) . "\n";

                foreach ($issues['advisories'] as $issue => $details) {
                    $txt .= ' * ';
                    if ($details['cve']) {
                        $txt .= "{$details['cve']} ";
                    }
                    $txt .= "{$details['title']} ";

                    if ('' !== $details['link']) {
                        $txt .= "{$details['link']}";
                    }

                    $txt .= "\n";
                }
            }
        }
        return $txt;
    }
}
