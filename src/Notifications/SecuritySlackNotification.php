<?php

namespace Jorijn\LaravelSecurityChecker\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\SlackMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Queue\SerializesModels;

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
     * @param $vulnerabilities
     * @param $composerLockPath
     */
    public function __construct($vulnerabilities, $composerLockPath)
    {
        $this->vulnerabilities = $vulnerabilities;
        $this->composerLockPath = $composerLockPath;
    }

    /**
     * Get the notification's delivery channels.
     *
     * @return array
     */
    public function via()
    {
        return ['slack'];
    }

    /**
     * Get the slack representation of the notification.
     *
     * @return SlackMessage
     */
    public function toSlack()
    {
        return (new SlackMessage)
            ->from(config('app.url'))
            ->content("*Security Check Report:* `{$this->composerLockPath}`")
            ->attachment(function ($attachment) {
                $attachment->content($this->textFormatter())->markdown(['text']);
            });
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array
     */
    public function toArray()
    {
        return $this->vulnerabilities;
    }

    /**
     * @return string
     */
    protected function textFormatter()
    {
        $packageCount = \count($this->vulnerabilities);
        $content = trans_choice('laravel-security-checker::messages.subject_new_vulnerabilities', $packageCount, [
            'count' => $packageCount,
        ]);

        if ($packageCount > 0) {
            foreach ($this->vulnerabilities as $dependency => $issues) {
                $dependencyFullName = sprintf('%s (%s)', $dependency, $issues['version']);

                $content .= PHP_EOL;
                $content .= sprintf('*%s*', $dependencyFullName);
                $content .= PHP_EOL;
                $content .= str_repeat('-', \strlen($dependencyFullName));
                $content .= PHP_EOL;

                foreach ($issues['advisories'] as $issue => $details) {
                    $content .= ' * ';

                    if ($details['cve']) {
                        $content .= $details['cve'].' ';
                    }

                    $content .= $details['title'].' ';

                    if (!empty($details['link'])) {
                        $content .= $details['link'];
                    }

                    $content .= PHP_EOL;
                }
            }
        }

        return $content;
    }
}
