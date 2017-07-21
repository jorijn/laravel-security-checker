<?php

namespace Jorijn\LaravelSecurityChecker\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Mail;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;
use SensioLabs\Security\SecurityChecker;

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
    public function __construct(SecurityChecker $checker)
    {
        parent::__construct();

        $this->checker = $checker;
    }

    /**
     *
     */
    public function fire()
    {
        // get the path to composer.lock
        $composerLock = base_path('composer.lock');

        // and feed it into the SecurityChecker
        $checkResult = $this->checker->check($composerLock);

        $recipients = config('laravel-security-checker.recipients', []);
        if (count($recipients) === 0) {
            $this->error(__('No recipients has been configured yet!'));
            return 1;
        }

        Mail::to($recipients)->send(new SecurityMail($checkResult));
    }
}
