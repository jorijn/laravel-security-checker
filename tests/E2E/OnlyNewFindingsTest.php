<?php

namespace Jorijn\LaravelSecurityChecker\Tests\E2E;

/**
 * LCS_NOTIFY_ONLY_NEW against the app's real (default) cache store.
 */
class OnlyNewFindingsTest extends E2ETestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Each scenario starts without any memory of earlier runs.
        $this->artisan(['cache:clear']);
    }

    public function testEachFindingIsMailedOnce(): void
    {
        $env = ['LCS_MAIL_TO' => 'security@example.com', 'LCS_NOTIFY_ONLY_NEW' => 'true'];

        // Without dev dependencies first: only laravel/framework is found, and new.
        $first = $this->artisan(['security-check:email'], $env + ['LCS_EXCLUDE_DEV' => 'true']);
        $this->assertSame(0, $first->getExitCode(), $first->getOutput().$first->getErrorOutput());

        // Same findings again: nothing new, nothing sent.
        $this->artisan(['security-check:email'], $env + ['LCS_EXCLUDE_DEV' => 'true']);

        // With dev dependencies, phpunit/phpunit appears: only that is new.
        $this->artisan(['security-check:email'], $env);

        $mails = $this->sentMails();
        $this->assertCount(2, $mails, $this->appLog());

        $this->assertSame('[E2E App] 1 package has known vulnerabilities', $this->mailHeader($mails[0], 'Subject'));
        $this->assertStringContainsString('laravel/framework', $this->mailHtml($mails[0]));

        $this->assertSame('[E2E App] 1 package has known vulnerabilities', $this->mailHeader($mails[1], 'Subject'));
        $this->assertStringContainsString('phpunit/phpunit', $this->mailHtml($mails[1]));
        $this->assertStringNotContainsString('laravel/framework', $this->mailHtml($mails[1]));

        $this->assertStringContainsString('no new vulnerabilities since the last run, not sending any email', $this->appLog());
    }

    public function testTheConsoleCommandAlwaysShowsEverything(): void
    {
        $this->artisan(['security-check:email'], ['LCS_MAIL_TO' => 'security@example.com', 'LCS_NOTIFY_ONLY_NEW' => 'true']);

        $process = $this->artisan(['security-check:now'], ['LCS_NOTIFY_ONLY_NEW' => 'true']);

        $this->assertStringContainsString('[CRITICAL] 2 packages have known vulnerabilities', $process->getOutput());
    }
}
