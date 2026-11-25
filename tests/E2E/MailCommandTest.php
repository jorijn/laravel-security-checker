<?php

namespace Jorijn\LaravelSecurityChecker\Tests\E2E;

/**
 * `php artisan security-check:email`: the mail as Laravel really renders and sends it.
 */
class MailCommandTest extends E2ETestCase
{
    public function testMailsTheReportToTheConfiguredRecipient(): void
    {
        $process = $this->artisan(['security-check:email'], ['LCS_MAIL_TO' => 'security@example.com']);

        $this->assertSame(0, $process->getExitCode(), $process->getOutput().$process->getErrorOutput());

        $mails = $this->sentMails();
        $this->assertCount(1, $mails);

        $mail = $mails[0];
        $this->assertSame('security@example.com', $this->mailHeader($mail, 'To'));
        $this->assertSame('[E2E App] 2 packages have known vulnerabilities', $this->mailHeader($mail, 'Subject'));

        $html = $this->mailHtml($mail);
        $this->assertStringContainsString('2 packages have known vulnerabilities', $html);
        $this->assertMatchesRegularExpression('/laravel\/framework — \d+\.\d+\.\d+/', $html);
        $this->assertStringContainsString('phpunit/phpunit', $html);
        $this->assertStringContainsString('E2E fixture: framework advisory with a CVE', $html);
        $this->assertStringContainsString('https://example.com/advisories/CVE-2099-0001', $html);
        $this->assertStringNotContainsString('CVE-2099-0009', $html);

        $this->assertStringContainsString('vulnerabilities were found, emailed to configured recipients', $this->appLog());
    }

    public function testMailShowsTheCveCode(): void
    {
        $this->artisan(['security-check:email'], ['LCS_MAIL_TO' => 'security@example.com']);

        $html = $this->mailHtml($this->sentMails()[0] ?? '');

        // The view uses `{{ $information['cve'] or '' }}`. Blade dropped its "or" shorthand in
        // Laravel 5.7, so PHP now evaluates a boolean `or` and the CVE column shows "1".
        // Only leaf cells (no nested markup): the mail layout itself is built from nested tables.
        preg_match_all('/<td[^>]*>([^<]*)<\/td>/', $html, $m);
        $cells = array_map('trim', $m[1]);
        $this->assertContains('E2E fixture: framework advisory with a CVE', $cells, 'precondition: the table rendered');

        $this->assertKnownBug('the mail shows "1" instead of the CVE code', function () use ($cells) {
            $this->assertContains('CVE-2099-0001', $cells);
            $this->assertContains('CVE-2099-0003', $cells);
            $this->assertNotContains('1', $cells);
        });
    }

    public function testSendsNothingWithoutVulnerabilitiesByDefault(): void
    {
        $this->useAdvisories('clean');

        $process = $this->artisan(['security-check:email'], ['LCS_MAIL_TO' => 'security@example.com']);

        $this->assertSame(0, $process->getExitCode());
        $this->assertSame([], $this->sentMails());
        $this->assertStringContainsString('no vulnerabilities were found, not sending any email', $this->appLog());
    }

    public function testNotifyWithoutVulnerabilitiesSendsAnAllClearMail(): void
    {
        $this->useAdvisories('clean');

        $process = $this->artisan(['security-check:email'], [
            'LCS_MAIL_TO' => 'security@example.com',
            'LCS_NOTIFY_WITHOUT_VULNERABILITIES' => 'true',
        ]);

        $this->assertSame(0, $process->getExitCode());

        $mails = $this->sentMails();
        $this->assertCount(1, $mails);
        $this->assertSame('[E2E App] No packages have known vulnerabilities', $this->mailHeader($mails[0], 'Subject'));
        $this->assertStringContainsString('It seems that no packages have any known vulnerabilities', $this->mailHtml($mails[0]));
    }

    /**
     * `.env` values like "1", "yes" or "on" are common, and the README only says "true". The
     * command compares with `!== true`, so anything env() does not cast to a real boolean is
     * silently ignored and no all-clear mail is sent.
     */
    public function testNotifyWithoutVulnerabilitiesAcceptsCommonTruthyValues(): void
    {
        $this->useAdvisories('clean');

        $process = $this->artisan(['security-check:email'], [
            'LCS_MAIL_TO' => 'security@example.com',
            'LCS_NOTIFY_WITHOUT_VULNERABILITIES' => '1',
        ]);

        $this->assertSame(0, $process->getExitCode());

        $this->assertKnownBug('LCS_NOTIFY_WITHOUT_VULNERABILITIES is ignored unless it is literally "true"', function () {
            $this->assertCount(1, $this->sentMails());
        });
    }

    public function testFailsWithoutRecipients(): void
    {
        $process = $this->artisan(['security-check:email']);

        $this->assertSame(1, $process->getExitCode());
        $this->assertStringContainsString('No recipients has been configured yet!', $process->getOutput().$process->getErrorOutput());
        $this->assertSame([], $this->sentMails());
        $this->assertStringContainsString('vulnerabilities were found, but there are no recipients configured', $this->appLog());
    }

    public function testCommaSeparatedRecipientsAllReceiveTheMail(): void
    {
        $process = $this->artisan(['security-check:email'], [
            'LCS_MAIL_TO' => 'security@example.com,ops@example.com',
        ]);

        // The whole string is handed to Symfony Mailer as one address, which rejects it as
        // invalid (RfcComplianceException): the command crashes and nobody is warned.
        $this->assertKnownBug('a comma-separated LCS_MAIL_TO crashes the command', function () use ($process) {
            $this->assertSame(0, $process->getExitCode(), $process->getOutput().$process->getErrorOutput());
            $mails = $this->sentMails();
            $this->assertCount(1, $mails);
            $this->assertSame('security@example.com, ops@example.com', $this->mailHeader($mails[0], 'To'));
        });
    }

    public function testUnreachableAdvisorySourceFailsLoudlyAndSendsNoMail(): void
    {
        $this->breakAdvisorySource('refuse');

        $process = $this->artisan(['security-check:email'], ['LCS_MAIL_TO' => 'security@example.com']);

        // Characterisation of 3.x: the exception reaches the scheduler/cron output, no mail is
        // sent. 4.0 will add a dedicated exit code and an alert for this case.
        $this->assertNotSame(0, $process->getExitCode());
        $this->assertSame([], $this->sentMails());
    }
}
