<?php

namespace Jorijn\LaravelSecurityChecker\Tests\E2E;

use PHPUnit\Framework\Attributes\TestWith;

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

        // The view used `{{ $information['cve'] or '' }}`. Blade dropped its "or" shorthand in
        // Laravel 5.7, so PHP evaluated a boolean `or` and the CVE column showed "1".
        // Only leaf cells (no nested markup): the mail layout itself is built from nested tables.
        preg_match_all('/<td[^>]*>([^<]*)<\/td>/', $html, $m);
        $cells = array_map('trim', $m[1]);
        $this->assertContains('E2E fixture: framework advisory with a CVE', $cells, 'precondition: the table rendered');

        $this->assertContains('CVE-2099-0001', $cells);
        $this->assertContains('CVE-2099-0003', $cells);
        $this->assertNotContains('1', $cells);
    }

    public function testEveryPackageGetsItsOwnHeading(): void
    {
        $this->artisan(['security-check:email'], ['LCS_MAIL_TO' => 'security@example.com']);

        $html = $this->mailHtml($this->sentMails()[0] ?? '');

        // Both fixture packages must be rendered as a heading. Without a blank line after each
        // table, Markdown treats the next "## package" line as part of the table's HTML block,
        // so every package but the first showed up as literal "## vendor/package" text.
        $this->assertMatchesRegularExpression('/<h2[^>]*>laravel\/framework — /', $html);
        $this->assertMatchesRegularExpression('/<h2[^>]*>phpunit\/phpunit — /', $html);
        $this->assertStringNotContainsString('## ', $html);
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
     * `.env` values like "1", "yes" or "on" are common, and the README only said "true". The
     * command used to compare with `!== true`, so anything env() does not cast to a real boolean
     * was silently ignored and no all-clear mail was sent.
     */
    #[TestWith(['1'])]
    #[TestWith(['yes'])]
    #[TestWith(['on'])]
    public function testNotifyWithoutVulnerabilitiesAcceptsCommonTruthyValues(string $value): void
    {
        $this->useAdvisories('clean');

        $process = $this->artisan(['security-check:email'], [
            'LCS_MAIL_TO' => 'security@example.com',
            'LCS_NOTIFY_WITHOUT_VULNERABILITIES' => $value,
        ]);

        $this->assertSame(0, $process->getExitCode());
        $this->assertCount(1, $this->sentMails());
    }

    /**
     * The flip side of the fix above: falsy spellings must keep the default of sending nothing.
     */
    #[TestWith(['false'])]
    #[TestWith(['0'])]
    #[TestWith(['no'])]
    public function testNotifyWithoutVulnerabilitiesIgnoresFalsyValues(string $value): void
    {
        $this->useAdvisories('clean');

        $process = $this->artisan(['security-check:email'], [
            'LCS_MAIL_TO' => 'security@example.com',
            'LCS_NOTIFY_WITHOUT_VULNERABILITIES' => $value,
        ]);

        $this->assertSame(0, $process->getExitCode());
        $this->assertSame([], $this->sentMails());
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

        // The whole string used to be handed to Symfony Mailer as one address, which rejected it
        // as invalid (RfcComplianceException): the command crashed and nobody was warned.
        $this->assertSame(0, $process->getExitCode(), $process->getOutput().$process->getErrorOutput());
        $mails = $this->sentMails();
        $this->assertCount(1, $mails);
        $this->assertSame('security@example.com, ops@example.com', $this->mailHeader($mails[0], 'To'));
    }

    public function testUnreachableAdvisorySourceMailsACheckCouldNotRunAlert(): void
    {
        $this->breakAdvisorySource('refuse');

        $process = $this->artisan(['security-check:email'], ['LCS_MAIL_TO' => 'security@example.com']);

        // 3.x crashed here and sent nothing, so a broken check looked like a quiet week.
        $this->assertSame(2, $process->getExitCode(), $process->getOutput().$process->getErrorOutput());

        $mails = $this->sentMails();
        $this->assertCount(1, $mails);
        $this->assertSame('security@example.com', $this->mailHeader($mails[0], 'To'));
        $this->assertSame('[E2E App] The security check could not run', $this->mailHeader($mails[0], 'Subject'));

        $html = $this->mailHtml($mails[0]);
        $this->assertStringContainsString(static::$appPath.'/composer.lock', $html);
        $this->assertStringContainsString('Could not reach Packagist', $html);
        $this->assertStringContainsString('the security check could not run, alert emailed to configured recipients', $this->appLog());
    }

    public function testTheCheckCouldNotRunAlertCanBeTurnedOff(): void
    {
        $this->breakAdvisorySource('refuse');

        $process = $this->artisan(['security-check:email'], [
            'LCS_MAIL_TO' => 'security@example.com',
            'LCS_NOTIFY_ON_FAILURE' => 'false',
        ]);

        $this->assertSame(2, $process->getExitCode());
        $this->assertSame([], $this->sentMails());
    }
}
