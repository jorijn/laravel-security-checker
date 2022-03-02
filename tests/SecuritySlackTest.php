<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Jorijn\LaravelSecurityChecker\Notifications\SecuritySlackNotification;

class SecuritySlackTest extends TestCase
{
    /**
     * This method tests if the SecuritySlackNotification class gets rendered correctly.
     */
    public function testSlackNotification(): void
    {
        $vulnerabilities = $this->getFakeVulnerabilityReport();
        $composerLockPath = '/path/to/composer.lock';
        $notification = new SecuritySlackNotification($vulnerabilities, $composerLockPath);

        $this->assertInstanceOf(SecuritySlackNotification::class, $notification);

        $generatedNotification = $notification->toSlack();

        $this->assertEquals('slack', $notification->via()[0]);
        $this->assertEquals($notification->toArray(), $vulnerabilities);
        $this->assertEquals($generatedNotification->username, config('app.url'));
        $this->assertEquals("*Security Check Report:* `{$composerLockPath}`", $generatedNotification->content);
        $this->assertCount(count($generatedNotification->attachments), $vulnerabilities);
    }
}
