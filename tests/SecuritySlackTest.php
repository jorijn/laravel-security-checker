<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;
use Jorijn\LaravelSecurityChecker\Notifications\SecuritySlackNotification;

class SecuritySlackTest extends TestCase
{
    /**
     * This method tests if the SecuritySlackNotification class gets rendered correctly.
     */
    public function testSlackNotification()
    {
        $vulnerabilities = $this->getFakeVulnerabilityReport();
        $composerLockPath = '/path/to/composer.lock';
        $notification = new SecuritySlackNotification($vulnerabilities, $composerLockPath);

        $this->assertInstanceOf(SecuritySlackNotification::class, $notification);

        $generatedNotification = $notification->toSlack();

        $this->assertEquals($notification->via()[0], 'slack');
        $this->assertEquals($notification->toArray(), $vulnerabilities);
        $this->assertEquals($generatedNotification->username, config('app.url'));
        $this->assertEquals($generatedNotification->content, "*Security Check Report:* `{$composerLockPath}`");
        $this->assertEquals(count($generatedNotification->attachments), count($vulnerabilities));
    }
}
