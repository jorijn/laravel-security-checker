<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;

class SecurityMailTest extends TestCase
{
    /**
     * This method tests if the Mailable class gets rendered correctly.
     */
    public function testLaravelMailable(): void
    {
        // create the mailable
        $vulnerabilities = $this->getFakeVulnerabilityReport();
        $mailable = new SecurityMail($vulnerabilities);

        $this->assertInstanceOf(SecurityMail::class, $mailable);

        // build the mailable with the build() method -- this fills all template
        // variables and generates the subject and title.
        $generatedMailable  = $mailable->build();
        $vulnerabilityCount = count($vulnerabilities);
        $translatedSubject  = trans_choice(
            'laravel-security-checker::messages.subject_new_vulnerabilities',
            $vulnerabilityCount,
            [ 'count' => $vulnerabilityCount ]
        );

        // assert that this has been done correctly.
        $this->assertEquals($generatedMailable->viewData['title'], $translatedSubject);
        $this->assertEquals($generatedMailable->subject, '['.Config::get('app.name').'] '. $translatedSubject);
    }

    /**
     * The view used Blade's removed `or` shorthand, which made the CVE column render "1".
     */
    public function testRenderedMailShowsTheCveCode(): void
    {
        $report = $this->getFakeVulnerabilityReport();
        $report['vendor/without-cve'] = [
            'version' => 'v1.0.0',
            'advisories' => [
                'vendor/without-cve/2024-01-01.yaml' => [
                    'title' => 'Advisory without a CVE',
                    'link' => 'https://example.com/advisory',
                    'cve' => '',
                ],
            ],
        ];

        $html = (new SecurityMail($report))->render();

        preg_match_all('/<td[^>]*>([^<]*)<\/td>/', $html, $matches);
        $cells = array_map('trim', $matches[1]);

        $this->assertContains('CVE-2016-5385', $cells);
        $this->assertNotContains('1', $cells);
    }
}
