<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Illuminate\Support\Facades\Config;
use Jorijn\LaravelSecurityChecker\Mailables\SecurityMail;

class SecurityMailTest extends TestCase
{
    /**
     * This method tests if the Mailable class gets rendered correctly.
     */
    public function testLaravelMailable()
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
}
