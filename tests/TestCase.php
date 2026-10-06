<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Enlightn\SecurityChecker\SecurityChecker;
use Jorijn\LaravelSecurityChecker\ServiceProvider;

class TestCase extends \Orchestra\Testbench\TestCase
{
    /**
     * @param \Illuminate\Foundation\Application $app
     * @return array
     */
    protected function getPackageProviders($app): array
    {
        return [ServiceProvider::class];
    }

    /**
     * The expected options are explicit (rather than read from config) so tests prove the
     * commands normalize the config before handing it to the checker.
     */
    protected function bindPassingSecurityChecker(bool $excludeDev = false, array $allowList = []): void
    {
        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->allows('check')
            ->with(base_path('composer.lock'), $excludeDev, $allowList)
            ->andReturns([]);

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);
    }

    /**
     * The expected options are explicit (rather than read from config) so tests prove the
     * commands normalize the config before handing it to the checker.
     */
    protected function bindFailingSecurityChecker(bool $excludeDev = false, array $allowList = []): void
    {
        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->allows('check')
            ->with(base_path('composer.lock'), $excludeDev, $allowList)
            ->andReturns($this->getFakeVulnerabilityReport());

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);
    }

    /**
     * Returns a fake vulnerability report that is digestible by our package
     *
     * @return array
     */
    public function getFakeVulnerabilityReport(): array
    {
        return [
            'bugsnag/bugsnag-laravel' => [
                'version' => 'v2.0.1',
                'advisories' => [
                    'bugsnag/bugsnag-laravel/CVE-2016-5385.yaml' => [
                        'title' => 'HTTP Proxy header vulnerability',
                        'link' => 'https://github.com/bugsnag/bugsnag-laravel/releases/tag/v2.0.2',
                        'cve' => 'CVE-2016-5385'
                    ]
                ]
            ]
        ];
    }
}
