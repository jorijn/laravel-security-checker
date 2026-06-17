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

    protected function bindPassingSecurityChecker(): void
    {
        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->allows('check')
            ->with(
                base_path('composer.lock'),
                config('laravel-security-checker.exclude_dev', false),
                config('laravel-security-checker.allow_list', [])
            )
            ->andReturns([]);

        // bind Mockery instance to the app container
        $this->app->instance(SecurityChecker::class, $securityCheckerMock);
    }

    protected function bindFailingSecurityChecker(): void
    {
        $securityCheckerMock = \Mockery::mock(SecurityChecker::class);
        $securityCheckerMock->allows('check')
            ->with(
                base_path('composer.lock'),
                config('laravel-security-checker.exclude_dev', false),
                config('laravel-security-checker.allow_list', [])
            )
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
