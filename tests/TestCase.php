<?php

namespace Jorijn\LaravelSecurityChecker\Tests;

use Jorijn\LaravelSecurityChecker\ServiceProvider;

class TestCase extends \Orchestra\Testbench\TestCase
{
    /**
     * @param \Illuminate\Foundation\Application $app
     * @return array
     */
    protected function getPackageProviders($app)
    {
        return [ ServiceProvider::class ];
    }
}
