<?php

namespace Jorijn\LaravelSecurityChecker;

use Jorijn\LaravelSecurityChecker\Console\SecurityCommand;

class ServiceProvider extends \Illuminate\Support\ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $configPath = __DIR__.'/../config/laravel-security-checker.php';
        $this->mergeConfigFrom($configPath, 'laravel-security-checker');
    }

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $configPath = __DIR__.'/../config/laravel-security-checker.php';
        $this->publishes([ $configPath => $this->getConfigPath() ], 'config');

        if ($this->app->runningInConsole()) {
            $this->commands([
                SecurityCommand::class
            ]);
        }
    }

    /**
     * Get the config path
     *
     * @return string
     */
    protected function getConfigPath()
    {
        return config_path('laravel-security-checker.php');
    }

    /**
     * Publish the config file
     *
     * @param  string $configPath
     */
    protected function publishConfig($configPath)
    {
        $this->publishes([ $configPath => config_path('laravel-security-checker.php') ], 'config');
    }
}
