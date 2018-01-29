<?php

namespace Jorijn\LaravelSecurityChecker;

use Jorijn\LaravelSecurityChecker\Console\SecurityCommand;
use Jorijn\LaravelSecurityChecker\Console\SecurityMailCommand;
use Jorijn\LaravelSecurityChecker\Console\SecuritySlackCommand;

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
        $configPath = __DIR__ . '/../config/laravel-security-checker.php';
        $this->mergeConfigFrom($configPath, 'laravel-security-checker');
    }

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        // configuration
        $configPath = __DIR__ . '/../config/laravel-security-checker.php';
        $this->publishes([$configPath => $this->getConfigPath()], 'config');

        // views
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'laravel-security-checker');
        $this->publishes([
            __DIR__ . '/../resources/views' => resource_path('views/vendor/laravel-security-checker'),
        ], 'views');

        // translations
        $this->loadTranslationsFrom(__DIR__ . '/../resources/lang', 'laravel-security-checker');
        $this->publishes([
            __DIR__ . '/../resources/lang' => resource_path('lang/vendor/laravel-security-checker'),
        ], 'translations');

        if ($this->app->runningInConsole()) {
            $this->commands([
                SecurityCommand::class,
                SecurityMailCommand::class,
                SecuritySlackCommand::class,
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
}
