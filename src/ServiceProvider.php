<?php

namespace Jorijn\LaravelSecurityChecker;

use Jorijn\LaravelSecurityChecker\Console\SecurityCommand;
use Jorijn\LaravelSecurityChecker\Console\SecurityMailCommand;
use Jorijn\LaravelSecurityChecker\Console\SecuritySlackCommand;
use Jorijn\LaravelSecurityChecker\Contracts\Checker;

class ServiceProvider extends \Illuminate\Support\ServiceProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $configPath = __DIR__.'/../config/laravel-security-checker.php';
        $this->mergeConfigFrom($configPath, 'laravel-security-checker');
 
        $this->app->singleton(CheckerManager::class);

        // Not a singleton: the configured driver is looked up each time a command runs, so a
        // config change (or a test) never sees a stale driver.
        $this->app->bind(Checker::class, fn ($app) => $app->make(CheckerManager::class)->driver());
    }

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        // configuration
        $configPath = __DIR__.'/../config/laravel-security-checker.php';
        $this->publishes([ $configPath => $this->getConfigPath() ], 'config');

        // views
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'laravel-security-checker');
        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/laravel-security-checker'),
        ], 'views');

        // translations
        $this->loadTranslationsFrom(__DIR__.'/../resources/lang', 'laravel-security-checker');
        // langPath() follows the app's own layout: lang/ since Laravel 9, or resources/lang when an
        // older app still has that directory. Publishing to resource_path('lang') instead created
        // resources/lang in modern apps, which makes Laravel switch its whole language path there
        // and silently lose the app's own translations in lang/.
        $this->publishes([
            __DIR__.'/../resources/lang' => $this->app->langPath('vendor/laravel-security-checker'),
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
