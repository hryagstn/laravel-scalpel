<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel;

use Hryagstn\Scalpel\Console\Commands\ScalpelBaselineCommand;
use Hryagstn\Scalpel\Console\Commands\ScalpelDiffCommand;
use Hryagstn\Scalpel\Console\Commands\ScalpelScanCommand;
use Hryagstn\Scalpel\Console\Commands\ScalpelVerifyCommand;
use Illuminate\Support\ServiceProvider;

final class ScalpelServiceProvider extends ServiceProvider
{
    /**
     * Register package services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/scalpel.php',
            'scalpel',
        );

        $this->app->singleton(Scalpel::class, function (): Scalpel {
            return new Scalpel(Scalpel::getDefaultScanners());
        });
    }

    /**
     * Bootstrap package services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/scalpel.php' => config_path('scalpel.php'),
        ], 'scalpel-config');

        if ($this->app->runningInConsole()) {
            $this->commands([
                ScalpelScanCommand::class,
                ScalpelBaselineCommand::class,
                ScalpelDiffCommand::class,
                ScalpelVerifyCommand::class,
            ]);
        }
    }
}
