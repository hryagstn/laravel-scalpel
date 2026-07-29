<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Commands;

use Hryagstn\Scalpel\Console\Concerns\HasBanner;
use Hryagstn\Scalpel\Console\Concerns\HasScannerProgress;
use Hryagstn\Scalpel\Scalpel;
use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Illuminate\Console\Command;

final class ScalpelBaselineCommand extends Command
{
    use HasBanner;
    use HasScannerProgress;

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'scalpel:baseline
        {--force : Overwrite existing baseline without confirmation}
        {--fast : Enable metadata-based fast scan (deferred hashing)}
        {--no-banner : Suppress the banner/header}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Create a filesystem baseline snapshot';

    /**
     * Execute the console command.
     */
    public function handle(Scalpel $scalpel): int
    {
        if ($this->option('fast')) {
            config(['scalpel.baseline_fast_scan' => true]);
        }

        if (! $this->shouldSuppressBanner()) {
            $this->displayBanner('Baseline Snapshot');
        }

        $scanner = $scalpel->getScanner('Baseline Diff');

        if (! $scanner instanceof BaselineDiffScanner) {
            $this->error('  BaselineDiffScanner is not registered.');

            return 1;
        }

        // Check if baseline already exists
        if ($scanner->baselineExists()) {
            /** @var bool $force */
            $force = $this->option('force');

            if (! $force && ! $this->confirm('A baseline snapshot already exists. Do you want to overwrite it?')) {
                $this->info('  Baseline creation cancelled.');
                $this->newLine();

                return 0;
            }
        }

        $this->info('  ▸ Creating baseline snapshot...');

        $basePath = (string) base_path();

        $progressBar = null;
        $scanner->setProgressCallback(function (string $event, array $data) use (&$progressBar) {
            if ($event === 'start') {
                $progressBar = $this->output->createProgressBar($data['total']);
                $progressBar->setFormat('  %current%/%max% [%bar%] %percent:3s%% -- %message%');
                $progressBar->setMessage('Scanning files...');
                $progressBar->start();
            } elseif ($event === 'advance' && $progressBar) {
                $message = (string) ($data['file'] ?? '');
                if (strlen($message) > 40) {
                    $message = '...'.substr($message, -37);
                }
                $progressBar->setMessage($message);
                $progressBar->advance();
            } elseif ($event === 'finish' && $progressBar) {
                $progressBar->setMessage('Complete!');
                $progressBar->finish();
                $this->newLine();
            }
        });

        $baseline = $scanner->createBaseline($basePath);

        $scanner->setProgressCallback(null);

        $fileCount = $baseline['files'];

        /** @var string $baselinePath */
        $baselinePath = config('scalpel.baseline_path', 'scalpel/baseline.json');

        $this->newLine();
        $this->info('  ✅ Baseline created successfully!');
        $this->line("  📁 Files indexed: <fg=white;options=bold>{$fileCount}</>");
        $this->line("  💾 Stored at: <fg=gray>storage/app/private/{$baselinePath}</>");
        $this->newLine();

        return 0;
    }
}
