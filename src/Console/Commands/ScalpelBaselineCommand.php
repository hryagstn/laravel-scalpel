<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Commands;

use Hryagstn\Scalpel\Scalpel;
use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Illuminate\Console\Command;

final class ScalpelBaselineCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'scalpel:baseline
        {--force : Overwrite existing baseline without confirmation}';

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
        $this->newLine();
        $this->line('  🔬 <fg=cyan;options=bold>Laravel Scalpel</> — Baseline Snapshot');
        $this->newLine();

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
        $baseline = $scanner->createBaseline($basePath);

        $fileCount = $baseline['files'];

        /** @var string $baselinePath */
        $baselinePath = config('scalpel.baseline_path', 'scalpel/baseline.json');

        $this->newLine();
        $this->info("  ✅ Baseline created successfully!");
        $this->line("  📁 Files indexed: <fg=white;options=bold>{$fileCount}</>");
        $this->line("  💾 Stored at: <fg=gray>storage/app/private/{$baselinePath}</>");
        $this->newLine();

        return 0;
    }
}
