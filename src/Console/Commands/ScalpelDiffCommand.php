<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Commands;

use Hryagstn\Scalpel\Console\Concerns\HasBanner;
use Hryagstn\Scalpel\Console\Concerns\HasScannerProgress;
use Hryagstn\Scalpel\Console\Concerns\OutputsFindings;
use Hryagstn\Scalpel\Scalpel;
use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Illuminate\Console\Command;

final class ScalpelDiffCommand extends Command
{
    use HasBanner;
    use HasScannerProgress;
    use OutputsFindings;

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'scalpel:diff
        {--format=table : Output format (table or json)}
        {--fast : Enable metadata-based fast scan (deferred hashing)}
        {--no-banner : Suppress the banner/header}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Compare current filesystem against baseline';

    /**
     * Execute the console command.
     */
    public function handle(Scalpel $scalpel): int
    {
        if ($this->option('fast')) {
            config(['scalpel.baseline_fast_scan' => true]);
        }

        if (! $this->shouldSuppressBanner()) {
            $this->displayBanner('Baseline Diff');
        }

        $scanner = $scalpel->getScanner('Baseline Diff');

        if (! $scanner instanceof BaselineDiffScanner) {
            $this->error('  BaselineDiffScanner is not registered.');

            return 1;
        }

        // Check if baseline exists
        if (! $scanner->baselineExists()) {
            $this->info('  No baseline snapshot found.');
            $this->info('  Run "php artisan scalpel:baseline" first to create a snapshot.');
            $this->newLine();

            return 1;
        }

        $formatOption = $this->option('format');
        $format = is_string($formatOption) ? $formatOption : 'table';

        if ($format !== 'json') {
            $this->info('  ▸ Comparing filesystem against baseline...');
            $this->newLine();
        }

        $basePath = (string) base_path();
        $findings = $this->runScannerWithProgress($scanner, $basePath, $format);

        // Apply severity threshold from config
        $findings = $this->applySeverityThreshold($findings);

        if ($format === 'json') {
            $this->outputJson($findings);
        } else {
            $this->outputTable($findings, '✅ No changes detected. Filesystem matches the baseline.');
        }

        return $findings->hasCriticalOrHigh() ? 1 : 0;
    }
}
