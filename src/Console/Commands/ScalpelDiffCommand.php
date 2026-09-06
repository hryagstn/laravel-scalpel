<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Commands;

use Hryagstn\Scalpel\Console\Commands\Concerns\InteractsWithFindings;
use Hryagstn\Scalpel\Console\Concerns\HasBanner;
use Hryagstn\Scalpel\Console\Concerns\HasScannerProgress;
use Hryagstn\Scalpel\Console\Concerns\OutputsFindings;
use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;
use Hryagstn\Scalpel\Events\ScanFinished;
use Hryagstn\Scalpel\Scalpel;
use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Illuminate\Console\Command;

final class ScalpelDiffCommand extends Command
{
    use HasBanner;
    use HasScannerProgress;
    use InteractsWithFindings;
    use OutputsFindings;

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'scalpel:diff
        {--format=table : Output format (table, json, github or sarif)}
        {--fast : Enable metadata-based fast scan (deferred hashing)}
        {--fail-on= : Minimum severity that constitutes failure: CRITICAL, HIGH, MEDIUM or LOW (default: HIGH)}
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
        $this->resetFindingsState();
        $startedAt = microtime(true);

        $originalFast = config('scalpel.baseline_fast_scan');
        if ($this->option('fast')) {
            config(['scalpel.baseline_fast_scan' => true]);
        }

        // Resolve early so an invalid --fail-on value warns before scanning
        $this->failOnSeverity();

        if (! $this->shouldSuppressBanner()) {
            $this->displayBanner('Baseline Diff');
        }

        $scanner = $scalpel->getScanner('Baseline Diff');

        if (! $scanner instanceof BaselineDiffScanner) {
            $this->error('  BaselineDiffScanner is not registered.');

            return 1;
        }

        // Check if baseline exists.
        // A missing baseline is reported by the scanner as a MEDIUM finding,
        // so mirror that severity in the exit code (2 = findings below the
        // failure threshold).
        if (! $scanner->baselineExists()) {
            $this->info('  No baseline snapshot found.');
            $this->info('  Run "php artisan scalpel:baseline" first to create a snapshot.');
            $this->newLine();

            $findings = new FindingCollection([Finding::make(
                severity: Severity::MEDIUM,
                file: $scanner->getBaselinePath(),
                line: null,
                description: 'No baseline snapshot found. Run `php artisan scalpel:baseline` to create one.',
                scannerName: $scanner->name(),
            )]);
            $findings = $this->applySeverityThreshold($findings);
            event(new ScanFinished($findings, 'diff', (microtime(true) - $startedAt) * 1000));
            $formatOption = $this->option('format');
            $format = is_string($formatOption) ? $formatOption : 'table';
            if ($format === 'json') {
                $this->outputJson($findings);
            } elseif ($format === 'sarif') {
                $this->outputSarif($findings);
            } elseif ($format === 'github') {
                $this->outputGithubAnnotations($findings);
            } else {
                $this->outputTable($findings);
            }
            config(['scalpel.baseline_fast_scan' => $originalFast]);

            return $this->resolveExitCode($findings);
        }

        $formatOption = $this->option('format');
        $format = is_string($formatOption) ? $formatOption : 'table';

        if (! in_array($format, ['json', 'sarif', 'github'], true)) {
            $this->info('  ▸ Comparing filesystem against baseline...');
            $this->newLine();
        }

        $basePath = (string) base_path();
        $findings = $this->runScannerWithProgress($scanner, $basePath, $format);

        // Apply severity threshold from config
        $findings = $this->applySeverityThreshold($findings);

        // Announce results to listeners (notifications, alerting, ...)
        event(new ScanFinished($findings, 'diff', (microtime(true) - $startedAt) * 1000));

        if ($format === 'json') {
            $this->outputJson($findings);
        } elseif ($format === 'sarif') {
            $this->outputSarif($findings);
        } elseif ($format === 'github') {
            $this->outputGithubAnnotations($findings);
        } else {
            $this->outputTable($findings, '✅ No changes detected. Filesystem matches the baseline.');
        }

        $exitCode = $this->resolveExitCode($findings);
        config(['scalpel.baseline_fast_scan' => $originalFast]);

        return $exitCode;
    }
}
