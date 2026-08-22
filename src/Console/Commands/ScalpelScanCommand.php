<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Commands;

use Hryagstn\Scalpel\Console\Commands\Concerns\InteractsWithFindings;
use Hryagstn\Scalpel\Console\Concerns\HasBanner;
use Hryagstn\Scalpel\Console\Concerns\HasScannerProgress;
use Hryagstn\Scalpel\Console\Concerns\OutputsFindings;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Events\ScanFinished;
use Hryagstn\Scalpel\Scalpel;
use Illuminate\Console\Command;

final class ScalpelScanCommand extends Command
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
    protected $signature = 'scalpel:scan
        {--only= : Comma-separated list of scanners to run}
        {--format=table : Output format (table, json or github)}
        {--fast : Enable metadata-based fast scan (deferred hashing)}
        {--include-vendor : Include the vendor/ directory in content scanning (slower)}
        {--fail-on= : Minimum severity that constitutes failure: CRITICAL, HIGH, MEDIUM or LOW (default: HIGH)}
        {--no-banner : Suppress the banner/header}
        {--production : Force production-level environment security checks}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Scan the application for intrusion evidence';

    /**
     * Execute the console command.
     */
    public function handle(Scalpel $scalpel): int
    {
        $this->resetFindingsState();
        $startedAt = microtime(true);

        if ($this->option('fast')) {
            config(['scalpel.baseline_fast_scan' => true]);
        }

        if ($this->option('production')) {
            config(['scalpel.assume_production' => true]);
        }

        if ($this->option('include-vendor')) {
            $this->enableVendorContentScanning();
        }

        // Resolve early so an invalid --fail-on value warns before scanning
        $this->failOnSeverity();

        if (! $this->shouldSuppressBanner()) {
            $this->displayBanner('Intrusion Evidence Scanner');
        }

        $basePath = (string) base_path();

        /** @var string|null $onlyOption */
        $onlyOption = $this->option('only');

        $formatOption = $this->option('format');
        $format = is_string($formatOption) ? $formatOption : 'table';

        // Run scanners
        if ($onlyOption !== null && $onlyOption !== '') {
            $scannerClasses = $this->resolveScannerNames($onlyOption);
            $findings = $this->runSelectedScanners($scalpel, $basePath, $scannerClasses, $format);
        } else {
            $findings = $this->runAllScanners($scalpel, $basePath, $format);
        }

        // Apply severity threshold from config
        $findings = $this->applySeverityThreshold($findings);

        // Announce results to listeners (notifications, alerting, ...)
        event(new ScanFinished($findings, 'scan', (microtime(true) - $startedAt) * 1000));

        // Output results
        if ($format === 'json') {
            $this->outputJson($findings);
        } elseif ($format === 'github') {
            $this->outputGithubAnnotations($findings);
        } else {
            $this->outputTable($findings);
        }

        return $this->resolveExitCode($findings);
    }

    /**
     * Remove vendor/ from the content-scan exclusion list so content
     * scanners also analyze installed packages. Baseline diff always
     * monitors vendor/ regardless of this flag.
     */
    private function enableVendorContentScanning(): void
    {
        /** @var string[] $paths */
        $paths = config('scalpel.content_scan_excluded_paths', []);

        config([
            'scalpel.content_scan_excluded_paths' => array_values(array_diff($paths, ['vendor'])),
        ]);
    }

    /**
     * Resolve scanner aliases to their scanner class names.
     *
     * Aliases are resolved against Scalpel::SCANNER_ALIASES which maps each
     * alias to a scanner class, so the mapping can never drift from the
     * scanners' name() methods.
     *
     * @return array<class-string>
     */
    private function resolveScannerNames(string $onlyOption): array
    {
        $aliases = array_map('trim', explode(',', $onlyOption));
        $resolved = [];

        foreach ($aliases as $alias) {
            $alias = strtolower($alias);

            $scannerClass = Scalpel::SCANNER_ALIASES[$alias] ?? null;

            if ($scannerClass === null) {
                if (! is_string($this->option('format')) || $this->option('format') !== 'json') {
                    $this->warn("Unknown scanner alias: {$alias}");
                }

                continue;
            }

            $resolved[] = $scannerClass;
        }

        return $resolved;
    }

    /**
     * Run all scanners with progress output.
     *
     * @param  class-string[]|null  $scannerClasses  When non-null, ONLY these scanner classes run
     *                                               (an empty array therefore runs no scanners).
     */
    private function runAllScanners(Scalpel $scalpel, string $basePath, string $format, ?array $scannerClasses = null): FindingCollection
    {
        $collection = new FindingCollection;

        foreach ($scalpel->getScanners() as $scanner) {
            if ($scannerClasses !== null && ! in_array($scanner::class, $scannerClasses, true)) {
                continue;
            }

            $collection->merge($this->runScannerWithProgress($scanner, $basePath, $format));
        }

        if ($format !== 'json' && $format !== 'github') {
            $this->newLine();
        }

        return $collection;
    }

    /**
     * Run only selected scanners with progress output.
     *
     * @param  class-string[]  $scannerClasses
     */
    private function runSelectedScanners(Scalpel $scalpel, string $basePath, array $scannerClasses, string $format): FindingCollection
    {
        return $this->runAllScanners($scalpel, $basePath, $format, $scannerClasses);
    }
}
