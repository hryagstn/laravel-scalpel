<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Commands;

use Hryagstn\Scalpel\Console\Concerns\HasBanner;
use Hryagstn\Scalpel\Console\Concerns\HasScannerProgress;
use Hryagstn\Scalpel\Console\Concerns\OutputsFindings;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Scalpel;
use Illuminate\Console\Command;

final class ScalpelScanCommand extends Command
{
    use HasBanner;
    use HasScannerProgress;
    use OutputsFindings;

    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'scalpel:scan
        {--only= : Comma-separated list of scanners to run}
        {--format=table : Output format (table or json)}
        {--fast : Enable metadata-based fast scan (deferred hashing)}
        {--no-banner : Suppress the banner/header}
        {--production : Force production-level environment security checks}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Scan the application for intrusion evidence';

    /**
     * Scanner name aliases mapped to their class name() returns.
     *
     * @var array<string, string>
     */
    private const SCANNER_ALIASES = [
        'structural' => 'Structural Anomaly',
        'obfuscated' => 'Obfuscated Code',
        'htaccess' => 'Htaccess',
        'baseline' => 'Baseline Diff',
        'env' => 'Env Integrity',
    ];

    /**
     * Execute the console command.
     */
    public function handle(Scalpel $scalpel): int
    {
        if ($this->option('fast')) {
            config(['scalpel.baseline_fast_scan' => true]);
        }

        if ($this->option('production')) {
            config(['scalpel.assume_production' => true]);
        }

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
            $scannerNames = $this->resolveScannerNames($onlyOption);
            $findings = $this->runSelectedScanners($scalpel, $basePath, $scannerNames, $format);
        } else {
            $findings = $this->runAllScanners($scalpel, $basePath, $format);
        }

        // Apply severity threshold from config
        $findings = $this->applySeverityThreshold($findings);

        // Output results
        if ($format === 'json') {
            $this->outputJson($findings);
        } else {
            $this->outputTable($findings);
        }

        return $findings->hasCriticalOrHigh() ? 1 : 0;
    }

    /**
     * Resolve scanner aliases to their actual names.
     *
     * @return string[]
     */
    private function resolveScannerNames(string $onlyOption): array
    {
        $aliases = array_map('trim', explode(',', $onlyOption));
        $resolved = [];

        foreach ($aliases as $alias) {
            $alias = strtolower($alias);

            if (isset(self::SCANNER_ALIASES[$alias])) {
                $resolved[] = self::SCANNER_ALIASES[$alias];
            } else {
                if ($this->option('format') !== 'json') {
                    $this->warn("Unknown scanner alias: {$alias}");
                }
            }
        }

        return $resolved;
    }

    /**
     * Run all scanners with progress output.
     */
    private function runAllScanners(Scalpel $scalpel, string $basePath, string $format): FindingCollection
    {
        $collection = new FindingCollection;

        foreach ($scalpel->getScanners() as $scanner) {
            $collection->merge($this->runScannerWithProgress($scanner, $basePath, $format));
        }

        if ($format !== 'json') {
            $this->newLine();
        }

        return $collection;
    }

    /**
     * Run only selected scanners with progress output.
     *
     * @param  string[]  $scannerNames
     */
    private function runSelectedScanners(Scalpel $scalpel, string $basePath, array $scannerNames, string $format): FindingCollection
    {
        $collection = new FindingCollection;

        foreach ($scalpel->getScanners() as $scanner) {
            if (in_array($scanner->name(), $scannerNames, true)) {
                $collection->merge($this->runScannerWithProgress($scanner, $basePath, $format));
            }
        }

        if ($format !== 'json') {
            $this->newLine();
        }

        return $collection;
    }
}
