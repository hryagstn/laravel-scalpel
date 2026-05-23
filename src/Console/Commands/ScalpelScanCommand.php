<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Commands;

use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;
use Hryagstn\Scalpel\Scalpel;
use Illuminate\Console\Command;

final class ScalpelScanCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'scalpel:scan
        {--only= : Comma-separated list of scanners to run}
        {--format=table : Output format (table or json)}';

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
        'structural'  => 'Structural Anomaly',
        'obfuscated'  => 'Obfuscated Code',
        'htaccess'    => '.htaccess',
        'baseline'    => 'Baseline Diff',
        'env'         => 'Env Integrity',
    ];

    /**
     * Execute the console command.
     */
    public function handle(Scalpel $scalpel): int
    {
        $this->displayBanner();

        $basePath = (string) base_path();

        /** @var string|null $onlyOption */
        $onlyOption = $this->option('only');

        /** @var string $format */
        $format = $this->option('format');

        // Run scanners
        if ($onlyOption !== null && $onlyOption !== '') {
            $scannerNames = $this->resolveScannerNames($onlyOption);
            $findings = $this->runSelectedScanners($scalpel, $basePath, $scannerNames);
        } else {
            $findings = $this->runAllScanners($scalpel, $basePath);
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
     * Display the package banner.
     */
    private function displayBanner(): void
    {
        $this->newLine();
        $this->line('  ╔══════════════════════════════════════════════════╗');
        $this->line('  ║  🔬 <fg=cyan;options=bold>Laravel Scalpel</> — Intrusion Evidence Scanner  ║');
        $this->line('  ║  <fg=gray>v1.0.0 • Filesystem Security Analysis</>           ║');
        $this->line('  ╚══════════════════════════════════════════════════╝');
        $this->newLine();
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
                $this->warn("Unknown scanner alias: {$alias}");
            }
        }

        return $resolved;
    }

    /**
     * Run all scanners with progress output.
     */
    private function runAllScanners(Scalpel $scalpel, string $basePath): FindingCollection
    {
        $collection = new FindingCollection();

        foreach ($scalpel->getScanners() as $scanner) {
            $this->info("  ▸ Running scanner: {$scanner->name()}");
            $collection->merge($scanner->scan($basePath));
        }

        $this->newLine();

        return $collection;
    }

    /**
     * Run only selected scanners with progress output.
     *
     * @param string[] $scannerNames
     */
    private function runSelectedScanners(Scalpel $scalpel, string $basePath, array $scannerNames): FindingCollection
    {
        $collection = new FindingCollection();

        foreach ($scalpel->getScanners() as $scanner) {
            if (in_array($scanner->name(), $scannerNames, true)) {
                $this->info("  ▸ Running scanner: {$scanner->name()}");
                $collection->merge($scanner->scan($basePath));
            }
        }

        $this->newLine();

        return $collection;
    }

    /**
     * Apply the configured severity threshold to filter findings.
     */
    private function applySeverityThreshold(FindingCollection $findings): FindingCollection
    {
        /** @var string $thresholdValue */
        $thresholdValue = config('scalpel.severity_threshold', 'LOW');
        $threshold = Severity::tryFrom($thresholdValue);

        if ($threshold === null) {
            return $findings;
        }

        return $findings->filterBySeverity($threshold);
    }

    /**
     * Output findings as JSON.
     */
    private function outputJson(FindingCollection $findings): void
    {
        $this->line((string) json_encode([
            'total'    => $findings->count(),
            'findings' => $findings->toArray(),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    /**
     * Output findings as formatted tables grouped by severity.
     */
    private function outputTable(FindingCollection $findings): void
    {
        if ($findings->isEmpty()) {
            $this->info('  ✅ No findings detected. Your application looks clean!');
            $this->newLine();

            return;
        }

        // Group findings by severity: CRITICAL first, then HIGH, MEDIUM, LOW
        $grouped = $findings->groupBySeverity();
        $severityOrder = [
            Severity::CRITICAL->value,
            Severity::HIGH->value,
            Severity::MEDIUM->value,
            Severity::LOW->value,
        ];

        foreach ($severityOrder as $severityValue) {
            if (! isset($grouped[$severityValue])) {
                continue;
            }

            $severityFindings = $grouped[$severityValue];
            $severity = Severity::from($severityValue);

            $this->line("  <fg={$severity->color()};options=bold>{$severity->badge()}</> (" . count($severityFindings) . ' findings)');

            $rows = [];
            foreach ($severityFindings as $finding) {
                $rows[] = [
                    $finding->severity->badge(),
                    $finding->file,
                    $finding->line !== null ? (string) $finding->line : '-',
                    $finding->description,
                ];
            }

            $this->table(
                ['Severity', 'File', 'Line', 'Description'],
                $rows,
            );

            $this->newLine();
        }

        // Summary table: scanner name → count
        $this->line('  <fg=cyan;options=bold>📊 Summary by Scanner</>');

        $byScanner = $findings->groupByScanner();
        $summaryRows = [];

        foreach ($byScanner as $scannerName => $scannerFindings) {
            $summaryRows[] = [$scannerName, (string) count($scannerFindings)];
        }

        $this->table(['Scanner', 'Findings'], $summaryRows);
        $this->newLine();

        $this->line("  <fg=white;options=bold>Total findings: {$findings->count()}</>");

        if ($findings->hasCriticalOrHigh()) {
            $this->error('  ⚠  CRITICAL or HIGH severity findings detected. Investigate immediately!');
        }

        $this->newLine();
    }
}
