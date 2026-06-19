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
        {--format=table : Output format (table or json)}
        {--no-banner : Suppress the banner/header}';

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
        if (! $this->shouldSuppressBanner()) {
            $this->displayBanner();
        }

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
        $version = ltrim(Scalpel::version(), 'v');
        $this->newLine();
        $this->line('  ╔══════════════════════════════════════════════════╗');
        $this->line($this->formatBoxLine('  🔬 <fg=cyan;options=bold>Laravel Scalpel</> — Intrusion Evidence Scanner  '));
        $this->line($this->formatBoxLine("  <fg=gray>v{$version} • Filesystem Security Analysis</>"));
        $this->line('  ╚══════════════════════════════════════════════════╝');
        $this->newLine();
    }

    /**
     * Determine if the banner/header should be suppressed.
     */
    private function shouldSuppressBanner(): bool
    {
        return $this->option('format') === 'json'
            || ($this->hasOption('no-ansi') && $this->option('no-ansi'))
            || $this->option('no-banner')
            || config('scalpel.suppress_banner', false);
    }

    /**
     * Format a line to fit perfectly inside the banner's double box.
     */
    private function formatBoxLine(string $content, int $innerWidth = 50): string
    {
        $visibleContent = preg_replace('/<[^>]*>/', '', $content);
        $visibleLength = mb_strlen($visibleContent ?? '', 'UTF-8');
        $padLength = max(0, $innerWidth - $visibleLength);

        return "  ║" . $content . str_repeat(' ', $padLength) . "║";
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
    private function runAllScanners(Scalpel $scalpel, string $basePath): FindingCollection
    {
        $collection = new FindingCollection();
        $format = $this->option('format');

        foreach ($scalpel->getScanners() as $scanner) {
            $collection->merge($this->runScanner($scalpel, $scanner, $basePath, $format));
        }

        if ($format !== 'json') {
            $this->newLine();
        }

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
        $format = $this->option('format');

        foreach ($scalpel->getScanners() as $scanner) {
            if (in_array($scanner->name(), $scannerNames, true)) {
                $collection->merge($this->runScanner($scalpel, $scanner, $basePath, $format));
            }
        }

        if ($format !== 'json') {
            $this->newLine();
        }

        return $collection;
    }

    /**
     * Run a single scanner, optionally showing progress.
     */
    private function runScanner(Scalpel $scalpel, \Hryagstn\Scalpel\Contracts\ScannerInterface $scanner, string $basePath, string $format): FindingCollection
    {
        if ($format !== 'json') {
            $this->info("  ▸ Running scanner: {$scanner->name()}");
        }

        $hasProgress = $format !== 'json' && $scanner instanceof \Hryagstn\Scalpel\Scanners\BaseScanner;
        if ($hasProgress) {
            $progressBar = null;
            $scanner->setProgressCallback(function (string $event, array $data) use (&$progressBar) {
                if ($event === 'start') {
                    $progressBar = $this->output->createProgressBar($data['total']);
                    $progressBar->setFormat('  %current%/%max% [%bar%] %percent:3s%% -- %message%');
                    $progressBar->setMessage('Scanning files...');
                    $progressBar->start();
                } elseif ($event === 'advance' && $progressBar) {
                    $message = $data['file'];
                    if (strlen($message) > 40) {
                        $message = '...' . substr($message, -37);
                    }
                    $progressBar->setMessage($message);
                    $progressBar->advance();
                } elseif ($event === 'finish' && $progressBar) {
                    $progressBar->setMessage('Complete!');
                    $progressBar->finish();
                    $this->newLine();
                }
            });
        }

        $findings = $scanner->scan($basePath);

        if ($hasProgress) {
            $scanner->setProgressCallback(null);
        }

        return $findings;
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
        $payload = [
            'total'    => $findings->count(),
            'findings' => $findings->toArray(),
        ];

        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if (config('scalpel.signing.enabled', false)) {
            $key = config('scalpel.signing.key');
            if (empty($key)) {
                throw new \RuntimeException('Scalpel signing is enabled but the signing key (SCALPEL_SIGNING_KEY) is not configured.');
            }
            $signature = hash_hmac('sha256', $json, $key);
            $payload['signature'] = $signature;
            $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }

        $this->line((string) $json);
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
            $this->line('  <fg=red;options=bold>⚠  CRITICAL or HIGH severity findings detected. Investigate immediately!</>');
        }

        $this->newLine();
    }
}
