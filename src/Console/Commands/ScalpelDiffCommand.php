<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Commands;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;
use Hryagstn\Scalpel\Scalpel;
use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Illuminate\Console\Command;

final class ScalpelDiffCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'scalpel:diff
        {--format=table : Output format (table or json)}';

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
        $this->newLine();
        $this->line('  🔬 <fg=cyan;options=bold>Laravel Scalpel</> — Baseline Diff');
        $this->newLine();

        $scanner = $scalpel->getScanner('Baseline Diff');

        if (! $scanner instanceof BaselineDiffScanner) {
            $this->error('  BaselineDiffScanner is not registered.');

            return 1;
        }

        // Check if baseline exists
        if (! $scanner->baselineExists()) {
            $this->error('  No baseline snapshot found.');
            $this->line('  <fg=gray>Run <fg=white>php artisan scalpel:baseline</> first to create a snapshot.</>');
            $this->newLine();

            return 1;
        }

        $this->info('  ▸ Comparing filesystem against baseline...');
        $this->newLine();

        $basePath = (string) base_path();
        $findings = $scanner->scan($basePath);

        /** @var string $format */
        $format = $this->option('format');

        if ($format === 'json') {
            $this->outputJson($findings);
        } else {
            $this->outputTable($findings);
        }

        return $findings->hasCriticalOrHigh() ? 1 : 0;
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
            $this->info('  ✅ No changes detected. Filesystem matches the baseline.');
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

        // Summary
        $this->line("  <fg=white;options=bold>Total changes detected: {$findings->count()}</>");

        if ($findings->hasCriticalOrHigh()) {
            $this->error('  ⚠  CRITICAL or HIGH severity changes detected. Investigate immediately!');
        }

        $this->newLine();
    }
}
