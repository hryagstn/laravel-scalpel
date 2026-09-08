<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Concerns;

use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;
use Hryagstn\Scalpel\Scalpel;

trait OutputsFindings
{
    /**
     * Apply the configured severity threshold to filter findings.
     */
    protected function applySeverityThreshold(FindingCollection $findings): FindingCollection
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
     * Output findings as JSON, with optional HMAC signing.
     */
    protected function outputJson(FindingCollection $findings): void
    {
        $payload = [
            'schema_version' => 1,
            'status' => $findings->status(),
            'generated_at' => date('c'),
            'scanned_files' => $findings->scannedFilesCount(),
            'skipped_files' => $findings->skippedFilesCount(),
            'skipped_directories' => $findings->skippedDirectoriesCount(),
            'total' => $findings->count(),
            'findings' => $findings->toArray(),
            'errors' => $findings->errors(),
        ];

        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        if ((bool) config('scalpel.signing.enabled', false)) {
            /** @var string|null $key */
            $key = config('scalpel.signing.key');
            if (empty($key)) {
                throw new \RuntimeException('Scalpel signing is enabled but the signing key (SCALPEL_SIGNING_KEY) is not configured.');
            }
            $signature = hash_hmac('sha256', (string) $json, $key);
            $payload['signature'] = $signature;
            $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        }

        $this->line((string) $json);
    }

    /** Output findings in SARIF 2.1.0 for code-scanning integrations. */
    protected function outputSarif(FindingCollection $findings): void
    {
        $results = [];
        foreach ($findings as $finding) {
            $physicalLocation = [
                'artifactLocation' => ['uri' => $finding->file],
            ];

            if ($finding->line !== null) {
                $physicalLocation['region'] = [
                    'startLine' => $finding->line,
                ];
            }

            $results[] = [
                'ruleId' => strtolower(str_replace(' ', '-', $finding->scannerName)),
                'level' => match ($finding->severity) {
                    Severity::CRITICAL, Severity::HIGH => 'error',
                    Severity::MEDIUM => 'warning',
                    Severity::LOW => 'note',
                },
                'message' => ['text' => $finding->description],
                'locations' => [[
                    'physicalLocation' => $physicalLocation,
                ]],
            ];
        }

        $notifications = [];
        foreach ($findings->errors() as $error) {
            $notifications[] = [
                'level' => 'error',
                'message' => ['text' => "[{$error['scanner']}] {$error['error']}"],
                'descriptor' => ['id' => strtolower(str_replace(' ', '-', $error['scanner'])).'-error'],
                'locations' => [[
                    'physicalLocation' => [
                        'artifactLocation' => ['uri' => $error['file']],
                    ],
                ]],
            ];
        }

        $this->line((string) json_encode([
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => ['driver' => ['name' => 'Laravel Scalpel', 'version' => Scalpel::version()]],
                'invocations' => [[
                    'executionSuccessful' => ! $findings->hasErrors() && $findings->status() !== 'failed',
                    'toolExecutionNotifications' => $notifications,
                    'properties' => [
                        'status' => $findings->status(),
                        'scannedFiles' => $findings->scannedFilesCount(),
                        'skippedFiles' => $findings->skippedFilesCount(),
                        'skippedDirectories' => $findings->skippedDirectoriesCount(),
                    ],
                ]],
                'results' => $results,
            ]],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /**
     * Output findings as formatted tables grouped by severity.
     */
    protected function outputTable(FindingCollection $findings, string $cleanMessage = '✅ No findings detected. Your application looks clean!'): void
    {
        if ($findings->hasErrors()) {
            $statusLabel = strtoupper($findings->status());
            $this->warn("  ⚠  Some files or directories could not be inspected (scan status: {$statusLabel}):");
            foreach ($findings->errors() as $err) {
                $this->line("    • [{$err['scanner']}] {$err['file']}: {$err['error']}");
            }
            $this->newLine();
        }

        if ($findings->isEmpty()) {
            if ($findings->hasErrors()) {
                $this->warn(sprintf(
                    '  ⚠  No security findings detected, but the scan was %s (%d files, %d directories skipped due to read errors).',
                    $findings->status(),
                    $findings->skippedFilesCount(),
                    $findings->skippedDirectoriesCount(),
                ));
            } else {
                $this->info("  {$cleanMessage}");
            }
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

            $this->line("  <fg={$severity->color()};options=bold>{$severity->badge()}</> (".count($severityFindings).' findings)');

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

        // Summary table by scanner if available
        $byScanner = $findings->groupByScanner();
        if (count($byScanner) > 1) {
            $this->line('  <fg=cyan;options=bold>📊 Summary by Scanner</>');

            $summaryRows = [];
            foreach ($byScanner as $scannerName => $scannerFindings) {
                $summaryRows[] = [$scannerName, (string) count($scannerFindings)];
            }

            $this->table(['Scanner', 'Findings'], $summaryRows);
            $this->newLine();
        }

        $this->line("  <fg=white;options=bold>Total findings: {$findings->count()}</>");

        if ($findings->hasCriticalOrHigh()) {
            $this->line('  <fg=red;options=bold>⚠  CRITICAL or HIGH severity findings detected. Investigate immediately!</>');
        }

        $this->newLine();
    }
}
