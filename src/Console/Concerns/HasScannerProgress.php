<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Concerns;

use Hryagstn\Scalpel\Contracts\ScannerInterface;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Scanners\BaseScanner;

trait HasScannerProgress
{
    /**
     * Run a single scanner, optionally showing progress.
     */
    protected function runScannerWithProgress(ScannerInterface $scanner, string $basePath, string $format): FindingCollection
    {
        if (! in_array($format, ['json', 'sarif'], true)) {
            $this->info("  ▸ Running scanner: {$scanner->name()}");
        }

        $hasProgress = ! in_array($format, ['json', 'sarif'], true) && $scanner instanceof BaseScanner;
        if ($hasProgress) {
            $progressBar = null;
            $scanner->setProgressCallback(function (string $event, array $data) use (&$progressBar) {
                if ($event === 'start') {
                    $total = isset($data['total']) && is_numeric($data['total']) ? (int) $data['total'] : 0;
                    $progressBar = $this->output->createProgressBar($total);
                    $progressBar->setFormat('  %current%/%max% [%bar%] %percent:3s%% -- %message%');
                    $progressBar->setMessage('Scanning files...');
                    $progressBar->start();
                } elseif ($event === 'advance' && $progressBar) {
                    $rawFile = $data['file'] ?? '';
                    $message = is_string($rawFile) || is_numeric($rawFile) ? (string) $rawFile : '';
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
        }

        try {
            $findings = $scanner->scan($basePath);
            if (! $findings->hasErrors() && $findings->status() === 'complete') {
                $findings->setScannerStatus($scanner->name(), 'complete');
            }
        } catch (\Throwable $exception) {
            $findings = new FindingCollection;
            $findings->addError($basePath, 'Scanner failed with exception: '.$exception->getMessage(), $scanner->name());
            $findings->setScannerStatus($scanner->name(), 'failed');
        } finally {
            if ($scanner instanceof BaseScanner) {
                $scanner->setProgressCallback(null);
            }
        }

        return $findings;
    }
}
