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
        if ($format !== 'json') {
            $this->info("  ▸ Running scanner: {$scanner->name()}");
        }

        $hasProgress = $format !== 'json' && $scanner instanceof BaseScanner;
        if ($hasProgress) {
            $progressBar = null;
            $scanner->setProgressCallback(function (string $event, array $data) use (&$progressBar) {
                if ($event === 'start') {
                    $progressBar = $this->output->createProgressBar($data['total']);
                    $progressBar->setFormat('  %current%/%max% [%bar%] %percent:3s%% -- %message%');
                    $progressBar->setMessage('Scanning files...');
                    $progressBar->start();
                } elseif ($event === 'advance' && $progressBar) {
                    $message = (string) ($data['file'] ?? '');
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

        $findings = $scanner->scan($basePath);

        if ($hasProgress) {
            $scanner->setProgressCallback(null);
        }

        return $findings;
    }
}
