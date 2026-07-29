<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Scanners;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\Finder\Finder;

class BaselineDiffScanner extends BaseScanner
{
    public function name(): string
    {
        return 'Baseline Diff';
    }

    /**
     * Create a baseline snapshot of all files in the project.
     *
     * Uses baseline_excluded_paths (in addition to global excluded_paths)
     * but intentionally does NOT exclude content_scan_excluded_paths —
     * vendor/ and other directories skipped by content scanners are still
     * hashed here so that unauthorized modifications can be detected.
     *
     * @param  string  $basePath  The root directory of the Laravel project.
     * @return array{files: int, size: int, created_at: string}
     */
    public function createBaseline(string $basePath): array
    {
        $basePath = rtrim($basePath, '/');
        $excludedPaths = $this->getBaselineExcludedPaths();

        $finder = $this->createBaselineFinder($basePath, $excludedPaths);

        // Convert finder to array to avoid double crawling the filesystem (once for count and once for iteration)
        $filesArray = iterator_to_array($finder, false);
        $totalFiles = count($filesArray);
        $this->notifyProgress('start', ['total' => $totalFiles]);

        // Load existing baseline to reuse unchanged file hashes (Deferred Hashing)
        $oldBaseline = $this->baselineExists() ? $this->loadBaseline() : null;
        $oldFiles = $oldBaseline['files'] ?? [];

        $snapshot = [];
        $totalSize = 0;
        $processed = 0;

        foreach ($filesArray as $file) {
            $realPath = $file->getRealPath();
            if ($realPath === false) {
                continue;
            }

            $relativePath = $this->relativePath($realPath, $basePath);

            if ($this->isExcluded($relativePath, $excludedPaths)) {
                continue;
            }

            $fileSize = $file->getSize();
            $modifiedAt = $file->getMTime();
            if ($fileSize === false || $modifiedAt === false) {
                continue;
            }

            $totalSize += $fileSize;
            $hash = null;

            if (! empty($oldFiles) && isset($oldFiles[$relativePath]) && (bool) config('scalpel.baseline_fast_scan', true)) {
                $oldFile = $oldFiles[$relativePath];
                if ($oldFile['size'] === $fileSize && $oldFile['modified_at'] === $modifiedAt) {
                    $hash = $oldFile['hash'];
                }
            }

            if ($hash === null) {
                $computedHash = hash_file('sha256', $realPath);
                if ($computedHash === false) {
                    continue;
                }
                $hash = $computedHash;
            }

            $snapshot[$relativePath] = [
                'hash' => $hash,
                'size' => $fileSize,
                'modified_at' => $modifiedAt,
            ];

            $processed++;
            $this->notifyProgress('advance', [
                'current' => $processed,
                'total' => $totalFiles,
                'file' => $relativePath,
            ]);
        }

        $this->notifyProgress('finish');

        $baselineData = [
            'created_at' => date('c'),
            'base_path' => $basePath,
            'files' => $snapshot,
        ];

        $json = json_encode($baselineData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json !== false) {
            Storage::put($this->getBaselinePath(), $json);
        }

        return [
            'files' => count($snapshot),
            'size' => $totalSize,
            'created_at' => $baselineData['created_at'],
        ];
    }

    /**
     * Check if a baseline snapshot exists.
     */
    public function baselineExists(): bool
    {
        return Storage::exists($this->getBaselinePath());
    }

    /**
     * Get the configured baseline storage path.
     */
    public function getBaselinePath(): string
    {
        /** @var string $path */
        $path = config('scalpel.baseline_path', 'scalpel/baseline.json');

        return $path;
    }

    public function scan(string $basePath): FindingCollection
    {
        $findings = new FindingCollection;
        $basePath = rtrim($basePath, '/');

        if (! $this->baselineExists()) {
            $findings->add(Finding::make(
                severity: Severity::MEDIUM,
                file: $this->getBaselinePath(),
                line: null,
                description: 'No baseline snapshot found. Run `php artisan scalpel:baseline` to create one.',
                scanner_name: $this->name(),
            ));

            return $findings;
        }

        $baseline = $this->loadBaseline();

        if ($baseline === null) {
            $findings->add(Finding::make(
                severity: Severity::HIGH,
                file: $this->getBaselinePath(),
                line: null,
                description: 'Baseline file is corrupted or unreadable.',
                scanner_name: $this->name(),
            ));

            return $findings;
        }

        /** @var array<string, array{hash: string, size: int, modified_at: int}> $baselineFiles */
        $baselineFiles = $baseline['files'] ?? [];
        $excludedPaths = $this->getBaselineExcludedPaths();
        $currentFiles = $this->buildCurrentFileMap($basePath, $excludedPaths, $baselineFiles);

        // Check for NEW and MODIFIED files
        foreach ($currentFiles as $relativePath => $fileData) {
            if (! isset($baselineFiles[$relativePath])) {
                $findings->add(Finding::make(
                    severity: $this->severityForNewOrModified($relativePath),
                    file: $relativePath,
                    line: null,
                    description: 'New file detected that was not in the baseline snapshot.',
                    scanner_name: $this->name(),
                ));

                continue;
            }

            if ($fileData['hash'] !== $baselineFiles[$relativePath]['hash']) {
                $findings->add(Finding::make(
                    severity: $this->severityForNewOrModified($relativePath),
                    file: $relativePath,
                    line: null,
                    description: sprintf(
                        'File has been modified since baseline (hash mismatch). Size: %d → %d bytes.',
                        $baselineFiles[$relativePath]['size'],
                        $fileData['size'],
                    ),
                    scanner_name: $this->name(),
                ));
            }
        }

        // Check for DELETED files
        foreach ($baselineFiles as $relativePath => $baselineData) {
            if (! isset($currentFiles[$relativePath])) {
                $findings->add(Finding::make(
                    severity: $this->severityForDeleted($relativePath),
                    file: $relativePath,
                    line: null,
                    description: 'File has been deleted since baseline snapshot.',
                    scanner_name: $this->name(),
                ));
            }
        }

        return $findings;
    }

    /**
     * Get all paths excluded from baseline operations.
     *
     * This merges global excluded_paths with baseline_excluded_paths.
     * Intentionally excludes content_scan_excluded_paths so that vendor/
     * and similar directories are still monitored via hash comparison.
     *
     * @return string[]
     */
    public function getBaselineExcludedPaths(): array
    {
        $global = $this->getExcludedPaths();

        /** @var string[] $baselineExcluded */
        $baselineExcluded = config('scalpel.baseline_excluded_paths', []);

        return array_unique(array_merge($global, $baselineExcluded));
    }

    /**
     * Create a Finder instance optimised for baseline operations.
     *
     * Applies the same directory-vs-file exclusion logic as BaseScanner::createFinder()
     * but uses baseline-specific excluded paths instead of content scan paths.
     *
     * @param  string[]  $excludedPaths
     */
    private function createBaselineFinder(string $basePath, array $excludedPaths): Finder
    {
        $finder = new Finder;
        $finder->in($basePath)
            ->files()
            ->ignoreDotFiles(false)
            ->ignoreVCS(true);

        $excludedDirs = [];
        $excludedFiles = [];

        foreach ($excludedPaths as $excluded) {
            $excluded = rtrim($excluded, '/');
            $fullPath = rtrim($basePath, '/').'/'.$excluded;

            if (is_dir($fullPath)) {
                $excludedDirs[] = $excluded;
            } else {
                $excludedFiles[] = $excluded;
            }
        }

        if (! empty($excludedDirs)) {
            $finder->exclude($excludedDirs);
        }

        foreach ($excludedFiles as $file) {
            $finder->notPath($file);
        }

        return $finder;
    }

    /**
     * Load and decode the baseline snapshot.
     *
     * @return array<string, mixed>|null
     */
    private function loadBaseline(): ?array
    {
        $contents = Storage::get($this->getBaselinePath());

        if ($contents === null) {
            return null;
        }

        /** @var array<string, mixed>|null $data */
        $data = json_decode($contents, true);

        if (! is_array($data)) {
            return null;
        }

        return $data;
    }

    /**
     * Build a map of current files with their hashes.
     *
     * @param  string[]  $excludedPaths
     * @param  array<string, array{hash: string, size: int, modified_at: int}>|null  $baselineFiles
     * @return array<string, array{hash: string, size: int, modified_at: int}>
     */
    private function buildCurrentFileMap(string $basePath, array $excludedPaths, ?array $baselineFiles = null): array
    {
        $finder = $this->createBaselineFinder($basePath, $excludedPaths);

        // Convert finder to array to avoid double crawling the filesystem (once for count and once for iteration)
        $filesArray = iterator_to_array($finder, false);
        $totalFiles = count($filesArray);
        $this->notifyProgress('start', ['total' => $totalFiles]);

        $files = [];
        $processed = 0;

        foreach ($filesArray as $file) {
            $realPath = $file->getRealPath();
            if ($realPath === false) {
                continue;
            }

            $relativePath = $this->relativePath($realPath, $basePath);

            if ($this->isExcluded($relativePath, $excludedPaths)) {
                continue;
            }

            $fileSize = $file->getSize();
            $modifiedAt = $file->getMTime();
            if ($fileSize === false || $modifiedAt === false) {
                continue;
            }

            $hash = null;

            if ($baselineFiles !== null && isset($baselineFiles[$relativePath]) && (bool) config('scalpel.baseline_fast_scan', true)) {
                $baselineFile = $baselineFiles[$relativePath];
                if ($baselineFile['size'] === $fileSize && $baselineFile['modified_at'] === $modifiedAt) {
                    $hash = $baselineFile['hash'];
                }
            }

            if ($hash === null) {
                $computedHash = hash_file('sha256', $realPath);
                if ($computedHash === false) {
                    continue;
                }
                $hash = $computedHash;
            }

            $files[$relativePath] = [
                'hash' => $hash,
                'size' => $fileSize,
                'modified_at' => $modifiedAt,
            ];

            $processed++;
            $this->notifyProgress('advance', [
                'current' => $processed,
                'total' => $totalFiles,
                'file' => $relativePath,
            ]);
        }

        $this->notifyProgress('finish');

        return $files;
    }

    /**
     * Determine severity for a new or modified file.
     */
    private function severityForNewOrModified(string $relativePath): Severity
    {
        $extension = strtolower(pathinfo($relativePath, PATHINFO_EXTENSION));

        if (in_array($extension, ['php', 'htaccess'], true) || basename($relativePath) === '.htaccess') {
            return Severity::HIGH;
        }

        return Severity::MEDIUM;
    }

    /**
     * Determine severity for a deleted file.
     */
    private function severityForDeleted(string $relativePath): Severity
    {
        if (basename($relativePath) === '.env') {
            return Severity::CRITICAL;
        }

        return Severity::MEDIUM;
    }
}
