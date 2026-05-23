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
     * @param string $basePath The root directory of the Laravel project.
     * @return array{files: int, size: int, created_at: string} Statistics about the created baseline.
     */
    public function createBaseline(string $basePath): array
    {
        $basePath = rtrim($basePath, '/');
        $excludedPaths = $this->getAllExcludedPaths();

        $finder = new Finder();
        $finder->in($basePath)
            ->files()
            ->ignoreDotFiles(false)
            ->ignoreVCS(true);

        $snapshot = [];
        $totalSize = 0;

        foreach ($finder as $file) {
            $relativePath = $this->relativePath($file->getRealPath(), $basePath);

            if ($this->isExcluded($relativePath, $excludedPaths)) {
                continue;
            }

            $fileSize = $file->getSize();
            $totalSize += $fileSize;

            $snapshot[$relativePath] = [
                'hash' => hash_file('sha256', $file->getRealPath()),
                'size' => $fileSize,
                'modified_at' => $file->getMTime(),
            ];
        }

        $baselineData = [
            'created_at' => date('c'),
            'base_path' => $basePath,
            'files' => $snapshot,
        ];

        Storage::put(
            $this->getBaselinePath(),
            json_encode($baselineData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
        );

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
        $findings = new FindingCollection();
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

        $excludedPaths = $this->getAllExcludedPaths();

        // Build current file map
        $currentFiles = $this->buildCurrentFileMap($basePath, $excludedPaths);

        // Check for NEW and MODIFIED files
        foreach ($currentFiles as $relativePath => $fileData) {
            if (! isset($baselineFiles[$relativePath])) {
                // NEW file — not in baseline
                $findings->add(Finding::make(
                    severity: $this->severityForNewOrModified($relativePath),
                    file: $relativePath,
                    line: null,
                    description: 'New file detected that was not in the baseline snapshot.',
                    scanner_name: $this->name(),
                ));
                continue;
            }

            // File exists in both — check if modified
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

        // Check for DELETED files (in baseline but not on disk)
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
     * Build a map of all current files with their hashes.
     *
     * @param string $basePath
     * @param string[] $excludedPaths
     * @return array<string, array{hash: string, size: int, modified_at: int}>
     */
    private function buildCurrentFileMap(string $basePath, array $excludedPaths): array
    {
        $finder = new Finder();
        $finder->in($basePath)
            ->files()
            ->ignoreDotFiles(false)
            ->ignoreVCS(true);

        $files = [];

        foreach ($finder as $file) {
            $relativePath = $this->relativePath($file->getRealPath(), $basePath);

            if ($this->isExcluded($relativePath, $excludedPaths)) {
                continue;
            }

            $files[$relativePath] = [
                'hash' => hash_file('sha256', $file->getRealPath()),
                'size' => $file->getSize(),
                'modified_at' => $file->getMTime(),
            ];
        }

        return $files;
    }

    /**
     * Determine severity for a new or modified file based on its extension.
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
     * Determine severity for a deleted file based on its name/type.
     */
    private function severityForDeleted(string $relativePath): Severity
    {
        $basename = basename($relativePath);

        if ($basename === '.env') {
            return Severity::CRITICAL;
        }

        return Severity::MEDIUM;
    }

    /**
     * Get all paths to exclude (global + baseline-specific).
     *
     * @return string[]
     */
    private function getAllExcludedPaths(): array
    {
        $global = $this->getExcludedPaths();

        /** @var string[] $baselineExcluded */
        $baselineExcluded = config('scalpel.baseline_excluded_paths', []);

        return array_merge($global, $baselineExcluded);
    }
}
