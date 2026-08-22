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
    /**
     * Current baseline snapshot schema version. Bump when the structure of
     * the baseline JSON changes in a way that requires migration.
     */
    private const BASELINE_SCHEMA_VERSION = 1;

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
        $oldFiles = is_array($oldBaseline) ? ($oldBaseline['files'] ?? []) : [];

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

            // Skip files whose metadata cannot be read
            if ($fileSize === false || $modifiedAt === false) {
                continue;
            }

            $hash = null;

            if (is_array($oldFiles) && $oldFiles !== [] && isset($oldFiles[$relativePath]) && config('scalpel.baseline_fast_scan', true)) {
                $oldFile = $oldFiles[$relativePath];

                $oldSize = is_array($oldFile) ? ($oldFile['size'] ?? null) : null;
                $oldMtime = is_array($oldFile) ? ($oldFile['modified_at'] ?? null) : null;
                $oldHash = is_array($oldFile) ? ($oldFile['hash'] ?? null) : null;

                if ($oldSize === $fileSize && $oldMtime === $modifiedAt && is_string($oldHash)) {
                    $hash = $oldHash;
                }
            }

            if ($hash === null) {
                $hash = hash_file('sha256', $realPath);

                // Skip unreadable files — a hash is required for diffing
                if ($hash === false) {
                    continue;
                }
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
            'schema_version' => self::BASELINE_SCHEMA_VERSION,
            'created_at' => date('c'),
            'base_path' => $basePath,
            'files' => $snapshot,
        ];

        $baselineJson = json_encode($baselineData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($baselineJson === false) {
            throw new \RuntimeException('Unable to encode baseline snapshot to JSON.');
        }

        // HMAC-sign the baseline so tampering (e.g. an attacker regenerating
        // it to conceal a planted backdoor) can be detected by scalpel:diff.
        $signingKey = $this->signingKey();

        if ($signingKey !== null) {
            $baselineData['signature'] = hash_hmac('sha256', $baselineJson, $signingKey);
            $baselineJson = json_encode($baselineData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

            if ($baselineJson === false) {
                throw new \RuntimeException('Unable to encode signed baseline snapshot to JSON.');
            }
        }

        Storage::put($this->getBaselinePath(), $baselineJson);

        return [
            'files' => count($snapshot),
            'size' => $totalSize,
            'created_at' => $baselineData['created_at'],
            'signed' => $signingKey !== null,
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
                scannerName: $this->name(),
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
                scannerName: $this->name(),
            ));

            return $findings;
        }

        // Verify the baseline HMAC signature before trusting its contents.
        $signatureError = $this->validateBaselineSignature($baseline);

        if ($signatureError !== null) {
            $findings->add(Finding::make(
                severity: Severity::CRITICAL,
                file: $this->getBaselinePath(),
                line: null,
                description: $signatureError,
                scannerName: $this->name(),
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
                    scannerName: $this->name(),
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
                    scannerName: $this->name(),
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
                    scannerName: $this->name(),
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
     * Get the HMAC signing key, or null when output signing is disabled
     * or no usable key is configured.
     */
    private function signingKey(): ?string
    {
        if (! config('scalpel.signing.enabled', false)) {
            return null;
        }

        $key = config('scalpel.signing.key');

        if (! is_string($key) || $key === '') {
            return null;
        }

        return $key;
    }

    /**
     * Validate the baseline snapshot's HMAC signature.
     *
     * Returns null when the signature is valid (or signing is disabled),
     * or an error description when the baseline should not be trusted.
     *
     * @param  array<string, mixed>  $baseline
     */
    private function validateBaselineSignature(array $baseline): ?string
    {
        $signingKey = $this->signingKey();

        if ($signingKey === null) {
            return null;
        }

        if (! isset($baseline['signature']) || ! is_string($baseline['signature'])) {
            return 'Baseline snapshot is not signed, but output signing is enabled. '
                .'Re-create the baseline with `php artisan scalpel:baseline --force`.';
        }

        $signature = $baseline['signature'];
        unset($baseline['signature']);

        $canonicalJson = json_encode($baseline, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($canonicalJson === false) {
            return 'Baseline snapshot could not be re-encoded for signature verification.';
        }

        if (! hash_equals(hash_hmac('sha256', $canonicalJson, $signingKey), $signature)) {
            return 'Baseline signature verification FAILED — the baseline may have been '
                .'regenerated to conceal intrusion evidence. Investigate immediately.';
        }

        return null;
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

            // Skip files whose metadata cannot be read
            if ($fileSize === false || $modifiedAt === false) {
                continue;
            }

            $hash = null;

            if ($baselineFiles !== null && isset($baselineFiles[$relativePath]) && config('scalpel.baseline_fast_scan', true)) {
                $baselineFile = $baselineFiles[$relativePath];

                if ($baselineFile['size'] === $fileSize && $baselineFile['modified_at'] === $modifiedAt) {
                    $hash = $baselineFile['hash'];
                }
            }

            if ($hash === null) {
                $hash = hash_file('sha256', $realPath);

                // Skip unreadable files — a hash is required for diffing
                if ($hash === false) {
                    continue;
                }
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
        $filename = basename($relativePath);

        if ($extension === 'php' || $extension === 'htaccess' || in_array($extension, $this->getSuspiciousPhpExtensions(), true)) {
            return Severity::HIGH;
        }

        if ($filename === '.htaccess' || $filename === '.user.ini') {
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
