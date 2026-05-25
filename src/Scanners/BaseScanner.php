<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Scanners;

use Hryagstn\Scalpel\Contracts\ScannerInterface;
use Hryagstn\Scalpel\Data\FindingCollection;
use Symfony\Component\Finder\Finder;

abstract class BaseScanner implements ScannerInterface
{
    /**
     * Get the globally excluded paths from config.
     * These paths are excluded from ALL scanners including baseline.
     *
     * @return string[]
     */
    protected function getExcludedPaths(): array
    {
        /** @var string[] $paths */
        $paths = config('scalpel.excluded_paths', []);

        return $paths;
    }

    /**
     * Get paths excluded from content scanners (obfuscated, structural, htaccess).
     * These paths are still monitored by BaselineDiffScanner via hash comparison.
     *
     * @return string[]
     */
    protected function getContentScanExcludedPaths(): array
    {
        /** @var string[] $paths */
        $paths = config('scalpel.content_scan_excluded_paths', []);

        return array_merge($this->getExcludedPaths(), $paths);
    }

    /**
     * Check if a given path should be excluded.
     */
    protected function isExcluded(string $relativePath, array $excludedPaths): bool
    {
        foreach ($excludedPaths as $excluded) {
            $excluded = rtrim($excluded, '/');

            if ($relativePath === $excluded || str_starts_with($relativePath, $excluded . '/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Create a Finder instance for the given base path with excluded paths.
     *
     * Uses Finder::exclude() for directories — this prevents Finder from
     * traversing into excluded directories entirely, which is significantly
     * faster than notPath() which filters after traversal.
     *
     * Uses Finder::notPath() only for file-level exclusions.
     *
     * By default, uses content_scan_excluded_paths (global + content-scan-specific).
     * Pass a custom list to override.
     *
     * @param string   $basePath
     * @param string[] $excludedPaths
     */
    protected function createFinder(string $basePath, ?array $excludedPaths = null): Finder
    {
        $excludedPaths ??= $this->getContentScanExcludedPaths();

        $finder = new Finder();
        $finder->in($basePath)
               ->files()
               ->ignoreDotFiles(false)
               ->ignoreVCS(true);

        $excludedDirs  = [];
        $excludedFiles = [];

        foreach ($excludedPaths as $excluded) {
            $excluded   = rtrim($excluded, '/');
            $fullPath   = rtrim($basePath, '/') . '/' . $excluded;

            if (is_dir($fullPath)) {
                // Use exclude() to prevent traversal into the directory entirely
                $excludedDirs[] = $excluded;
            } else {
                // Use notPath() for file-level exclusions
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
     * Get a path relative to the base path.
     */
    protected function relativePath(string $fullPath, string $basePath): string
    {
        // Normalize separators to forward slash for cross-platform compatibility
        $fullPath = str_replace('\\', '/', $fullPath);
        $basePath = str_replace('\\', '/', rtrim($basePath, '/\\')) . '/';

        if (str_starts_with($fullPath, $basePath)) {
            return substr($fullPath, strlen($basePath));
        }

        return $fullPath;
    }

    abstract public function scan(string $basePath): FindingCollection;

    abstract public function name(): string;
}