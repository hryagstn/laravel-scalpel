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
     * Create a Finder instance for the given base path with excluded directories.
     */
    protected function createFinder(string $basePath): Finder
    {
        $finder = new Finder();
        $finder->in($basePath)->files()->ignoreDotFiles(false)->ignoreVCS(true);

        foreach ($this->getExcludedPaths() as $excluded) {
            $finder->notPath($excluded);
        }

        return $finder;
    }

    /**
     * Get a path relative to the base path.
     */
    protected function relativePath(string $fullPath, string $basePath): string
    {
        $basePath = rtrim($basePath, '/') . '/';

        if (str_starts_with($fullPath, $basePath)) {
            return substr($fullPath, strlen($basePath));
        }

        return $fullPath;
    }

    abstract public function scan(string $basePath): FindingCollection;

    abstract public function name(): string;
}
