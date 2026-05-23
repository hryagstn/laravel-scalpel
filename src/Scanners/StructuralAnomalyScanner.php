<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Scanners;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;
use Symfony\Component\Finder\Finder;

class StructuralAnomalyScanner extends BaseScanner
{
    public function name(): string
    {
        return 'Structural Anomaly';
    }

    public function scan(string $basePath): FindingCollection
    {
        $findings = new FindingCollection();
        $basePath = rtrim($basePath, '/');

        /** @var string[] $nonPhpZones */
        $nonPhpZones = config('scalpel.non_php_zones', []);

        /** @var string[] $allowedFiles */
        $allowedFiles = config('scalpel.structural_allowed_files', []);

        /** @var string[] $allowedDirectories */
        $allowedDirectories = config('scalpel.structural_allowed_directories', []);

        $excludedPaths = $this->getExcludedPaths();

        foreach ($nonPhpZones as $zone) {
            $zonePath = $basePath . '/' . $zone;

            if (! is_dir($zonePath)) {
                continue;
            }

            $finder = new Finder();
            $finder->in($zonePath)
                ->files()
                ->ignoreDotFiles(false)
                ->ignoreVCS(true)
                ->name('*.php');

            foreach ($finder as $file) {
                $relativePath = $this->relativePath($file->getRealPath(), $basePath);

                // Skip globally excluded paths
                if ($this->isExcluded($relativePath, $excludedPaths)) {
                    continue;
                }

                // Skip explicitly allowed files
                if ($this->isAllowedFile($relativePath, $allowedFiles)) {
                    continue;
                }

                // Skip files in allowed directories
                if ($this->isInAllowedDirectory($relativePath, $allowedDirectories)) {
                    continue;
                }

                $findings->add(Finding::make(
                    severity: Severity::HIGH,
                    file: $relativePath,
                    line: null,
                    description: "PHP file found in non-PHP zone '{$zone}'. This may indicate a web shell or backdoor.",
                    scanner_name: $this->name(),
                ));
            }
        }

        return $findings;
    }

    /**
     * Check if a file path matches any of the explicitly allowed files.
     *
     * @param string $relativePath
     * @param string[] $allowedFiles
     * @return bool
     */
    private function isAllowedFile(string $relativePath, array $allowedFiles): bool
    {
        return in_array($relativePath, $allowedFiles, true);
    }

    /**
     * Check if a file resides within an allowed directory.
     *
     * @param string $relativePath
     * @param string[] $allowedDirectories
     * @return bool
     */
    private function isInAllowedDirectory(string $relativePath, array $allowedDirectories): bool
    {
        foreach ($allowedDirectories as $directory) {
            $directory = rtrim($directory, '/');

            if (str_starts_with($relativePath, $directory . '/')) {
                return true;
            }
        }

        return false;
    }
}
