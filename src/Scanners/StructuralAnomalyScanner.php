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

    /**
     * Laravel framework directories that always contain legitimate PHP files.
     * These are excluded regardless of user configuration to prevent false positives.
     *
     * @var string[]
     */
    private const FRAMEWORK_ALLOWED_DIRECTORIES = [
        'storage/framework/views',
        'storage/framework/cache',
    ];

    public function scan(string $basePath): FindingCollection
    {
        $findings = new FindingCollection;
        $basePath = rtrim($basePath, '/');

        /** @var string[] $nonPhpZones */
        $nonPhpZones = config('scalpel.non_php_zones', []);

        /** @var string[] $allowedFiles */
        $allowedFiles = config('scalpel.structural_allowed_files', []);

        /** @var string[] $configAllowedDirectories */
        $configAllowedDirectories = config('scalpel.structural_allowed_directories', []);

        $phpExtensions = $this->getSuspiciousPhpExtensions();

        // Merge user-configured allowed directories with built-in framework exclusions
        $allowedDirectories = array_unique(array_merge($configAllowedDirectories, self::FRAMEWORK_ALLOWED_DIRECTORIES));

        $excludedPaths = $this->getExcludedPaths();

        foreach ($nonPhpZones as $zone) {
            $zonePath = $basePath.'/'.$zone;

            if (! is_dir($zonePath)) {
                continue;
            }

            $finder = new Finder;

            // Match plain PHP files (*.php) as well as double-extension
            // smuggles (*.php.jpg)
            $extensionPattern = implode('|', array_map(static fn (string $extension): string => preg_quote($extension, '/'), $phpExtensions));

            $finder->in($zonePath)
                ->files()
                ->ignoreDotFiles(false)
                ->ignoreVCS(true)
                ->name('/\.(?:'.$extensionPattern.')(?:\..*)?$/i');

            foreach ($finder as $file) {
                $realPath = $file->getRealPath();
                if ($realPath === false) {
                    continue;
                }
                $relativePath = $this->relativePath($realPath, $basePath);

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

                $filename = basename($relativePath);
                $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

                // Double-extension webshell (e.g. shell.php.jpg)
                if (! in_array($extension, $phpExtensions, true)) {
                    $findings->add(Finding::make(
                        severity: Severity::HIGH,
                        file: $relativePath,
                        line: null,
                        description: "File '{$filename}' embeds a PHP extension under a different final extension — a common upload-filter bypass for web shells.",
                        scannerName: $this->name(),
                    ));

                    continue;
                }

                $findings->add(Finding::make(
                    severity: Severity::HIGH,
                    file: $relativePath,
                    line: null,
                    description: "PHP file ('.{$extension}') found in non-PHP zone '{$zone}'. This may indicate a web shell or backdoor.",
                    scannerName: $this->name(),
                ));
            }
        }

        return $findings;
    }

    /**
     * Check if a file path matches any of the explicitly allowed files.
     *
     * @param  string[]  $allowedFiles
     */
    private function isAllowedFile(string $relativePath, array $allowedFiles): bool
    {
        return in_array($relativePath, $allowedFiles, true);
    }

    /**
     * Check if a file resides within an allowed directory.
     *
     * @param  string[]  $allowedDirectories
     */
    private function isInAllowedDirectory(string $relativePath, array $allowedDirectories): bool
    {
        foreach ($allowedDirectories as $directory) {
            $directory = rtrim($directory, '/');

            if (str_starts_with($relativePath, $directory.'/')) {
                return true;
            }
        }

        return false;
    }
}
