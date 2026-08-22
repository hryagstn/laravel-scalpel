<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel;

use Composer\InstalledVersions;
use Hryagstn\Scalpel\Contracts\ScannerInterface;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Hryagstn\Scalpel\Scanners\EnvIntegrityScanner;
use Hryagstn\Scalpel\Scanners\HtaccessScanner;
use Hryagstn\Scalpel\Scanners\ObfuscatedCodeScanner;
use Hryagstn\Scalpel\Scanners\StructuralAnomalyScanner;

final class Scalpel
{
    /**
     * CLI aliases mapped to their scanner class.
     *
     * This is the single source of truth for scanner aliases. Scanner names
     * are resolved at runtime from the scanner instance's name() method, so
     * this map can never drift out of sync with the scanners themselves.
     *
     * @var array<string, class-string<ScannerInterface>>
     */
    public const SCANNER_ALIASES = [
        'structural' => StructuralAnomalyScanner::class,
        'obfuscated' => ObfuscatedCodeScanner::class,
        'htaccess' => HtaccessScanner::class,
        'baseline' => BaselineDiffScanner::class,
        'env' => EnvIntegrityScanner::class,
    ];

    /** @var ScannerInterface[] */
    private array $scanners;

    /**
     * @param  ScannerInterface[]  $scanners
     */
    public function __construct(array $scanners)
    {
        $this->scanners = $scanners;
    }

    /**
     * Run all registered scanners against the given base path.
     */
    public function runAll(string $basePath): FindingCollection
    {
        $collection = new FindingCollection;

        foreach ($this->scanners as $scanner) {
            $collection->merge($scanner->scan($basePath));
        }

        return $collection;
    }

    /**
     * Run only the specified scanners (by name) against the given base path.
     *
     * @param  string[]  $scannerNames
     */
    public function runOnly(string $basePath, array $scannerNames): FindingCollection
    {
        $collection = new FindingCollection;

        foreach ($this->scanners as $scanner) {
            if (in_array($scanner->name(), $scannerNames, true)) {
                $collection->merge($scanner->scan($basePath));
            }
        }

        return $collection;
    }

    /**
     * Get all registered scanner instances.
     *
     * @return ScannerInterface[]
     */
    public function getScanners(): array
    {
        return $this->scanners;
    }

    /**
     * Get a scanner instance by its name.
     */
    public function getScanner(string $name): ?ScannerInterface
    {
        foreach ($this->scanners as $scanner) {
            if ($scanner->name() === $name) {
                return $scanner;
            }
        }

        return null;
    }

    /**
     * Get the default set of all available scanners.
     *
     * @return ScannerInterface[]
     */
    public static function getDefaultScanners(): array
    {
        return [
            new StructuralAnomalyScanner,
            new ObfuscatedCodeScanner,
            new HtaccessScanner,
            new BaselineDiffScanner,
            new EnvIntegrityScanner,
        ];
    }

    /**
     * Get the dynamic version of the package.
     */
    public static function version(): string
    {
        try {
            if (class_exists(InstalledVersions::class)) {
                return InstalledVersions::getPrettyVersion('hryagstn/laravel-scalpel') ?? '1.0.0-dev';
            }
        } catch (\OutOfBoundsException) {
            // Package is not installed via composer in the current project
        }

        $composerPath = dirname(__DIR__).'/composer.json';
        if (file_exists($composerPath)) {
            $content = file_get_contents($composerPath);
            if ($content !== false) {
                $data = json_decode($content, true);
                if (is_array($data) && isset($data['version']) && is_string($data['version'])) {
                    return $data['version'];
                }
            }
        }

        return '1.0.0-dev';
    }
}
