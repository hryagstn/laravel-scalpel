<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel;

use Hryagstn\Scalpel\Contracts\ScannerInterface;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Hryagstn\Scalpel\Scanners\EnvIntegrityScanner;
use Hryagstn\Scalpel\Scanners\HtaccessScanner;
use Hryagstn\Scalpel\Scanners\ObfuscatedCodeScanner;
use Hryagstn\Scalpel\Scanners\StructuralAnomalyScanner;

final class Scalpel
{
    /** @var ScannerInterface[] */
    private array $scanners;

    /**
     * @param ScannerInterface[] $scanners
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
        $collection = new FindingCollection();

        foreach ($this->scanners as $scanner) {
            $collection->merge($scanner->scan($basePath));
        }

        return $collection;
    }

    /**
     * Run only the specified scanners (by name) against the given base path.
     *
     * @param string[] $scannerNames
     */
    public function runOnly(string $basePath, array $scannerNames): FindingCollection
    {
        $collection = new FindingCollection();

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
            new StructuralAnomalyScanner(),
            new ObfuscatedCodeScanner(),
            new HtaccessScanner(),
            new BaselineDiffScanner(),
            new EnvIntegrityScanner(),
        ];
    }
}
