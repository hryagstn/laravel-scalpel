<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Contracts;

use Hryagstn\Scalpel\Data\FindingCollection;

interface ScannerInterface
{
    /**
     * Run the scan against the given base path.
     *
     * @param  string  $basePath  The root directory of the Laravel project to scan.
     * @return FindingCollection Collection of findings from this scanner.
     */
    public function scan(string $basePath): FindingCollection;

    /**
     * Get the human-readable name of this scanner.
     */
    public function name(): string;
}
