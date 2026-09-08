<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Data;

use ArrayIterator;
use Countable;
use IteratorAggregate;
use Traversable;

/**
 * @implements IteratorAggregate<int, Finding>
 */
final class FindingCollection implements Countable, IteratorAggregate
{
    /** @var Finding[] */
    private array $findings = [];

    /** @var array<int, array{file: string, error: string, scanner: string, is_directory?: bool}> */
    private array $errors = [];

    /** @var array<string, 'complete'|'partial'|'failed'> */
    private array $scannerStatuses = [];

    /** @var 'complete'|'partial'|'failed'|null */
    private ?string $explicitStatus = null;

    private int $scannedFilesCount = 0;

    private int $skippedFilesCount = 0;

    private int $skippedDirectoriesCount = 0;

    /**
     * @param  Finding[]  $findings
     */
    public function __construct(array $findings = [])
    {
        foreach ($findings as $finding) {
            $this->add($finding);
        }
    }

    /**
     * Add a finding to the collection.
     */
    public function add(Finding $finding): self
    {
        $this->findings[] = $finding;

        return $this;
    }

    /**
     * Immutable-style alias to add a finding to the collection.
     */
    public function withFinding(Finding $finding): self
    {
        $clone = clone $this;
        $clone->findings[] = $finding;

        return $clone;
    }

    /**
     * Record an operational error encountered during scanning (e.g. unreadable file/permission denied).
     */
    public function addError(string $file, string $error, string $scanner, bool $isDirectory = false): self
    {
        $this->errors[] = [
            'file' => $file,
            'error' => $error,
            'scanner' => $scanner,
            'is_directory' => $isDirectory,
        ];

        if ($isDirectory) {
            $this->skippedDirectoriesCount++;
        } else {
            $this->skippedFilesCount++;
        }

        if (! isset($this->scannerStatuses[$scanner]) || $this->scannerStatuses[$scanner] !== 'failed') {
            $this->scannerStatuses[$scanner] = 'partial';
        }

        return $this;
    }

    /**
     * Record an unreadable directory encountered during scanning.
     */
    public function addDirectoryError(string $directory, string $error, string $scanner): self
    {
        return $this->addError($directory, $error, $scanner, isDirectory: true);
    }

    /**
     * Get all operational errors.
     *
     * @return array<int, array{file: string, error: string, scanner: string, is_directory?: bool}>
     */
    public function errors(): array
    {
        return $this->errors;
    }

    /**
     * Check if the collection has any operational errors.
     */
    public function hasErrors(): bool
    {
        return count($this->errors) > 0;
    }

    /**
     * Record the completion status of a specific scanner.
     *
     * @param  'complete'|'partial'|'failed'  $status
     */
    public function setScannerStatus(string $scanner, string $status): self
    {
        $this->scannerStatuses[$scanner] = $status;

        return $this;
    }

    /**
     * Mark the entire collection status as complete.
     */
    public function markComplete(): self
    {
        $this->explicitStatus = 'complete';

        return $this;
    }

    /**
     * Mark the entire collection status as failed.
     */
    public function markFailed(): self
    {
        $this->explicitStatus = 'failed';

        return $this;
    }

    /**
     * Mark the entire collection status as partial.
     */
    public function markPartial(): self
    {
        $this->explicitStatus = 'partial';

        return $this;
    }

    /**
     * Combine two completion statuses commutatively into a single status.
     *
     * @param  'complete'|'failed'|'partial'|null  $a
     * @param  'complete'|'failed'|'partial'|null  $b
     * @return 'complete'|'failed'|'partial'|null
     */
    public static function combineStatuses(?string $a, ?string $b): ?string
    {
        if ($a === null) {
            return $b;
        }

        if ($b === null) {
            return $a;
        }

        if ($a === 'partial' || $b === 'partial') {
            return 'partial';
        }

        if ($a === 'failed' && $b === 'failed') {
            return 'failed';
        }

        if ($a === 'complete' && $b === 'complete') {
            return 'complete';
        }

        // One is failed and the other is complete -> partial success
        return 'partial';
    }

    /**
     * Get the aggregated scan completion status: 'complete', 'partial', or 'failed'.
     */
    public function status(): string
    {
        $hasIncompleteness = $this->hasErrors()
            || $this->skippedFilesCount > 0
            || $this->skippedDirectoriesCount > 0;

        $resolved = $this->explicitStatus;

        if ($this->scannerStatuses !== []) {
            $scannerResolved = null;
            foreach ($this->scannerStatuses as $status) {
                $scannerResolved = self::combineStatuses($scannerResolved, $status);
            }

            $resolved = self::combineStatuses($resolved, $scannerResolved);
        }

        if ($resolved === null) {
            $resolved = $hasIncompleteness ? 'partial' : 'complete';
        } elseif ($resolved === 'complete' && $hasIncompleteness) {
            $resolved = 'partial';
        } elseif ($resolved === 'failed' && $this->scannedFilesCount > 0) {
            $resolved = 'partial';
        }

        return $resolved;
    }

    /**
     * Increment the count of inspected files.
     */
    public function incrementScannedFiles(int $count = 1): self
    {
        $this->scannedFilesCount += $count;

        return $this;
    }

    /**
     * Increment the count of skipped files.
     */
    public function incrementSkippedFiles(int $count = 1): self
    {
        $this->skippedFilesCount += $count;

        return $this;
    }

    /**
     * Get the count of successfully scanned/inspected files.
     */
    public function scannedFilesCount(): int
    {
        return $this->scannedFilesCount;
    }

    /**
     * Get the count of skipped/unreadable files.
     */
    public function skippedFilesCount(): int
    {
        return $this->skippedFilesCount;
    }

    /**
     * Get the count of unreadable directories.
     */
    public function skippedDirectoriesCount(): int
    {
        return $this->skippedDirectoriesCount;
    }

    /**
     * Merge another FindingCollection into this one.
     */
    public function merge(self $other): self
    {
        foreach ($other->findings as $finding) {
            $this->findings[] = $finding;
        }

        foreach ($other->errors as $error) {
            $this->errors[] = $error;
        }

        $this->scannedFilesCount += $other->scannedFilesCount;
        $this->skippedFilesCount += $other->skippedFilesCount;
        $this->skippedDirectoriesCount += $other->skippedDirectoriesCount;

        foreach ($other->scannerStatuses as $scanner => $status) {
            $combined = isset($this->scannerStatuses[$scanner])
                ? self::combineStatuses($this->scannerStatuses[$scanner], $status)
                : $status;

            if ($combined !== null) {
                $this->scannerStatuses[$scanner] = $combined;
            }
        }

        $this->explicitStatus = self::combineStatuses($this->explicitStatus, $other->explicitStatus);

        return $this;
    }

    /**
     * Filter findings by minimum severity threshold.
     */
    public function filterBySeverity(Severity $threshold): self
    {
        $filtered = array_filter(
            $this->findings,
            fn (Finding $f) => $f->severity->meetsThreshold($threshold),
        );

        $clone = clone $this;
        $clone->findings = array_values($filtered);

        return $clone;
    }

    /**
     * Group findings by severity level.
     *
     * @return array<string, Finding[]>
     */
    public function groupBySeverity(): array
    {
        $groups = [];

        foreach (Severity::cases() as $severity) {
            $groups[$severity->value] = [];
        }

        foreach ($this->findings as $finding) {
            $groups[$finding->severity->value][] = $finding;
        }

        // Remove empty groups
        return array_filter($groups, fn (array $items) => count($items) > 0);
    }

    /**
     * Group findings by scanner name.
     *
     * @return array<string, Finding[]>
     */
    public function groupByScanner(): array
    {
        $groups = [];

        foreach ($this->findings as $finding) {
            $groups[$finding->scannerName][] = $finding;
        }

        return $groups;
    }

    /**
     * Check if the collection contains any findings at the given severity or above.
     */
    public function hasSeverity(Severity $severity): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->severity->meetsThreshold($severity)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the collection has any CRITICAL or HIGH findings.
     */
    public function hasCriticalOrHigh(): bool
    {
        return $this->hasSeverity(Severity::HIGH);
    }

    /**
     * Get all findings as an array.
     *
     * @return Finding[]
     */
    public function all(): array
    {
        return $this->findings;
    }

    /**
     * Check if the collection is empty.
     */
    public function isEmpty(): bool
    {
        return count($this->findings) === 0;
    }

    /**
     * Get the count of findings.
     */
    public function count(): int
    {
        return count($this->findings);
    }

    /**
     * Convert the collection to an array of associative arrays.
     *
     * @return list<array<string, mixed>>
     */
    public function toArray(): array
    {
        return array_values(array_map(fn (Finding $f) => $f->toArray(), $this->findings));
    }

    /**
     * Get an iterator for the findings.
     *
     * @return Traversable<int, Finding>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->findings);
    }
}
