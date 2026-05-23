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

    /**
     * @param Finding[] $findings
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
     * Merge another FindingCollection into this one.
     */
    public function merge(self $other): self
    {
        foreach ($other->findings as $finding) {
            $this->findings[] = $finding;
        }

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

        return new self(array_values($filtered));
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
            $groups[$finding->scanner_name][] = $finding;
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
     * @return array<int, array<string, mixed>>
     */
    public function toArray(): array
    {
        return array_map(fn (Finding $f) => $f->toArray(), $this->findings);
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
