<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Data;

enum Severity: string
{
    case CRITICAL = 'CRITICAL';
    case HIGH = 'HIGH';
    case MEDIUM = 'MEDIUM';
    case LOW = 'LOW';

    /**
     * Get the numeric weight for sorting (higher = more severe).
     */
    public function weight(): int
    {
        return match ($this) {
            self::CRITICAL => 4,
            self::HIGH => 3,
            self::MEDIUM => 2,
            self::LOW => 1,
        };
    }

    /**
     * Check if this severity meets or exceeds the given threshold.
     */
    public function meetsThreshold(self $threshold): bool
    {
        return $this->weight() >= $threshold->weight();
    }

    /**
     * Get the display color for console output.
     */
    public function color(): string
    {
        return match ($this) {
            self::CRITICAL => 'red',
            self::HIGH => 'yellow',
            self::MEDIUM => 'cyan',
            self::LOW => 'gray',
        };
    }

    /**
     * Get the badge string for console output.
     */
    public function badge(): string
    {
        return match ($this) {
            self::CRITICAL => '🔴 CRITICAL',
            self::HIGH => '🟠 HIGH',
            self::MEDIUM => '🟡 MEDIUM',
            self::LOW => '⚪ LOW',
        };
    }
}
