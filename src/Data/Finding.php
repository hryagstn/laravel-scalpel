<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Data;

final class Finding
{
    public readonly string $scannerName;

    /**
     * Backward-compatibility alias for $scannerName.
     */
    public readonly string $scanner_name;

    public function __construct(
        public readonly Severity $severity,
        public readonly string $file,
        public readonly ?int $line,
        public readonly string $description,
        string $scannerName = '',
        string $scanner_name = '',
    ) {
        $name = $scannerName !== '' ? $scannerName : $scanner_name;

        $this->scannerName = $name;
        $this->scanner_name = $name;
    }

    /**
     * Create a new Finding instance.
     *
     * Supports both $scannerName (camelCase) and $scanner_name (snake_case)
     * for backward compatibility with PHP 8 named arguments.
     */
    public static function make(
        Severity $severity,
        string $file,
        ?int $line,
        string $description,
        string $scannerName = '',
        string $scanner_name = '',
    ): self {
        $name = $scannerName !== '' ? $scannerName : $scanner_name;

        return new self($severity, $file, $line, $description, $name);
    }

    /**
     * Convert the finding to an associative array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'severity' => $this->severity->value,
            'file' => $this->file,
            'line' => $this->line,
            'description' => $this->description,
            'scanner' => $this->scannerName,
        ];
    }
}
