<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Data;

final class Finding
{
    public function __construct(
        public readonly Severity $severity,
        public readonly string $file,
        public readonly ?int $line,
        public readonly string $description,
        public readonly string $scannerName,
    ) {}

    /**
     * Create a new Finding instance.
     */
    public static function make(
        Severity $severity,
        string $file,
        ?int $line,
        string $description,
        string $scannerName,
    ): self {
        return new self($severity, $file, $line, $description, $scannerName);
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
