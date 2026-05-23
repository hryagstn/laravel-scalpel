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
        public readonly string $scanner_name,
    ) {}

    /**
     * Create a new Finding instance.
     */
    public static function make(
        Severity $severity,
        string $file,
        ?int $line,
        string $description,
        string $scanner_name,
    ): self {
        return new self($severity, $file, $line, $description, $scanner_name);
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
            'scanner' => $this->scanner_name,
        ];
    }
}
