<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Scanners;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;

class EnvIntegrityScanner extends BaseScanner
{
    public function name(): string
    {
        return 'Env Integrity';
    }

    public function scan(string $basePath): FindingCollection
    {
        $findings = new FindingCollection();
        $basePath = rtrim($basePath, '/');

        $envPath = $basePath . '/.env';
        $envExamplePath = $basePath . '/.env.example';

        // Check 1: Missing .env file
        if (! file_exists($envPath)) {
            $findings->add(Finding::make(
                severity: Severity::CRITICAL,
                file: '.env',
                line: null,
                description: 'The .env file is missing. The application may not function correctly without environment configuration.',
                scanner_name: $this->name(),
            ));

            // Still check for .env in public/ even if root .env is missing
            $this->checkPublicEnv($basePath, $findings);

            return $findings;
        }

        // Check 2: World-readable permissions
        $this->checkPermissions($envPath, $findings);

        // Check 3: Extra keys in .env not in .env.example
        if (file_exists($envExamplePath)) {
            $this->checkExtraKeys($envPath, $envExamplePath, $findings);
        }

        // Check 4: .env file in public/ directory
        $this->checkPublicEnv($basePath, $findings);

        return $findings;
    }

    /**
     * Check if the .env file has world-readable permissions.
     */
    private function checkPermissions(string $envPath, FindingCollection $findings): void
    {
        // Windows does not support Unix file permission bits;
        // fileperms() always reports files as world-readable there.
        if (PHP_OS_FAMILY === 'Windows') {
            return;
        }

        $perms = @fileperms($envPath);

        if ($perms === false) {
            return;
        }

        // Check world-read bit (octal 0004)
        if ($perms & 0x0004) {
            $findings->add(Finding::make(
                severity: Severity::HIGH,
                file: '.env',
                line: null,
                description: sprintf(
                    'The .env file is world-readable (permissions: %s). This exposes sensitive credentials to all system users.',
                    substr(sprintf('%o', $perms), -4),
                ),
                scanner_name: $this->name(),
            ));
        }
    }

    /**
     * Compare .env keys against .env.example to find extra/unexpected keys.
     */
    private function checkExtraKeys(
        string $envPath,
        string $envExamplePath,
        FindingCollection $findings,
    ): void {
        $envKeys = $this->parseEnvKeys($envPath);
        $exampleKeys = $this->parseEnvKeys($envExamplePath);

        $extraKeys = array_diff($envKeys, $exampleKeys);

        if (empty($extraKeys)) {
            return;
        }

        $keyList = implode(', ', array_slice($extraKeys, 0, 10));
        $remaining = count($extraKeys) > 10 ? sprintf(' (and %d more)', count($extraKeys) - 10) : '';

        $findings->add(Finding::make(
            severity: Severity::MEDIUM,
            file: '.env',
            line: null,
            description: sprintf(
                'Found %d key(s) in .env not present in .env.example: %s%s. These may be injected or misconfigured.',
                count($extraKeys),
                $keyList,
                $remaining,
            ),
            scanner_name: $this->name(),
        ));
    }

    /**
     * Check for .env files inside the public/ directory.
     */
    private function checkPublicEnv(string $basePath, FindingCollection $findings): void
    {
        $publicEnvPath = $basePath . '/public/.env';

        if (file_exists($publicEnvPath)) {
            $findings->add(Finding::make(
                severity: Severity::CRITICAL,
                file: 'public/.env',
                line: null,
                description: 'A .env file exists in the public/ directory. This file is web-accessible and exposes all environment secrets.',
                scanner_name: $this->name(),
            ));
        }
    }

    /**
     * Parse an env file and extract key names.
     *
     * @param string $filePath
     * @return string[]
     */
    private function parseEnvKeys(string $filePath): array
    {
        $contents = @file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if ($contents === false) {
            return [];
        }

        $keys = [];

        foreach ($contents as $line) {
            $line = trim($line);

            // Skip comments and empty lines
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            // Extract key from KEY=VALUE format
            if (preg_match('/^([A-Za-z_][A-Za-z0-9_]*)\s*=/', $line, $matches) === 1) {
                $keys[] = $matches[1];
            }
        }

        return $keys;
    }
}
