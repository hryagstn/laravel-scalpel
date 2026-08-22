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
        $findings = new FindingCollection;
        $basePath = rtrim($basePath, '/');

        $envPath = $basePath.'/.env';
        $envExamplePath = $basePath.'/.env.example';

        // Check 1: Missing .env file
        if (! file_exists($envPath)) {
            $findings->add(Finding::make(
                severity: Severity::CRITICAL,
                file: '.env',
                line: null,
                description: 'The .env file is missing. The application may not function correctly without environment configuration.',
                scannerName: $this->name(),
            ));

            // Still check for .env in public/ even if root .env is missing
            $this->checkPublicEnv($basePath, $findings);

            return $findings;
        }

        // Check 2: Empty or unreadable .env file (truncation is a common
        // post-compromise tactic to silence error reporting)
        $envSize = @filesize($envPath);

        if ($envSize === 0) {
            $findings->add(Finding::make(
                severity: Severity::HIGH,
                file: '.env',
                line: null,
                description: 'The .env file is empty. It may have been truncated to disable error reporting or cover tracks.',
                scannerName: $this->name(),
            ));

            $this->checkPublicEnv($basePath, $findings);

            return $findings;
        }

        if (! is_readable($envPath)) {
            $findings->add(Finding::make(
                severity: Severity::HIGH,
                file: '.env',
                line: null,
                description: 'The .env file exists but is not readable by the current process.',
                scannerName: $this->name(),
            ));
        }

        // Check 3: World-readable permissions
        $this->checkPermissions($envPath, $findings);

        // Check 4: Extra keys in .env not in .env.example
        if (file_exists($envExamplePath)) {
            $this->checkExtraKeys($envPath, $envExamplePath, $findings);

            // Check 5: Keys defined in .env.example but missing from .env
            // (deletion of required keys may indicate tampering)
            $this->checkMissingKeys($envPath, $envExamplePath, $findings);
        }

        // Check 6: .env file in public/ directory
        $this->checkPublicEnv($basePath, $findings);

        // Check 5: Security configuration checks (APP_DEBUG, APP_KEY, APP_ENV)
        $this->checkSecurityConfiguration($envPath, $findings);

        return $findings;
    }

    /**
     * Check if the .env file has world-readable permissions.
     */
    private function checkPermissions(string $envPath, FindingCollection $findings): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            return;
        }

        $perms = @fileperms($envPath);

        if ($perms === false) {
            return;
        }

        if ($perms & 0x0004) {
            $findings->add(Finding::make(
                severity: Severity::HIGH,
                file: '.env',
                line: null,
                description: sprintf(
                    'The .env file is world-readable (permissions: %s). This exposes sensitive credentials to all system users.',
                    substr(sprintf('%o', $perms), -4),
                ),
                scannerName: $this->name(),
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
            scannerName: $this->name(),
        ));
    }

    /**
     * Compare .env keys against .env.example to find keys that were defined
     * in the example but are missing from the actual .env file. Deleting
     * required keys is a common post-compromise tactic (e.g. removing
     * APP_KEY or debug-related settings).
     */
    private function checkMissingKeys(
        string $envPath,
        string $envExamplePath,
        FindingCollection $findings,
    ): void {
        $envKeys = $this->parseEnvKeys($envPath);
        $exampleKeys = $this->parseEnvKeys($envExamplePath);

        $missingKeys = array_diff($exampleKeys, $envKeys);

        if (empty($missingKeys)) {
            return;
        }

        $keyList = implode(', ', array_slice($missingKeys, 0, 10));
        $remaining = count($missingKeys) > 10 ? sprintf(' (and %d more)', count($missingKeys) - 10) : '';

        $findings->add(Finding::make(
            severity: Severity::LOW,
            file: '.env',
            line: null,
            description: sprintf(
                'Found %d key(s) defined in .env.example but missing from .env: %s%s. Verify these were not removed to alter application behavior.',
                count($missingKeys),
                $keyList,
                $remaining,
            ),
            scannerName: $this->name(),
        ));
    }

    /**
     * Check for .env files inside the public/ directory.
     */
    private function checkPublicEnv(string $basePath, FindingCollection $findings): void
    {
        $publicEnvPath = $basePath.'/public/.env';

        if (file_exists($publicEnvPath)) {
            $findings->add(Finding::make(
                severity: Severity::CRITICAL,
                file: 'public/.env',
                line: null,
                description: 'A .env file exists in the public/ directory. This file is web-accessible and exposes all environment secrets.',
                scannerName: $this->name(),
            ));
        }
    }

    /**
     * Check security configuration values in .env.
     */
    private function checkSecurityConfiguration(string $envPath, FindingCollection $findings): void
    {
        $envMap = $this->parseEnvKeyValueMap($envPath);

        $appEnv = strtolower(trim($envMap['APP_ENV'] ?? ''));
        $appDebug = strtolower(trim($envMap['APP_DEBUG'] ?? ''));
        $appKey = trim($envMap['APP_KEY'] ?? '');

        $assumeProduction = (bool) config('scalpel.assume_production', false);
        $isProduction = $appEnv === 'production' || $assumeProduction;

        // Check APP_KEY presence
        if ($appKey === '') {
            $findings->add(Finding::make(
                severity: Severity::CRITICAL,
                file: '.env',
                line: null,
                description: 'APP_KEY is missing or empty in .env. Encryption and session security are compromised.',
                scannerName: $this->name(),
            ));
        }

        // Check APP_DEBUG=true in production
        if ($isProduction && in_array($appDebug, ['true', '1', 'yes'], true)) {
            $findings->add(Finding::make(
                severity: Severity::HIGH,
                file: '.env',
                line: null,
                description: 'APP_DEBUG is enabled (true) in a production environment. Detailed exception stack traces may be exposed publicly.',
                scannerName: $this->name(),
            ));
        }

        // Check APP_ENV=local when assume_production is enforced
        if ($assumeProduction && $appEnv === 'local') {
            $findings->add(Finding::make(
                severity: Severity::MEDIUM,
                file: '.env',
                line: null,
                description: 'APP_ENV is set to "local" while running under production security checks.',
                scannerName: $this->name(),
            ));
        }
    }

    /**
     * Parse an env file and extract key names.
     *
     * @return string[]
     */
    private function parseEnvKeys(string $filePath): array
    {
        return array_keys($this->parseEnvKeyValueMap($filePath));
    }

    /**
     * Parse an env file into key-value map.
     *
     * @return array<string, string>
     */
    private function parseEnvKeyValueMap(string $filePath): array
    {
        $contents = @file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if ($contents === false) {
            return [];
        }

        $map = [];

        foreach ($contents as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (preg_match('/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/', $line, $matches) === 1) {
                $value = trim($matches[2]);
                $value = trim($value, '"\'');
                $map[$matches[1]] = $value;
            }
        }

        return $map;
    }
}
