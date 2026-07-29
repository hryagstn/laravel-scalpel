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
        $publicEnvPath = $basePath.'/public/.env';

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
                scanner_name: $this->name(),
            ));
        }

        // Check APP_DEBUG=true in production
        if ($isProduction && in_array($appDebug, ['true', '1', 'yes'], true)) {
            $findings->add(Finding::make(
                severity: Severity::HIGH,
                file: '.env',
                line: null,
                description: 'APP_DEBUG is enabled (true) in a production environment. Detailed exception stack traces may be exposed publicly.',
                scanner_name: $this->name(),
            ));
        }

        // Check APP_ENV=local when assume_production is enforced
        if ($assumeProduction && $appEnv === 'local') {
            $findings->add(Finding::make(
                severity: Severity::MEDIUM,
                file: '.env',
                line: null,
                description: 'APP_ENV is set to "local" while running under production security checks.',
                scanner_name: $this->name(),
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
