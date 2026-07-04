<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Scanners;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;
use Symfony\Component\Finder\Finder;

class HtaccessScanner extends BaseScanner
{
    /**
     * PHP directives that weaken security when enabled.
     *
     * @var string[]
     */
    private const DANGEROUS_PHP_DIRECTIVES = [
        'allow_url_include',
        'allow_url_fopen',
        'disable_functions',
        'display_errors',
        'enable_dl',
    ];

    /**
     * MIME types and handler names that indicate script execution capability.
     *
     * @var string[]
     */
    private const SCRIPT_HANDLER_PATTERNS = [
        // Explicit handler names
        'cgi-script',
        'python-program',
        'perl-script',
        'ruby-script',
        'php-script',
        // MIME-type style handlers (used in AddHandler AND AddType)
        'application/x-httpd-python',
        'application/x-httpd-perl',
        'application/x-httpd-ruby',
        'application/x-httpd-cgi',
        'application/x-httpd-php',
        'text/x-php',
        'text/x-python',
        'text/x-perl',
    ];

    public function name(): string
    {
        return 'Htaccess';
    }

    public function scan(string $basePath): FindingCollection
    {
        $findings = new FindingCollection();
        $excludedPaths = $this->getExcludedPaths();

        // Use a dedicated Finder for .htaccess files.
        // We do NOT use createFinder() from BaseScanner because Symfony Finder's
        // ignoreDotFiles() affects file detection inconsistently across versions.
        // Instead we manually glob for .htaccess files to ensure reliable detection.
        $htaccessFiles = $this->findHtaccessFiles($basePath, $excludedPaths);

        foreach ($htaccessFiles as $fullPath) {
            $relativePath = $this->relativePath($fullPath, $basePath);
            $this->scanHtaccessFile($fullPath, $relativePath, $findings);
        }

        return $findings;
    }

    /**
     * Find all .htaccess files recursively under $basePath, respecting exclusions.
     *
     * Uses RecursiveDirectoryIterator directly to avoid dot-file issues with
     * Symfony Finder across different configurations.
     *
     * @param string   $basePath
     * @param string[] $excludedPaths
     * @return string[]
     */
    private function findHtaccessFiles(string $basePath, array $excludedPaths): array
    {
        $results = [];
        $basePath = rtrim($basePath, '/');

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator(
                    $basePath,
                    \RecursiveDirectoryIterator::SKIP_DOTS,
                ),
                \RecursiveIteratorIterator::SELF_FIRST,
            );

            foreach ($iterator as $file) {
                if (! $file->isFile()) {
                    continue;
                }

                if ($file->getFilename() !== '.htaccess') {
                    continue;
                }

                $fullPath = $file->getRealPath();
                if ($fullPath === false) {
                    continue;
                }
                $relativePath = $this->relativePath($fullPath, $basePath);

                if ($this->isExcluded($relativePath, $excludedPaths)) {
                    continue;
                }

                $results[] = $fullPath;
            }
        } catch (\UnexpectedValueException) {
            // Directory not readable — skip silently
        }

        return $results;
    }

    /**
     * Scan a single .htaccess file line by line.
     */
    private function scanHtaccessFile(
        string $filePath,
        string $relativePath,
        FindingCollection $findings,
    ): void {
        $handle = @fopen($filePath, 'r');

        if ($handle === false) {
            return;
        }

        $lineNumber = 0;

        try {
            while (($line = fgets($handle)) !== false) {
                $lineNumber++;

                // Normalize line endings and trim
                $trimmedLine = trim(str_replace(["\r\n", "\r"], "\n", $line));

                // Skip comments and empty lines
                if ($trimmedLine === '' || str_starts_with($trimmedLine, '#')) {
                    continue;
                }

                $this->checkAddHandler($trimmedLine, $lineNumber, $relativePath, $findings);
                $this->checkAddType($trimmedLine, $lineNumber, $relativePath, $findings);
                $this->checkPhpDirectives($trimmedLine, $lineNumber, $relativePath, $findings);
                $this->checkExternalRewrite($trimmedLine, $lineNumber, $relativePath, $findings);
                $this->checkExecCGI($trimmedLine, $lineNumber, $relativePath, $findings);
            }
        } finally {
            fclose($handle);
        }
    }

    /**
     * Check for AddHandler directives with dangerous handlers.
     *
     * Handles both named handlers (cgi-script) and MIME-type style handlers
     * (application/x-httpd-python) since attackers use both forms.
     */
    private function checkAddHandler(
        string $line,
        int $lineNumber,
        string $relativePath,
        FindingCollection $findings,
    ): void {
        if (preg_match('/^(?:AddHandler|SetHandler)\s+(\S+)/i', $line, $matches) !== 1) {
            return;
        }

        $handler = trim(strtolower($matches[1]), '"\'');

        // Check against config-defined dangerous handlers
        /** @var string[] $configHandlers */
        $configHandlers = config('scalpel.htaccess_dangerous_handlers', []);

        foreach ($configHandlers as $dangerous) {
            if (strtolower($dangerous) === $handler) {
                $findings->add(Finding::make(
                    severity: Severity::CRITICAL,
                    file: $relativePath,
                    line: $lineNumber,
                    description: "Dangerous AddHandler/SetHandler directive '{$handler}' — could allow execution of uploaded scripts.",
                    scanner_name: $this->name(),
                ));
                return;
            }
        }

        // Also check against built-in script handler patterns
        // (catches MIME-type style handlers not in config)
        foreach (self::SCRIPT_HANDLER_PATTERNS as $pattern) {
            if (strtolower($pattern) === $handler) {
                $findings->add(Finding::make(
                    severity: Severity::CRITICAL,
                    file: $relativePath,
                    line: $lineNumber,
                    description: "AddHandler/SetHandler uses script handler '{$handler}' — could allow execution of non-standard file types as scripts.",
                    scanner_name: $this->name(),
                ));
                return;
            }
        }

        // Catch any x-httpd-* or x-script-* pattern not explicitly listed
        if (preg_match('/^(application\/x-(httpd|script)-|text\/x-(php|python|perl|ruby))/i', $handler) === 1) {
            $findings->add(Finding::make(
                severity: Severity::CRITICAL,
                file: $relativePath,
                line: $lineNumber,
                description: "AddHandler/SetHandler uses suspicious MIME-type handler '{$handler}' — may enable script execution.",
                scanner_name: $this->name(),
            ));
        }
    }

    /**
     * Check for AddType directives mapping extensions to script handlers.
     */
    private function checkAddType(
        string $line,
        int $lineNumber,
        string $relativePath,
        FindingCollection $findings,
    ): void {
        if (preg_match('/^AddType\s+(\S+)\s+(.+)/i', $line, $matches) !== 1) {
            return;
        }

        $mimeType = trim(strtolower($matches[1]), '"\'');
        $extensions = trim($matches[2]);

        // Check against built-in script MIME types
        foreach (self::SCRIPT_HANDLER_PATTERNS as $pattern) {
            if (strtolower($pattern) === $mimeType) {
                $findings->add(Finding::make(
                    severity: Severity::HIGH,
                    file: $relativePath,
                    line: $lineNumber,
                    description: "AddType maps '{$extensions}' to script handler '{$mimeType}' — may enable code execution via non-standard file extensions.",
                    scanner_name: $this->name(),
                ));
                return;
            }
        }

        // Catch any x-httpd-* pattern not explicitly listed
        if (preg_match('/^(application\/x-(httpd|script)-|text\/x-(php|python|perl|ruby))/i', $mimeType) === 1) {
            $findings->add(Finding::make(
                severity: Severity::HIGH,
                file: $relativePath,
                line: $lineNumber,
                description: "AddType maps '{$extensions}' to suspicious MIME type '{$mimeType}' — may enable script execution.",
                scanner_name: $this->name(),
            ));
        }
    }

    /**
     * Check for php_flag/php_value directives that disable security features.
     */
    private function checkPhpDirectives(
        string $line,
        int $lineNumber,
        string $relativePath,
        FindingCollection $findings,
    ): void {
        if (preg_match('/^php_(flag|value)\s+(\S+)\s+(.+)/i', $line, $matches) !== 1) {
            return;
        }

        $directive = strtolower($matches[2]);
        $value = strtolower(trim($matches[3]));

        foreach (self::DANGEROUS_PHP_DIRECTIVES as $dangerous) {
            if ($directive !== $dangerous) {
                continue;
            }

            $isDangerous = match ($directive) {
                'allow_url_include',
                'allow_url_fopen',
                'display_errors',
                'enable_dl' => in_array($value, ['on', '1', 'true', 'yes'], true),
                'disable_functions' => $value === '' || $value === 'none',
                default => false,
            };

            if ($isDangerous) {
                $findings->add(Finding::make(
                    severity: Severity::CRITICAL,
                    file: $relativePath,
                    line: $lineNumber,
                    description: "php_{$matches[1]} disables security setting: '{$directive}' set to '{$value}'.",
                    scanner_name: $this->name(),
                ));
            }
        }
    }

    /**
     * Check for RewriteRule redirecting unconditionally to external domains.
     */
    private function checkExternalRewrite(
        string $line,
        int $lineNumber,
        string $relativePath,
        FindingCollection $findings,
    ): void {
        if (preg_match('/^RewriteRule\s+\S+\s+(https?:\/\/)/i', $line) !== 1) {
            return;
        }

        $findings->add(Finding::make(
            severity: Severity::HIGH,
            file: $relativePath,
            line: $lineNumber,
            description: 'RewriteRule redirects to an external URL — may be used for phishing or traffic hijacking.',
            scanner_name: $this->name(),
        ));
    }

    /**
     * Check for Options +ExecCGI directive.
     */
    private function checkExecCGI(
        string $line,
        int $lineNumber,
        string $relativePath,
        FindingCollection $findings,
    ): void {
        if (preg_match('/^Options\s+.*\+?ExecCGI/i', $line) !== 1) {
            return;
        }

        $findings->add(Finding::make(
            severity: Severity::CRITICAL,
            file: $relativePath,
            line: $lineNumber,
            description: 'Options ExecCGI enabled — allows execution of CGI scripts in this directory.',
            scanner_name: $this->name(),
        ));
    }
}