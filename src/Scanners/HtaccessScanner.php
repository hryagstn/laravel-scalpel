<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Scanners;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;

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
        'auto_prepend_file',
        'auto_append_file',
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
        $findings = new FindingCollection;

        $finder = $this->createFinder($basePath, $this->getExcludedPaths())->name('.htaccess');

        foreach ($finder as $file) {
            $relativePath = $file->getRelativePathname();
            $this->scanHtaccessFile($file->getPathname(), $relativePath, $findings);
        }

        foreach ($finder->getUnreadablePaths() as $unreadablePath) {
            $relativePath = $this->relativePath($unreadablePath, $basePath);
            $findings->addDirectoryError($relativePath, 'Unable to open directory for reading.', $this->name());
        }

        $findings->setScannerStatus($this->name(), $findings->hasErrors() ? 'partial' : 'complete');

        return $findings;
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
            $findings->addError($relativePath, 'Unable to open .htaccess file for reading.', $this->name());

            return;
        }

        $findings->incrementScannedFiles(1);

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
                    scannerName: $this->name(),
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
                    scannerName: $this->name(),
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
                scannerName: $this->name(),
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
                    scannerName: $this->name(),
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
                scannerName: $this->name(),
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
        $value = strtolower(trim($matches[3], " \t\"'"));

        foreach (self::DANGEROUS_PHP_DIRECTIVES as $dangerous) {
            if ($directive !== $dangerous) {
                continue;
            }

            $isDangerous = match ($directive) {
                'disable_functions' => $value === '' || $value === 'none',
                'auto_prepend_file', 'auto_append_file' => true,
                default => in_array($value, ['on', '1', 'true', 'yes'], true),
            };

            if ($isDangerous) {
                $findings->add(Finding::make(
                    severity: Severity::CRITICAL,
                    file: $relativePath,
                    line: $lineNumber,
                    description: "php_{$matches[1]} sets security-sensitive directive: '{$directive}' set to '{$value}'.",
                    scannerName: $this->name(),
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
            scannerName: $this->name(),
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
        if (preg_match('/^Options\s+(?!.*(?:^|\s)-ExecCGI\b).*\+ExecCGI\b/i', $line) !== 1) {
            return;
        }

        $findings->add(Finding::make(
            severity: Severity::CRITICAL,
            file: $relativePath,
            line: $lineNumber,
            description: 'Options ExecCGI enabled — allows execution of CGI scripts in this directory.',
            scannerName: $this->name(),
        ));
    }
}
