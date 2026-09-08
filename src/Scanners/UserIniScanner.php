<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Scanners;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;

/**
 * Scans PHP-FPM `.user.ini` files inside web-accessible directories
 * (public/, storage/) for dangerous directives — the persistence vector
 * where `auto_prepend_file = shell.txt` executes an attacker's file on
 * every request.
 */
final class UserIniScanner extends BaseScanner
{
    /**
     * Fallback list when scalpel.user_ini_dangerous_directives is not configured.
     *
     * @var string[]
     */
    private const DEFAULT_DANGEROUS_DIRECTIVES = [
        'auto_prepend_file',
        'auto_append_file',
        'include_path',
        'open_basedir',
        'disable_functions',
        'disable_classes',
        'zend_extension',
        'extension',
    ];

    public function name(): string
    {
        return 'User INI';
    }

    public function scan(string $basePath): FindingCollection
    {
        $findings = new FindingCollection;
        $basePath = rtrim($basePath, '/');

        /** @var string[] $dangerousDirectives */
        $dangerousDirectives = config('scalpel.user_ini_dangerous_directives', self::DEFAULT_DANGEROUS_DIRECTIVES);

        $finder = $this->createFinder($basePath, $this->getExcludedPaths())->name('.user.ini');

        foreach ($finder as $file) {
            $relativePath = $file->getRelativePathname();
            $this->scanUserIniFile($file->getPathname(), $relativePath, $dangerousDirectives, $findings);
        }

        foreach ($finder->getUnreadablePaths() as $unreadablePath) {
            $relativePath = $this->relativePath($unreadablePath, $basePath);
            $findings->addDirectoryError($relativePath, 'Unable to open directory for reading.', $this->name());
        }

        $findings->setScannerStatus($this->name(), $findings->hasErrors() ? 'partial' : 'complete');

        return $findings;
    }

    /**
     * @param  string[]  $dangerousDirectives
     */
    private function scanUserIniFile(string $filePath, string $relativePath, array $dangerousDirectives, FindingCollection $findings): void
    {
        $contents = @file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($contents === false) {
            $findings->addError($relativePath, 'Unable to read .user.ini file.', $this->name());

            return;
        }

        $findings->incrementScannedFiles(1);

        $lineNumber = 0;
        foreach ($contents as $line) {
            $lineNumber++;
            $trimmed = trim($line);

            if ($trimmed === '' || str_starts_with($trimmed, ';') || str_starts_with($trimmed, '#')) {
                continue;
            }

            foreach ($dangerousDirectives as $directive) {
                $pattern = '/^'.preg_quote($directive, '/').'\s*=/i';
                if (preg_match($pattern, $trimmed) === 1) {
                    $findings->add(Finding::make(
                        severity: Severity::CRITICAL,
                        file: $relativePath,
                        line: $lineNumber,
                        description: "Dangerous directive '{$directive}' found in .user.ini -- allows PHP configuration override.",
                        scannerName: $this->name(),
                    ));
                    break;
                }
            }
        }
    }
}
