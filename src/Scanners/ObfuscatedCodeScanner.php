<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Scanners;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;

class ObfuscatedCodeScanner extends BaseScanner
{
    /**
     * Dangerous function names used for variable-function detection.
     *
     * @var string[]
     */
    private const DANGEROUS_FUNCTIONS = [
        'system',
        'exec',
        'passthru',
        'shell_exec',
        'popen',
        'proc_open',
    ];

    public function name(): string
    {
        return 'Obfuscated Code';
    }

    public function scan(string $basePath): FindingCollection
    {
        $findings = new FindingCollection();
        $patterns = $this->getEnabledPatterns();

        if (empty($patterns)) {
            return $findings;
        }

        $finder = $this->createFinder($basePath);
        $finder->name('*.php');

        foreach ($finder as $file) {
            $realPath = $file->getRealPath();
            if ($realPath === false) {
                continue;
            }
            $relativePath = $this->relativePath($realPath, $basePath);
            $this->scanFile($realPath, $relativePath, $patterns, $findings);
        }

        return $findings;
    }

    /**
     * Scan a single file line by line for obfuscation patterns.
     *
     * @param string $filePath
     * @param string $relativePath
     * @param array<string, array{pattern: string, severity: Severity, description: string}> $patterns
     * @param FindingCollection $findings
     */
    private function scanFile(
        string $filePath,
        string $relativePath,
        array $patterns,
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

                if ($this->isCommentLine($line)) {
                    continue;
                }

                foreach ($patterns as $key => $patternDef) {
                    if ($key === 'long_encoded_string') {
                        // Handle long encoded string detection separately
                        $this->checkLongEncodedString($line, $lineNumber, $relativePath, $findings);
                        continue;
                    }

                    if ($key === 'variable_functions') {
                        // Handle variable function detection separately
                        $this->checkVariableFunctions($line, $lineNumber, $relativePath, $findings);
                        continue;
                    }

                    if (preg_match($patternDef['pattern'], $line) === 1) {
                        $findings->add(Finding::make(
                            severity: $patternDef['severity'],
                            file: $relativePath,
                            line: $lineNumber,
                            description: $patternDef['description'],
                            scanner_name: $this->name(),
                        ));
                    }
                }
            }
        } finally {
            fclose($handle);
        }
    }

    /**
     * Check for variable function calls that invoke dangerous functions.
     *
     * Detects patterns like:
     *   $var = 'system'; $var('command');
     *   $func = "exec"; $func($arg);
     */
    private function checkVariableFunctions(
        string $line,
        int $lineNumber,
        string $relativePath,
        FindingCollection $findings,
    ): void {
        // Check for assignment of dangerous function names to variables
        $dangerousFuncList = implode('|', self::DANGEROUS_FUNCTIONS);
        $assignmentPattern = '/\$[a-zA-Z_]\w*\s*=\s*[\'"](' . $dangerousFuncList . ')[\'"]/i';

        if (preg_match($assignmentPattern, $line) === 1) {
            $findings->add(Finding::make(
                severity: Severity::HIGH,
                file: $relativePath,
                line: $lineNumber,
                description: 'Variable assigned a dangerous function name — potential variable function call to evade detection.',
                scanner_name: $this->name(),
            ));
            return;
        }

        // Check for variable function invocation pattern: $var(...)
        // Only flag if the line also contains one of the dangerous function names as a string
        if (preg_match('/\$[a-zA-Z_]\w*\s*\(/', $line) === 1) {
            foreach (self::DANGEROUS_FUNCTIONS as $func) {
                if (str_contains($line, "'{$func}'") || str_contains($line, "\"{$func}\"")) {
                    $findings->add(Finding::make(
                        severity: Severity::HIGH,
                        file: $relativePath,
                        line: $lineNumber,
                        description: "Variable function call detected with dangerous function '{$func}'.",
                        scanner_name: $this->name(),
                    ));
                    return;
                }
            }
        }
    }

    /**
     * Check for suspiciously long encoded strings (e.g. base64 payloads).
     */
    private function checkLongEncodedString(
        string $line,
        int $lineNumber,
        string $relativePath,
        FindingCollection $findings,
    ): void {
        /** @var int $threshold */
        $threshold = config('scalpel.long_string_threshold', 500);

        // Extract string literals from the line
        if (preg_match_all('/[\'"]([^\'"]{' . $threshold . ',})[\'"]/', $line, $matches)) {
            foreach ($matches[1] as $stringContent) {
                if ($this->looksEncoded($stringContent)) {
                    $findings->add(Finding::make(
                        severity: Severity::MEDIUM,
                        file: $relativePath,
                        line: $lineNumber,
                        description: sprintf(
                            'Suspiciously long encoded string detected (%d chars). May contain obfuscated payload.',
                            strlen($stringContent),
                        ),
                        scanner_name: $this->name(),
                    ));
                }
            }
        }

        // Also check for long non-whitespace sequences outside of strings
        // (e.g. concatenated or heredoc payloads)
        $trimmedLine = trim($line);
        if (strlen($trimmedLine) > $threshold) {
            $nonSpaceRatio = 1 - (substr_count($trimmedLine, ' ') / strlen($trimmedLine));
            if ($nonSpaceRatio > 0.9 && $this->looksEncoded($trimmedLine)) {
                $findings->add(Finding::make(
                    severity: Severity::MEDIUM,
                    file: $relativePath,
                    line: $lineNumber,
                    description: sprintf(
                        'Line contains suspiciously dense encoded content (%d chars, %.0f%% non-space).',
                        strlen($trimmedLine),
                        $nonSpaceRatio * 100,
                    ),
                    scanner_name: $this->name(),
                ));
            }
        }
    }

    /**
     * Determine if a line is a PHP comment line.
     */
    private function isCommentLine(string $line): bool
    {
        $trimmed = ltrim($line);

        // Check for single-line comments (// or #)
        if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#')) {
            return true;
        }

        // Check for multi-line comment starts (/*) or continuation lines within comments (*)
        if (str_starts_with($trimmed, '/*') || str_starts_with($trimmed, '*')) {
            return true;
        }

        return false;
    }

    /**
     * Determine if a string looks like encoded content (base64, hex, etc).
     */
    private function looksEncoded(string $content): bool
    {
        // Base64 pattern: mostly alphanumeric with +/= characters
        if (preg_match('/^[A-Za-z0-9+\/=]{100,}$/', $content) === 1) {
            return true;
        }

        // Hex pattern: exclusively hex characters
        if (preg_match('/^[0-9a-fA-F]{100,}$/', $content) === 1) {
            return true;
        }

        // High ratio of alphanumeric characters suggests encoding
        $alphanumCount = preg_match_all('/[A-Za-z0-9]/', $content);
        if ($alphanumCount !== false && strlen($content) > 0) {
            $ratio = $alphanumCount / strlen($content);
            if ($ratio > 0.85) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build the list of enabled obfuscation patterns with their regex and metadata.
     *
     * @return array<string, array{pattern: string, severity: Severity, description: string}>
     */
    private function getEnabledPatterns(): array
    {
        /** @var array<string, bool> $config */
        $config = config('scalpel.obfuscation_patterns', []);

        $allPatterns = [
            'eval_base64_decode' => [
                'pattern' => '/eval\s*\(\s*base64_decode\s*\(/i',
                'severity' => Severity::CRITICAL,
                'description' => 'eval(base64_decode(...)) detected — classic obfuscation pattern used to hide malicious code.',
            ],
            'eval_gzinflate' => [
                'pattern' => '/eval\s*\(\s*gzinflate\s*\(/i',
                'severity' => Severity::CRITICAL,
                'description' => 'eval(gzinflate(...)) detected — compressed code execution, commonly used in web shells.',
            ],
            'eval_str_rot13' => [
                'pattern' => '/eval\s*\(\s*str_rot13\s*\(/i',
                'severity' => Severity::CRITICAL,
                'description' => 'eval(str_rot13(...)) detected — ROT13-encoded code execution.',
            ],
            'eval_gzuncompress' => [
                'pattern' => '/eval\s*\(\s*gzuncompress\s*\(/i',
                'severity' => Severity::CRITICAL,
                'description' => 'eval(gzuncompress(...)) detected — compressed code execution.',
            ],
            'eval_gzdecode' => [
                'pattern' => '/eval\s*\(\s*gzdecode\s*\(/i',
                'severity' => Severity::CRITICAL,
                'description' => 'eval(gzdecode(...)) detected — compressed code execution.',
            ],
            'assert_dynamic' => [
                'pattern' => '/assert\s*\(\s*(\$|[\'\"]\s*\$)/i',
                'severity' => Severity::HIGH,
                'description' => 'Dynamic assert() with variable argument — can execute arbitrary code.',
            ],
            'preg_replace_e' => [
                'pattern' => '/preg_replace\s*\(\s*[\'\"\/].*\/e[\'"]/i',
                'severity' => Severity::HIGH,
                'description' => 'preg_replace() with /e modifier — evaluates replacement as PHP code (deprecated but dangerous).',
            ],
            // These two have custom handlers and won't use the 'pattern' key directly
            'variable_functions' => [
                'pattern' => '',
                'severity' => Severity::HIGH,
                'description' => 'Variable function call with dangerous function name.',
            ],
            'long_encoded_string' => [
                'pattern' => '',
                'severity' => Severity::MEDIUM,
                'description' => 'Long encoded string detected.',
            ],
        ];

        $enabled = [];

        foreach ($allPatterns as $key => $pattern) {
            // Default to enabled if not explicitly configured
            if (($config[$key] ?? true) === true) {
                $enabled[$key] = $pattern;
            }
        }

        return $enabled;
    }
}
