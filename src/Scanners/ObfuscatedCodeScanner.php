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
        $findings = new FindingCollection;
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
     * @param  array<string, array{pattern: string, severity: Severity, description: string}>  $patterns
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
                        $this->checkLongEncodedString($line, $lineNumber, $relativePath, $findings);

                        continue;
                    }

                    if ($key === 'variable_functions') {
                        $this->checkVariableFunctions($line, $lineNumber, $relativePath, $findings);

                        continue;
                    }

                    if ($key === 'chr_chaining') {
                        $this->checkChrChaining($line, $lineNumber, $relativePath, $findings);

                        continue;
                    }

                    if (! empty($patternDef['pattern']) && preg_match($patternDef['pattern'], $line) === 1) {
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
     */
    private function checkVariableFunctions(
        string $line,
        int $lineNumber,
        string $relativePath,
        FindingCollection $findings,
    ): void {
        $dangerousFuncList = implode('|', self::DANGEROUS_FUNCTIONS);
        $assignmentPattern = '/\$[a-zA-Z_]\w*\s*=\s*[\'"]('.$dangerousFuncList.')[\'"]/i';

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
     * Check for excessive chr() chaining used to obfuscate code strings.
     */
    private function checkChrChaining(
        string $line,
        int $lineNumber,
        string $relativePath,
        FindingCollection $findings,
    ): void {
        $count = preg_match_all('/chr\s*\(\s*\d+\s*\)/i', $line);
        if ($count !== false && $count >= 10) {
            $findings->add(Finding::make(
                severity: Severity::MEDIUM,
                file: $relativePath,
                line: $lineNumber,
                description: sprintf('Excessive chr() function chaining detected (%d calls in one line) — common obfuscation technique.', $count),
                scanner_name: $this->name(),
            ));
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

        if (preg_match_all('/[\'"]([^\'"]{'.$threshold.',})[\'"]/', $line, $matches)) {
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

        if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#')) {
            return true;
        }

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
        if (preg_match('/^[A-Za-z0-9+\/=]{100,}$/', $content) === 1) {
            return true;
        }

        if (preg_match('/^[0-9a-fA-F]{100,}$/', $content) === 1) {
            return true;
        }

        $alphanumCount = preg_match_all('/[A-Za-z0-9]/', $content);
        if (strlen($content) > 0) {
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
            'create_function' => [
                'pattern' => '/create_function\s*\(/i',
                'severity' => Severity::HIGH,
                'description' => 'create_function() detected — deprecated function commonly exploited to execute dynamic code.',
            ],
            'file_put_contents_encoded' => [
                'pattern' => '/file_put_contents\s*\(.*(base64_decode|gzinflate|str_rot13)/i',
                'severity' => Severity::HIGH,
                'description' => 'file_put_contents() with decoded payload detected — dropper pattern writing malicious files to disk.',
            ],
            'superglobal_eval' => [
                'pattern' => '/\b(eval|system|exec|passthru|shell_exec|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                'severity' => Severity::CRITICAL,
                'description' => 'Direct execution of superglobal input ($_GET/$_POST/$_REQUEST) detected — immediate web shell pattern.',
            ],
            'hex_escape_sequence' => [
                'pattern' => '/(\\\\x[0-9a-fA-F]{2}){10,}/i',
                'severity' => Severity::MEDIUM,
                'description' => 'Dense hex escape sequences detected — obfuscated binary or code string.',
            ],
            'dynamic_include' => [
                'pattern' => '/(include|require)(_once)?\s*[\(\s]*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)/i',
                'severity' => Severity::CRITICAL,
                'description' => 'Dynamic file inclusion using superglobal input ($_GET/$_POST/$_REQUEST) — Remote/Local File Inclusion (RFI/LFI) backdoor.',
            ],
            'chr_chaining' => [
                'pattern' => '',
                'severity' => Severity::MEDIUM,
                'description' => 'Excessive chr() function chaining detected.',
            ],
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
            if (($config[$key] ?? true) === true) {
                $enabled[$key] = $pattern;
            }
        }

        return $enabled;
    }
}
