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

    /**
     * Patterns that describe a function-call shape and are matched against
     * code whose string literals and inline HTML have been blanked, so that
     * prose mentioning e.g. "eval(base64_decode(...))" is not reported.
     *
     * Patterns that must read string contents (preg_replace_e looks for /e
     * inside a regex string, hex_escape_sequence and long_encoded_string
     * inspect literal payloads) are intentionally not listed.
     *
     * @var string[]
     */
    private const CODE_ONLY_PATTERNS = [
        'eval_base64_decode',
        'eval_gzinflate',
        'eval_str_rot13',
        'eval_gzuncompress',
        'eval_gzdecode',
        'create_function',
        'dynamic_include',
        'superglobal_eval',
        'extract_input',
        'file_put_contents_encoded',
    ];

    /**
     * Whole statements Blade's props and aware directives compile to, taken
     * verbatim from CompilesComponents.
     *
     * @var string[]
     */
    private const COMPILED_BLADE_VARIABLE_VARIABLES = [
        '/\$\$__key\s*=\s*\$\$__key\s*\?\?\s*\$__value\s*;/',
        '/unset\s*\(\s*\$\$__key\s*\)\s*;/',
        '/\$\$__consumeVariable\s*=\s*is_string\(\s*\$__key\s*\)\s*\?\s*\$__env->getConsumableComponentData\(\s*\$__key\s*,\s*\$__value\s*\)\s*:\s*\$__env->getConsumableComponentData\(\s*\$__value\s*\)\s*;/',
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
        $extensions = array_map(static fn (string $extension): string => preg_quote($extension, '/'), $this->getSuspiciousPhpExtensions());
        $finder->name('/\.(?:'.implode('|', $extensions).')$/i');

        // Materialize the file list so progress can report a total upfront
        $filesArray = iterator_to_array($finder, false);
        $totalFiles = count($filesArray);
        $this->notifyProgress('start', ['total' => $totalFiles]);

        $processed = 0;

        foreach ($filesArray as $file) {
            $realPath = $file->getRealPath();
            if ($realPath === false) {
                continue;
            }
            $relativePath = $file->getRelativePathname();
            $this->scanFile($realPath, $relativePath, $patterns, $findings);

            $processed++;
            $this->notifyProgress('advance', [
                'current' => $processed,
                'total' => $totalFiles,
                'file' => $relativePath,
            ]);
        }

        foreach ($finder->getUnreadablePaths() as $unreadablePath) {
            $relativePath = $this->relativePath($unreadablePath, $basePath);
            $findings->addDirectoryError($relativePath, 'Unable to open directory for reading.', $this->name());
        }

        $findings->setScannerStatus($this->name(), $findings->hasErrors() ? 'partial' : 'complete');

        $this->notifyProgress('finish');

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
        $fileSize = @filesize($filePath);
        if ($fileSize !== false && $fileSize > 2 * 1024 * 1024) {
            $findings->addError($relativePath, sprintf('File exceeds maximum scan size limit (2MB, actual: %.2fMB) and was skipped.', $fileSize / 1048576), $this->name());

            return;
        }

        $handle = @fopen($filePath, 'r');

        if ($handle === false) {
            $findings->addError($relativePath, 'Unable to read PHP file for scanning.', $this->name());

            return;
        }

        $findings->incrementScannedFiles(1);

        try {
            $source = stream_get_contents($handle);
            if ($source === false) {
                return;
            }
            $code = $this->removeCommentsPreservingLines($source);
            $codeWithoutStrings = null;
            foreach ($patterns as $key => $patternDef) {
                if ($key === 'backtick_operator') {
                    $this->checkBacktickOperator($source, $relativePath, $patternDef, $findings);

                    continue;
                }
                if ($key === 'variable_variables') {
                    $this->checkVariableVariables($code, $relativePath, $patternDef, $findings);

                    continue;
                }
                if (in_array($key, ['long_encoded_string', 'variable_functions', 'chr_chaining'], true)) {
                    foreach (explode("\n", $code) as $index => $line) {
                        $lineNumber = $index + 1;
                        if ($key === 'long_encoded_string') {
                            $this->checkLongEncodedString($line, $lineNumber, $relativePath, $findings);
                        } elseif ($key === 'variable_functions') {
                            $this->checkVariableFunctions($line, $lineNumber, $relativePath, $findings);
                        } else {
                            $this->checkChrChaining($line, $lineNumber, $relativePath, $findings);
                        }
                    }

                    continue;
                }
                if (! empty($patternDef['pattern'])) {
                    $subject = $code;
                    if (in_array($key, self::CODE_ONLY_PATTERNS, true)) {
                        $codeWithoutStrings ??= $this->blankNonExecutableText($source);
                        $subject = $codeWithoutStrings;
                    }

                    if (preg_match_all($patternDef['pattern'], $subject, $matches, PREG_OFFSET_CAPTURE)) {
                        foreach ($matches[0] as $match) {
                            $lineNumber = substr_count(substr($subject, 0, $match[1]), "\n") + 1;
                            $findings->add(Finding::make(
                                severity: $patternDef['severity'],
                                file: $relativePath,
                                line: $lineNumber,
                                description: $patternDef['description'],
                                scannerName: $this->name(),
                            ));
                        }
                    }
                }
            }
        } finally {
            fclose($handle);
        }
    }

    /**
     * Check for the backtick (shell execution) operator.
     *
     * Matched by token, not regex: PHP emits a bare '`' token only for the
     * real operator, never for backticks inside strings, heredocs or comments.
     *
     * @param  array{pattern: string, severity: Severity, description: string}  $patternDef
     */
    private function checkBacktickOperator(
        string $source,
        string $relativePath,
        array $patternDef,
        FindingCollection $findings,
    ): void {
        if (! str_contains($source, '`')) {
            return;
        }

        $lineNumber = 1;
        $insideBackticks = false;

        foreach (token_get_all($source) as $token) {
            // Array tokens carry their own text; only they can span lines.
            if (is_array($token)) {
                $lineNumber += substr_count($token[1], "\n");

                continue;
            }

            if ($token !== '`') {
                continue;
            }

            // Backticks come in pairs. Report the opening one only, so a
            // single shell-exec expression yields a single finding.
            if ($insideBackticks) {
                $insideBackticks = false;

                continue;
            }

            $insideBackticks = true;

            $findings->add(Finding::make(
                severity: $patternDef['severity'],
                file: $relativePath,
                line: $lineNumber,
                description: $patternDef['description'],
                scannerName: $this->name(),
            ));
        }
    }

    /**
     * Check for variable variables ($$var).
     *
     * Compiled Blade views are full of them, so the statements Blade emits are
     * blanked before matching. Blanking statements rather than exempting names
     * keeps $$__key reported when it is called or assigned from input.
     *
     * @param  array{pattern: string, severity: Severity, description: string}  $patternDef
     */
    private function checkVariableVariables(
        string $code,
        string $relativePath,
        array $patternDef,
        FindingCollection $findings,
    ): void {
        if (! str_contains($code, '$$')) {
            return;
        }

        // Blanked rather than removed, so line numbers still match the source.
        foreach (self::COMPILED_BLADE_VARIABLE_VARIABLES as $statement) {
            $code = preg_replace_callback(
                $statement,
                static fn (array $match): string => preg_replace('/[^\r\n]/', ' ', $match[0]) ?? '',
                $code,
            ) ?? $code;
        }

        if (! preg_match_all($patternDef['pattern'], $code, $matches, PREG_OFFSET_CAPTURE)) {
            return;
        }

        foreach ($matches[0] as $match) {
            $findings->add(Finding::make(
                severity: $patternDef['severity'],
                file: $relativePath,
                line: substr_count(substr($code, 0, $match[1]), "\n") + 1,
                description: $patternDef['description'],
                scannerName: $this->name(),
            ));
        }
    }

    /** Remove PHP comments while preserving newlines for accurate reporting. */
    private function removeCommentsPreservingLines(string $source): string
    {
        if (! str_contains($source, '/*') && ! str_contains($source, '//') && ! str_contains($source, '#')) {
            return $source;
        }

        $result = '';
        foreach (token_get_all($source) as $token) {
            if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                $result .= preg_replace('/[^\r\n]/', ' ', $token[1]) ?? '';
            } else {
                $result .= is_array($token) ? $token[1] : $token;
            }
        }

        return $result;
    }

    /**
     * Blank comments, inline HTML and string literal contents, preserving
     * newlines and offsets, so call-shape patterns only match real code.
     *
     * String literals are kept verbatim when the statement they belong to
     * can still turn them into code:
     *  - the statement contains eval (e.g. eval('eval(base64_decode(...))')), or
     *  - a literal in the statement embeds PHP source ("<?php" / "<?="),
     *    which is how droppers write web shells to disk.
     *
     * Statements are delimited by ';' and PHP open/close tags.
     */
    private function blankNonExecutableText(string $source): string
    {
        $tokens = token_get_all($source);

        $stringTokens = [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE];
        $boundaryTokens = [T_OPEN_TAG, T_OPEN_TAG_WITH_ECHO, T_CLOSE_TAG];

        // First pass: decide per statement whether its literals must be kept.
        $statementOf = [];
        $keepStatement = [];
        $statement = 0;

        foreach ($tokens as $index => $token) {
            $statementOf[$index] = $statement;
            $keepStatement[$statement] ??= false;

            if (is_array($token)) {
                if ($token[0] === T_EVAL) {
                    $keepStatement[$statement] = true;
                } elseif (
                    in_array($token[0], $stringTokens, true)
                    && (str_contains($token[1], '<?php') || str_contains($token[1], '<?='))
                ) {
                    $keepStatement[$statement] = true;
                }

                if (in_array($token[0], $boundaryTokens, true)) {
                    $statement++;
                }
            } elseif ($token === ';') {
                $statement++;
            }
        }

        // Second pass: rebuild the source with non-executable text blanked.
        $result = '';

        foreach ($tokens as $index => $token) {
            if (! is_array($token)) {
                $result .= $token;

                continue;
            }

            $blank = in_array($token[0], [T_COMMENT, T_DOC_COMMENT, T_INLINE_HTML], true)
                || (in_array($token[0], $stringTokens, true) && ! $keepStatement[$statementOf[$index]]);

            $result .= $blank ? (preg_replace('/[^\r\n]/', ' ', $token[1]) ?? '') : $token[1];
        }

        return $result;
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
                scannerName: $this->name(),
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
                        scannerName: $this->name(),
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
                scannerName: $this->name(),
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

        // Extract string literals from the line
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
                        scannerName: $this->name(),
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
                    scannerName: $this->name(),
                ));
            }
        }
    }

    /**
     * Determine if a string looks like encoded content (base64, hex, etc).
     *
     * Callers guarantee the content already exceeds the configured minimum
     * length, so no length checks are needed here.
     */
    private function looksEncoded(string $content): bool
    {
        // Hex pattern: exclusively hexadecimal characters with even length
        // (each byte is encoded as two characters).
        if (preg_match('/^[0-9a-fA-F]+$/', $content) === 1 && strlen($content) % 2 === 0) {
            return true;
        }

        // Base64 pattern: allowed charset AND at least one structural base64
        // character (+, / or =). Requiring a structural character avoids
        // flagging long plain words that happen to be purely alphanumeric.
        if (
            preg_match('/^[A-Za-z0-9+\/=]+$/', $content) === 1
            && preg_match('/[+\/=]/', $content) === 1
        ) {
            return true;
        }

        // Very dense alphanumeric blob without spaces or punctuation —
        // likely a custom-encoded payload. The threshold is deliberately
        // strict (95%) so normal prose or minified code (which contain
        // punctuation) is not flagged.
        $alphanumCount = preg_match_all('/[A-Za-z0-9]/', $content);

        if ($alphanumCount !== false) {
            $ratio = $alphanumCount / strlen($content);

            if ($ratio > 0.95) {
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
            'backtick_operator' => [
                'pattern' => '',
                'severity' => Severity::HIGH,
                'description' => 'Backtick operator detected — executes shell commands (alias of shell_exec).',
            ],
            'variable_variables' => [
                'pattern' => '/\$\$[a-zA-Z_]/',
                'severity' => Severity::MEDIUM,
                'description' => 'Variable variables ($$var) detected — frequently used to obfuscate function calls.',
            ],
            'extract_input' => [
                'pattern' => '/extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)/i',
                'severity' => Severity::HIGH,
                'description' => 'extract() over request input — allows attackers to overwrite arbitrary variables.',
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
