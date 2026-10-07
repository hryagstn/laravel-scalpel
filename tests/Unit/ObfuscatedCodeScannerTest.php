<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\ObfuscatedCodeScanner;
use Hryagstn\Scalpel\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

class ObfuscatedCodeScannerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'scalpel.excluded_paths' => ['vendor', 'node_modules', '.git'],
            'scalpel.obfuscation_patterns' => [
                'eval_base64_decode' => true,
                'eval_gzinflate' => true,
                'eval_str_rot13' => true,
                'eval_gzuncompress' => true,
                'eval_gzdecode' => true,
                'variable_functions' => true,
                'preg_replace_e' => true,
                'long_encoded_string' => true,
                'create_function' => true,
                'file_put_contents_encoded' => true,
                'superglobal_eval' => true,
                'chr_chaining' => true,
                'hex_escape_sequence' => true,
                'dynamic_include' => true,
                'variable_variables' => true,
            ],
            'scalpel.long_string_threshold' => 50, // lower for easier testing
        ]);
    }

    public function test_eval_base64_decode(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php eval(base64_decode("cGhwaW5mbygpOw=="));');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('eval(base64_decode(...))', $findings->all()[0]->description);
    }

    public function test_eval_gzinflate(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php eval(gzinflate($payload));');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('eval(gzinflate(...))', $findings->all()[0]->description);
    }

    public function test_eval_str_rot13(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php eval(str_rot13("payload"));');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_eval_gzuncompress(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php eval(gzuncompress($payload));');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_eval_gzdecode(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php eval(gzdecode($payload));');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_variable_functions(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php
        $var = "system";
        $var("whoami");
        ');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertGreaterThanOrEqual(1, count($findings));
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_preg_replace_e(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php preg_replace("/.*/e", $replacement, $subject);');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_create_function(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php $fn = create_function("$a", "return \$a;");');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_file_put_contents_encoded(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php file_put_contents("shell.php", base64_decode($payload));');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_superglobal_eval(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php eval($_POST["cmd"]);');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_superglobal_eval_covers_assert(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php assert($_POST["cmd"]);');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function superglobalExecutionProvider(): array
    {
        // Each function is paired with a different superglobal so both
        // alternations of the superglobal_eval pattern are exercised.
        return [
            'system over $_GET' => ['<?php system($_GET["c"]);'],
            'exec over $_POST' => ['<?php exec($_POST["c"]);'],
            'passthru over $_REQUEST' => ['<?php passthru($_REQUEST["c"]);'],
            'shell_exec over $_COOKIE' => ['<?php shell_exec($_COOKIE["c"]);'],
        ];
    }

    #[DataProvider('superglobalExecutionProvider')]
    public function test_superglobal_eval_covers_shell_functions(string $code): void
    {
        file_put_contents($this->tempDir.'/test.php', $code);

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('Direct execution of superglobal input', $findings->all()[0]->description);
    }

    public function test_chr_chaining(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php $x = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109).chr(40).chr(34).chr(119).chr(104);');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('MEDIUM', $findings->all()[0]->severity->value);
    }

    public function test_hex_escape_sequence(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php $x = "\x73\x79\x73\x74\x65\x6d\x28\x22\x77\x68\x6f\x61\x6d\x69\x22\x29";');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('MEDIUM', $findings->all()[0]->severity->value);
    }

    public function test_dynamic_include(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php include($_GET["page"]);');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_long_encoded_string(): void
    {
        $longStr = str_repeat('a', 60);
        file_put_contents($this->tempDir.'/test.php', "<?php \$x = '{$longStr}';");

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertGreaterThanOrEqual(1, count($findings));
        $this->assertEquals('MEDIUM', $findings->all()[0]->severity->value);
    }

    public function test_realistic_base64_payload_is_flagged(): void
    {
        $payload = base64_encode(str_repeat('<?php system($_GET["c"]); ', 30));
        $this->assertGreaterThan(50, strlen($payload));

        file_put_contents($this->tempDir.'/test.php', "<?php \$x = '{$payload}';");

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $encodedFindings = array_filter(
            $findings->all(),
            fn ($f) => str_contains($f->description, 'encoded'),
        );

        $this->assertGreaterThanOrEqual(1, count($encodedFindings));
    }

    public function test_long_prose_is_not_flagged_as_encoded(): void
    {
        $prose = str_repeat('The quick brown fox jumps over the lazy dog near the riverbank. ', 3);
        file_put_contents($this->tempDir.'/test.php', "<?php \$message = '{$prose}';");

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_minified_code_with_punctuation_is_not_flagged_as_encoded(): void
    {
        $minified = str_repeat('function(a,b){return a+b};var x=1,y=2;', 4);
        file_put_contents($this->tempDir.'/test.php', "<?php \$tpl = \"{$minified}\";");

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_long_alphanumeric_word_without_base64_chars_is_still_flagged(): void
    {
        // Pure alphanumeric blob (no +/= chars): caught by density heuristic.
        $blob = str_repeat('AbCdEf0123456789ZzYyXxWwVvUuTt', 4);

        file_put_contents($this->tempDir.'/test.php', "<?php \$x = '{$blob}';");

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertGreaterThanOrEqual(1, count($findings));
    }

    public function test_eval_base64_decode_in_comments_is_skipped(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php
        // Komentar dokumentasi yang menjelaskan serangan
        // Contoh backdoor: eval(base64_decode("..."))
        # Contoh backdoor: eval(base64_decode("..."))
        /* Contoh backdoor: eval(base64_decode("...")) */
        /**
         * Contoh: eval(base64_decode("..."))
         */
        ');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_plain_assert_is_not_flagged(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php assert($user !== null);');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_disabled_patterns_are_skipped(): void
    {
        config(['scalpel.obfuscation_patterns.eval_base64_decode' => false]);
        file_put_contents($this->tempDir.'/test.php', '<?php eval(base64_decode("cGhwaW5mbygpOw=="));');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_handles_broken_symlinks_safely(): void
    {
        @symlink($this->tempDir.'/non_existent_file.php', $this->tempDir.'/test.php');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);

        @unlink($this->tempDir.'/test.php');
    }

    public function test_variable_variables_are_detected(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php $$payload($_GET["c"]);');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('MEDIUM', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('Variable variables', $findings->all()[0]->description);
    }

    public function test_compiled_blade_props_are_not_flagged_as_variable_variables(): void
    {
        // Verbatim compileProps() output, emitted by every @props component.
        file_put_contents($this->tempDir.'/compiled.php', <<<'PHP'
            <?php $attributes ??= new \Illuminate\View\ComponentAttributeBag;

            $__newAttributes = [];
            $__propNames = \Illuminate\View\ComponentAttributeBag::extractPropNames(['label']);

            foreach ($attributes->all() as $__key => $__value) {
                if (in_array($__key, $__propNames)) {
                    $$__key = $$__key ?? $__value;
                } else {
                    $__newAttributes[$__key] = $__value;
                }
            }

            foreach (array_filter(['label'], 'is_string', ARRAY_FILTER_USE_KEY) as $__key => $__value) {
                $$__key = $$__key ?? $__value;
            }

            $__defined_vars = get_defined_vars();

            foreach ($attributes->all() as $__key => $__value) {
                if (array_key_exists($__key, $__defined_vars)) unset($$__key);
            }
            PHP);

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_compiled_blade_aware_is_not_flagged_as_variable_variables(): void
    {
        // Verbatim compileAware() output, emitted by every @aware component.
        file_put_contents($this->tempDir.'/compiled.php', <<<'PHP'
            <?php foreach (['theme'] as $__key => $__value) {
                $__consumeVariable = is_string($__key) ? $__key : $__value;
                $$__consumeVariable = is_string($__key) ? $__env->getConsumableComponentData($__key, $__value) : $__env->getConsumableComponentData($__value);
            } ?>
            PHP);

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public static function bladeNameReuseProvider(): array
    {
        // The exemption covers whole compiled statements, not variable names,
        // so a payload cannot borrow it by reusing Blade's internal names.
        return [
            'call through an unrelated $$__ name' => ['<?php $$__cmd($_GET["c"]);'],
            'call through Blade\'s own $$__key' => ['<?php $$__key($_GET["c"]);'],
            'assignment to $$__key from input' => ['<?php $$__key = $_GET["c"];'],
            'unset of a different $$__ name' => ['<?php unset($$__cmd);'],
            'aware statement with a rewritten body' => ['<?php $$__consumeVariable = is_string($__key) ? $_GET["c"] : 1;'],
        ];
    }

    #[DataProvider('bladeNameReuseProvider')]
    public function test_blade_internal_names_are_still_flagged_outside_compiled_statements(string $code): void
    {
        file_put_contents($this->tempDir.'/test.php', $code);

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('MEDIUM', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('Variable variables', $findings->all()[0]->description);
    }

    public function test_aware_exemption_does_not_swallow_an_executing_body(): void
    {
        // Shaped like compileAware() but executing input, so both the
        // variable variable and the shell call must still be reported.
        file_put_contents(
            $this->tempDir.'/test.php',
            '<?php $$__consumeVariable = is_string($__key) ? system($_GET["c"]) : 1;',
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(2, $findings);

        $descriptions = implode("\n", array_map(fn ($finding) => $finding->description, $findings->all()));
        $this->assertStringContainsString('Variable variables', $descriptions);
        $this->assertStringContainsString('Direct execution of superglobal input', $descriptions);
    }

    public function test_variable_variables_report_the_original_line_number(): void
    {
        // Blanking the exempt statements above must not shift the payload's line.
        file_put_contents($this->tempDir.'/compiled.php', <<<'PHP'
            <?php
            $$__key = $$__key ?? $__value;
            unset($$__key);
            $$__cmd($_GET["c"]);
            PHP);

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals(4, $findings->all()[0]->line);
    }

    public function test_compiled_view_directory_is_still_content_scanned(): void
    {
        mkdir($this->tempDir.'/storage/framework/views', 0777, true);
        file_put_contents(
            $this->tempDir.'/storage/framework/views/abc123.php',
            '<?php eval(base64_decode("cGhwaW5mbygpOw=="));',
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_backtick_operator_is_detected(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php $output = `whoami`;');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('Backtick operator', $findings->all()[0]->description);
    }

    public function test_backtick_operator_is_reported_once_per_expression(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php $a = `id`; $b = `uname -a`;');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(2, $findings);
    }

    public function test_backtick_operator_reports_the_opening_line(): void
    {
        file_put_contents($this->tempDir.'/test.php', "<?php\n\n\$out = `ls\n-la`;\n");

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertSame(3, $findings->all()[0]->line);
    }

    public function test_quoted_sql_identifiers_in_single_quoted_string_are_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/test.php',
            "<?php \$q = orderByField('`product`.`id`', \$ids);",
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_quoted_sql_identifiers_in_double_quoted_string_are_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/test.php',
            '<?php $q = "SELECT `id` FROM `users` WHERE `id` = {$id}";',
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_quoted_sql_identifiers_spanning_multiple_lines_are_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/test.php',
            "<?php\n\$sql = sprintf(\n    'INSERT INTO `%s` (`ident`, `label`)\n     VALUES (?, ?)',\n    \$table,\n);",
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_quoted_sql_identifiers_in_heredoc_are_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/test.php',
            "<?php\n\$sql = <<<SQL\nSELECT `id`, `name` FROM `users`\nSQL;\n",
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_backticks_in_comments_are_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/test.php',
            "<?php\n// Escape the column as `id` before querying.\n/* also `name` here */\n\$x = 1;",
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_backticks_in_inline_html_are_not_flagged(): void
    {
        file_put_contents(
            $this->tempDir.'/test.php',
            "<?php \$x = 1; ?>\n<script>const t = `template \${x} literal`;</script>",
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_backtick_operator_can_be_disabled(): void
    {
        config(['scalpel.obfuscation_patterns.backtick_operator' => false]);
        file_put_contents($this->tempDir.'/test.php', '<?php $output = `whoami`;');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_content_scan_vendor_exclusion_does_not_hide_public_vendor(): void
    {
        config([
            'scalpel.excluded_paths' => ['node_modules', '.git'],
            'scalpel.content_scan_excluded_paths' => ['vendor', 'bootstrap/cache'],
        ]);

        @mkdir($this->tempDir.'/public/vendor/horizon', 0777, true);
        file_put_contents($this->tempDir.'/public/vendor/horizon/shell.php', '<?php eval($_POST["c"]);');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertSame('public/vendor/horizon/shell.php', $findings->all()[0]->file);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_content_scan_vendor_exclusion_still_skips_root_vendor(): void
    {
        config([
            'scalpel.excluded_paths' => ['node_modules', '.git'],
            'scalpel.content_scan_excluded_paths' => ['vendor', 'bootstrap/cache'],
        ]);

        @mkdir($this->tempDir.'/vendor/acme/pkg', 0777, true);
        @mkdir($this->tempDir.'/bootstrap/cache', 0777, true);
        file_put_contents($this->tempDir.'/vendor/acme/pkg/x.php', '<?php eval($_POST["c"]);');
        file_put_contents($this->tempDir.'/bootstrap/cache/services.php', '<?php eval($_POST["c"]);');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    /**
     * Prose that mentions a dangerous call without executing it.
     *
     * @return array<string, array{string}>
     */
    public static function nonExecutableMentionProvider(): array
    {
        return [
            'eval_base64_decode in double-quoted string' => [<<<'PHP'
                <?php $doc = "Never use eval(base64_decode(\$x)) in code";
                PHP],
            'eval_gzinflate in single-quoted string' => [<<<'PHP'
                <?php $m = 'eval(gzinflate($p)) is a classic web shell';
                PHP],
            'create_function in string' => [<<<'PHP'
                <?php $msg = 'create_function() was removed in PHP 8';
                PHP],
            'dynamic_include in string' => [<<<'PHP'
                <?php $warn = 'never include $_GET[page] directly';
                PHP],
            'superglobal_eval in exception message' => [<<<'PHP'
                <?php throw new RuntimeException('Blocked system($_GET[cmd]) attempt');
                PHP],
            'extract_input in string' => [<<<'PHP'
                <?php $rule = 'extract($_POST) overwrites variables';
                PHP],
            'file_put_contents_encoded in string' => [<<<'PHP'
                <?php $hint = 'file_put_contents($f, base64_decode($p)) drops a file';
                PHP],
            'nowdoc documentation' => [<<<'PHP'
                <?php
                $help = <<<'TXT'
                Avoid eval(base64_decode(...)) and system($_GET[x]).
                TXT;
                PHP],
            'inline HTML' => [<<<'PHP'
                <?php $x = 1; ?>
                <p>Do not write eval(base64_decode($x)) in templates.</p>
                PHP],
        ];
    }

    #[DataProvider('nonExecutableMentionProvider')]
    public function test_call_patterns_ignore_non_executable_text(string $code): void
    {
        file_put_contents($this->tempDir.'/test.php', $code);

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_dropper_writing_embedded_php_payload_is_still_detected(): void
    {
        file_put_contents($this->tempDir.'/test.php', <<<'PHP'
            <?php file_put_contents('s.php', '<?php eval(base64_decode("cGhw"));');
            PHP);

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $descriptions = array_map(static fn ($f) => $f->description, $findings->all());
        $this->assertCount(2, $findings);
        $this->assertStringContainsString('eval(base64_decode(...))', implode("\n", $descriptions));
        $this->assertStringContainsString('dropper pattern', implode("\n", $descriptions));
    }

    public function test_dropper_payload_split_across_literals_in_one_statement_is_still_detected(): void
    {
        file_put_contents($this->tempDir.'/test.php', <<<'PHP'
            <?php file_put_contents('s.php', "<?php " . 'eval(gzinflate($p));');
            PHP);

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $descriptions = implode("\n", array_map(static fn ($f) => $f->description, $findings->all()));
        $this->assertStringContainsString('eval(gzinflate(...))', $descriptions);
    }

    public function test_payload_inside_eval_string_argument_is_still_detected(): void
    {
        file_put_contents($this->tempDir.'/test.php', <<<'PHP'
            <?php eval('eval(base64_decode("cGhw"));');
            PHP);

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('eval(base64_decode(...))', $findings->all()[0]->description);
    }

    public function test_line_numbers_survive_blanked_multiline_strings(): void
    {
        file_put_contents($this->tempDir.'/test.php', <<<'PHP'
            <?php
            $doc = 'line one
            eval(base64_decode($x)) in docs';

            eval(base64_decode($p));
            PHP);

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertSame(5, $findings->all()[0]->line);
    }
}
