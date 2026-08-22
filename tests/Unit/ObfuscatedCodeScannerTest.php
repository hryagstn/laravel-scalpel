<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\ObfuscatedCodeScanner;
use Hryagstn\Scalpel\Tests\TestCase;

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
                'assert_dynamic' => true,
                'variable_functions' => true,
                'preg_replace_e' => true,
                'long_encoded_string' => true,
                'create_function' => true,
                'file_put_contents_encoded' => true,
                'superglobal_eval' => true,
                'chr_chaining' => true,
                'hex_escape_sequence' => true,
                'dynamic_include' => true,
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

    public function test_assert_dynamic(): void
    {
        file_put_contents($this->tempDir.'/test.php', '<?php assert($dynamic);');

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
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
}
