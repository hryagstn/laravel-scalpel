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
                'eval_base64_decode'  => true,
                'eval_gzinflate'      => true,
                'eval_str_rot13'      => true,
                'eval_gzuncompress'   => true,
                'eval_gzdecode'       => true,
                'assert_dynamic'      => true,
                'variable_functions'  => true,
                'preg_replace_e'      => true,
                'long_encoded_string' => true,
            ],
            'scalpel.long_string_threshold' => 50, // lower for easier testing
        ]);
    }

    public function test_eval_base64_decode(): void
    {
        file_put_contents($this->tempDir . '/test.php', '<?php eval(base64_decode("cGhwaW5mbygpOw=="));');

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('eval(base64_decode(...))', $findings->all()[0]->description);
    }

    public function test_eval_gzinflate(): void
    {
        file_put_contents($this->tempDir . '/test.php', '<?php eval(gzinflate($payload));');

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('eval(gzinflate(...))', $findings->all()[0]->description);
    }

    public function test_eval_str_rot13(): void
    {
        file_put_contents($this->tempDir . '/test.php', '<?php eval(str_rot13("payload"));');

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_eval_gzuncompress(): void
    {
        file_put_contents($this->tempDir . '/test.php', '<?php eval(gzuncompress($payload));');

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_eval_gzdecode(): void
    {
        file_put_contents($this->tempDir . '/test.php', '<?php eval(gzdecode($payload));');

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_assert_dynamic(): void
    {
        file_put_contents($this->tempDir . '/test.php', '<?php assert($dynamic);');

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_variable_functions(): void
    {
        file_put_contents($this->tempDir . '/test.php', '<?php
        $var = "system";
        $var("whoami");
        ');

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        // Should flag the assignment to dangerous function and/or the call
        $this->assertGreaterThanOrEqual(1, count($findings));
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_preg_replace_e(): void
    {
        file_put_contents($this->tempDir . '/test.php', '<?php preg_replace("/.*/e", $replacement, $subject);');

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_long_encoded_string(): void
    {
        // 60-character base64-like string (exceeds our threshold of 50)
        $longStr = str_repeat('a', 60);
        file_put_contents($this->tempDir . '/test.php', "<?php \$x = '{$longStr}';");

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertGreaterThanOrEqual(1, count($findings));
        $this->assertEquals('MEDIUM', $findings->all()[0]->severity->value);
    }

    public function test_eval_base64_decode_in_comments_is_skipped(): void
    {
        file_put_contents($this->tempDir . '/test.php', "<?php
        // Komentar dokumentasi yang menjelaskan serangan
        // Contoh backdoor: eval(base64_decode(\"...\"))
        # Contoh backdoor: eval(base64_decode(\"...\"))
        /* Contoh backdoor: eval(base64_decode(\"...\")) */
        /**
         * Contoh: eval(base64_decode(\"...\"))
         */
        ");

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_disabled_patterns_are_skipped(): void
    {
        config(['scalpel.obfuscation_patterns.eval_base64_decode' => false]);
        file_put_contents($this->tempDir . '/test.php', '<?php eval(base64_decode("cGhwaW5mbygpOw=="));');

        $scanner = new ObfuscatedCodeScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }
}
