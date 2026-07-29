<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Hryagstn\Scalpel\Scanners\ObfuscatedCodeScanner;
use Hryagstn\Scalpel\Tests\TestCase;

class BaseScannerExclusionTest extends TestCase
{
    private string $sandboxDir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->sandboxDir = $this->tempDir.'/exclusion_test';
        mkdir($this->sandboxDir, 0777, true);

        // Config reflects the new three-tier structure
        config([
            'scalpel.excluded_paths' => [
                'node_modules',
                '.git',
            ],
            'scalpel.content_scan_excluded_paths' => [
                'vendor',
                'bootstrap/cache',
            ],
            'scalpel.baseline_excluded_paths' => [
                'storage/logs',
                'storage/framework/cache',
            ],
            'scalpel.baseline_path' => 'scalpel/baseline.json',
            'scalpel.obfuscation_patterns' => [
                'eval_base64_decode' => true,
            ],
        ]);
    }

    protected function tearDown(): void
    {
        $this->cleanDir($this->sandboxDir);
        @rmdir($this->sandboxDir);
        parent::tearDown();
    }

    private function makeFile(string $relativePath, string $content): string
    {
        $fullPath = $this->sandboxDir.'/'.ltrim($relativePath, '/');
        @mkdir(dirname($fullPath), 0777, true);
        file_put_contents($fullPath, $content);

        return $fullPath;
    }

    // -------------------------------------------------------------------------
    // Tests: content_scan_excluded_paths skips vendor for content scanners
    // -------------------------------------------------------------------------

    public function test_obfuscated_scanner_skips_vendor_directory(): void
    {
        // Plant an obfuscated file inside vendor/ — should NOT be flagged
        $this->makeFile(
            'vendor/evil/backdoor.php',
            '<?php eval(base64_decode("dGVzdA==")); ?>'
        );

        // Also plant one outside vendor/ — SHOULD be flagged
        $this->makeFile(
            'app/legit.php',
            '<?php eval(base64_decode("dGVzdA==")); ?>'
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->sandboxDir);

        $files = array_map(fn ($f) => $f->file, $findings->all());

        $this->assertNotContains('vendor/evil/backdoor.php', $files,
            'vendor/ should be excluded from ObfuscatedCodeScanner');

        $this->assertContains('app/legit.php', $files,
            'Files outside vendor/ should still be scanned');
    }

    public function test_obfuscated_scanner_skips_node_modules(): void
    {
        $this->makeFile(
            'node_modules/pkg/evil.php',
            '<?php eval(base64_decode("dGVzdA==")); ?>'
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->sandboxDir);

        $files = array_map(fn ($f) => $f->file, $findings->all());

        $this->assertNotContains('node_modules/pkg/evil.php', $files,
            'node_modules/ should be excluded from all scanners');
    }

    public function test_obfuscated_scanner_skips_bootstrap_cache(): void
    {
        $this->makeFile(
            'bootstrap/cache/services.php',
            '<?php eval(base64_decode("dGVzdA==")); ?>'
        );

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan($this->sandboxDir);

        $files = array_map(fn ($f) => $f->file, $findings->all());

        $this->assertNotContains('bootstrap/cache/services.php', $files,
            'bootstrap/cache/ should be excluded from content scanners');
    }

    // -------------------------------------------------------------------------
    // Tests: BaselineDiffScanner still monitors vendor/ via hash comparison
    // -------------------------------------------------------------------------

    public function test_baseline_includes_vendor_in_snapshot(): void
    {
        // Create a clean vendor file
        $this->makeFile('vendor/laravel/framework/src/Request.php', '<?php // legit');
        $this->makeFile('app/Http/Controllers/HomeController.php', '<?php // legit');

        $scanner = new BaselineDiffScanner;
        $result = $scanner->createBaseline($this->sandboxDir);

        // Both files should be in the baseline
        $this->assertGreaterThanOrEqual(2, $result['files'],
            'Baseline should include vendor/ files for hash monitoring');
    }

    public function test_baseline_diff_detects_new_file_in_vendor(): void
    {
        // Create baseline without the evil file
        $this->makeFile('app/Http/Controllers/HomeController.php', '<?php // legit');
        $this->makeFile('vendor/laravel/framework/src/Request.php', '<?php // legit');

        $scanner = new BaselineDiffScanner;
        $scanner->createBaseline($this->sandboxDir);

        // Plant a new file in vendor/ after baseline
        $this->makeFile('vendor/evil/backdoor.php', '<?php eval(base64_decode("dGVzdA=="));');

        $findings = $scanner->scan($this->sandboxDir);

        $files = array_map(fn ($f) => $f->file, $findings->all());

        $this->assertContains('vendor/evil/backdoor.php', $files,
            'BaselineDiffScanner should detect new files planted in vendor/');
    }

    public function test_baseline_diff_detects_modified_vendor_file(): void
    {
        // Create baseline with clean vendor file
        $vendorFile = $this->makeFile(
            'vendor/laravel/framework/src/Request.php',
            '<?php // original content'
        );

        $scanner = new BaselineDiffScanner;
        $scanner->createBaseline($this->sandboxDir);

        // Modify the vendor file after baseline
        sleep(1); // ensure mtime differs
        file_put_contents($vendorFile, '<?php eval(base64_decode("modified"));');

        $findings = $scanner->scan($this->sandboxDir);

        $files = array_map(fn ($f) => $f->file, $findings->all());

        $this->assertContains('vendor/laravel/framework/src/Request.php', $files,
            'BaselineDiffScanner should detect modified files in vendor/');
    }

    // -------------------------------------------------------------------------
    // Tests: baseline_excluded_paths are excluded from baseline too
    // -------------------------------------------------------------------------

    public function test_baseline_excludes_storage_logs(): void
    {
        $this->makeFile('storage/logs/laravel.log', 'some log content');
        $this->makeFile('app/Console/Kernel.php', '<?php // legit');

        $scanner = new BaselineDiffScanner;
        $result = $scanner->createBaseline($this->sandboxDir);

        // storage/logs should not be in baseline — only app/ file
        $this->assertEquals(1, $result['files'],
            'storage/logs/ should be excluded from baseline snapshot');
    }

    // -------------------------------------------------------------------------
    // Tests: bootstrap/cache is monitored by baseline (NOT excluded)
    // -------------------------------------------------------------------------

    public function test_baseline_includes_bootstrap_cache(): void
    {
        $this->makeFile('bootstrap/cache/services.php', '<?php return [];');

        $scanner = new BaselineDiffScanner;
        $result = $scanner->createBaseline($this->sandboxDir);

        $this->assertGreaterThanOrEqual(1, $result['files'],
            'bootstrap/cache/ should be included in baseline for security monitoring');
    }

    public function test_baseline_diff_detects_modified_bootstrap_cache(): void
    {
        $cacheFile = $this->makeFile(
            'bootstrap/cache/services.php',
            '<?php return [];'
        );

        $scanner = new BaselineDiffScanner;
        $result = $scanner->createBaseline($this->sandboxDir);

        sleep(1);
        file_put_contents($cacheFile, '<?php /* injected */ return [];');

        $findings = $scanner->scan($this->sandboxDir);
        $files = array_map(fn ($f) => $f->file, $findings->all());

        $this->assertContains('bootstrap/cache/services.php', $files);
    }

    // -------------------------------------------------------------------------
    // Tests: isExcluded helper
    // -------------------------------------------------------------------------

    public function test_is_excluded_matches_exact_path(): void
    {
        $scanner = new ObfuscatedCodeScanner;

        $reflection = new \ReflectionMethod($scanner, 'isExcluded');
        $reflection->setAccessible(true);

        $this->assertTrue(
            $reflection->invoke($scanner, 'vendor', ['vendor']),
            'Exact path match should be excluded'
        );
    }

    public function test_is_excluded_matches_subdirectory(): void
    {
        $scanner = new ObfuscatedCodeScanner;

        $reflection = new \ReflectionMethod($scanner, 'isExcluded');
        $reflection->setAccessible(true);

        $this->assertTrue(
            $reflection->invoke($scanner, 'vendor/laravel/framework/src/Http/Request.php', ['vendor']),
            'Files inside excluded directory should be excluded'
        );
    }

    public function test_is_excluded_does_not_match_partial_names(): void
    {
        $scanner = new ObfuscatedCodeScanner;

        $reflection = new \ReflectionMethod($scanner, 'isExcluded');
        $reflection->setAccessible(true);

        $this->assertFalse(
            $reflection->invoke($scanner, 'vendor_custom/file.php', ['vendor']),
            'vendor_custom/ should not be excluded when only vendor/ is in the list'
        );
    }
}
