<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Feature;

use Hryagstn\Scalpel\Scalpel;
use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Hryagstn\Scalpel\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Storage;

class ScalpelDiffCommandTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'scalpel.excluded_paths' => ['vendor', 'node_modules', '.git'],
            'scalpel.baseline_excluded_paths' => ['storage', 'bootstrap'],
            'scalpel.baseline_path' => 'scalpel/baseline.json',
            'scalpel.non_php_zones' => ['public', 'storage'],
            'scalpel.structural_allowed_files' => ['public/index.php'],
            'scalpel.structural_allowed_directories' => ['public/vendor'],
        ]);
    }

    protected function tearDown(): void
    {
        Storage::delete(config('scalpel.baseline_path', 'scalpel/baseline.json'));

        parent::tearDown();
    }

    private function makeTempFile(string $relativePath, string $content): string
    {
        $fullPath = $this->tempDir.'/'.ltrim($relativePath, '/');
        $dir = dirname($fullPath);

        if (! is_dir($dir)) {
            mkdir($dir, 0777, true);
        }

        file_put_contents($fullPath, $content);

        return $fullPath;
    }

    private function createBaselineFromTempDir(): void
    {
        /** @var Scalpel $scalpel */
        $scalpel = app(Scalpel::class);

        /** @var BaselineDiffScanner $scanner */
        $scanner = $scalpel->getScanner('Baseline Diff');

        $scanner->createBaseline($this->tempDir);
    }

    public function test_diff_command_fails_if_no_baseline_exists(): void
    {
        Storage::delete(config('scalpel.baseline_path', 'scalpel/baseline.json'));

        $this->artisan('scalpel:diff')
            ->expectsOutputToContain('No baseline snapshot found')
            ->assertExitCode(1);
    }

    public function test_diff_command_shows_clean_when_no_changes(): void
    {
        $this->makeTempFile('app.php', '<?php return [];');
        $this->makeTempFile('.env', 'APP_ENV=testing');

        $this->createBaselineFromTempDir();

        /** @var Scalpel $scalpel */
        $scalpel = app(Scalpel::class);

        /** @var BaselineDiffScanner $scanner */
        $scanner = $scalpel->getScanner('Baseline Diff');

        $findings = $scanner->scan($this->tempDir);

        $this->assertTrue($findings->isEmpty(), 'Expected no findings but got: '.$findings->count());
    }

    public function test_diff_detects_new_file_after_baseline(): void
    {
        $this->makeTempFile('app.php', '<?php return [];');
        $this->createBaselineFromTempDir();

        $this->makeTempFile('public/evil.php', '<?php eval($_POST["cmd"]);');

        /** @var Scalpel $scalpel */
        $scalpel = app(Scalpel::class);

        /** @var BaselineDiffScanner $scanner */
        $scanner = $scalpel->getScanner('Baseline Diff');

        $findings = $scanner->scan($this->tempDir);

        $this->assertFalse($findings->isEmpty());

        $files = array_map(fn ($f) => $f->file, $findings->all());
        $this->assertContains('public/evil.php', $files);
    }

    public function test_diff_detects_modified_file_after_baseline(): void
    {
        $this->makeTempFile('app.php', '<?php return [];');
        $this->createBaselineFromTempDir();

        sleep(1);
        $this->makeTempFile('app.php', '<?php return ["modified" => true];');

        /** @var Scalpel $scalpel */
        $scalpel = app(Scalpel::class);

        /** @var BaselineDiffScanner $scanner */
        $scanner = $scalpel->getScanner('Baseline Diff');

        $findings = $scanner->scan($this->tempDir);

        $this->assertFalse($findings->isEmpty());

        $files = array_map(fn ($f) => $f->file, $findings->all());
        $this->assertContains('app.php', $files);
    }

    public function test_diff_detects_deleted_file_after_baseline(): void
    {
        $fileToDelete = $this->makeTempFile('will-be-deleted.php', '<?php echo "bye";');
        $this->makeTempFile('stays.php', '<?php echo "hello";');
        $this->createBaselineFromTempDir();

        @unlink($fileToDelete);

        /** @var Scalpel $scalpel */
        $scalpel = app(Scalpel::class);

        /** @var BaselineDiffScanner $scanner */
        $scanner = $scalpel->getScanner('Baseline Diff');

        $findings = $scanner->scan($this->tempDir);

        $this->assertFalse($findings->isEmpty());

        $files = array_map(fn ($f) => $f->file, $findings->all());
        $this->assertContains('will-be-deleted.php', $files);
    }

    public function test_diff_command_artisan_returns_exit_code_1_when_baseline_missing(): void
    {
        Storage::delete(config('scalpel.baseline_path', 'scalpel/baseline.json'));

        $this->artisan('scalpel:diff')
            ->assertExitCode(1);
    }

    public function test_diff_command_json_format_suppresses_banner_and_progress(): void
    {
        $this->makeTempFile('app.php', '<?php return [];');
        $this->makeTempFile('.env', 'APP_ENV=testing');
        $this->createBaselineFromTempDir();

        $exitCode = Artisan::call('scalpel:diff', ['--format' => 'json']);
        $this->assertIsInt($exitCode);

        $output = Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringNotContainsString('Comparing filesystem', $output);
        $this->assertStringContainsString('"total"', $output);
    }

    public function test_diff_command_supports_hmac_signing(): void
    {
        config([
            'scalpel.signing.enabled' => true,
            'scalpel.signing.key' => 'secret-signing-key',
        ]);

        $this->makeTempFile('app.php', '<?php return [];');
        $this->makeTempFile('.env', 'APP_ENV=testing');
        $this->createBaselineFromTempDir();

        Artisan::call('scalpel:diff', ['--format' => 'json']);
        $output = Artisan::output();

        $this->assertStringContainsString('"signature"', $output);
    }

    public function test_diff_command_no_banner_option_suppresses_banner(): void
    {
        $this->makeTempFile('app.php', '<?php return [];');
        $this->makeTempFile('.env', 'APP_ENV=testing');
        $this->createBaselineFromTempDir();

        $exitCode = Artisan::call('scalpel:diff', ['--no-banner' => true]);
        $this->assertIsInt($exitCode);

        $output = Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringContainsString('Comparing filesystem', $output);
    }

    public function test_diff_command_no_ansi_option_suppresses_banner(): void
    {
        $this->makeTempFile('app.php', '<?php return [];');
        $this->makeTempFile('.env', 'APP_ENV=testing');
        $this->createBaselineFromTempDir();

        $exitCode = Artisan::call('scalpel:diff', ['--no-ansi' => true]);
        $this->assertIsInt($exitCode);

        $output = Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringContainsString('Comparing filesystem', $output);
    }

    public function test_diff_command_config_suppress_banner_suppresses_banner(): void
    {
        config(['scalpel.suppress_banner' => true]);
        $this->makeTempFile('app.php', '<?php return [];');
        $this->makeTempFile('.env', 'APP_ENV=testing');
        $this->createBaselineFromTempDir();

        $exitCode = Artisan::call('scalpel:diff');
        $this->assertIsInt($exitCode);

        $output = Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringContainsString('Comparing filesystem', $output);
    }
}
