<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Feature;

use Hryagstn\Scalpel\Scalpel;
use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Hryagstn\Scalpel\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Storage;

class ScalpelScanCommandTest extends TestCase
{
    private array $createdFiles = [];

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        config([
            'scalpel.non_php_zones' => ['public'],
            'scalpel.structural_allowed_files' => ['public/index.php'],
            'scalpel.excluded_paths' => ['node_modules', '.git'],
            'scalpel.content_scan_excluded_paths' => ['vendor', 'bootstrap/cache'],
            'scalpel.baseline_excluded_paths' => ['storage', 'bootstrap'],
            'scalpel.severity_threshold' => 'LOW',
            'scalpel.assume_production' => false,
        ]);
    }

    protected function tearDown(): void
    {
        foreach ($this->createdFiles as $file) {
            if (file_exists($file)) {
                @unlink($file);
            }
        }

        @rmdir(base_path('public/testdir'));

        parent::tearDown();
    }

    private function createSandboxFile(string $relativePath, string $content): void
    {
        $path = base_path($relativePath);
        $dir = dirname($path);

        if (! is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        file_put_contents($path, $content);

        if ($relativePath === '.env') {
            @chmod($path, 0600);
        }

        $this->createdFiles[] = $path;
    }

    public function test_scan_command_runs_successfully_when_clean(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $this->createSandboxFile('.env.example', "APP_ENV=\nAPP_KEY=");

        $this->artisan('scalpel:baseline --force')->assertExitCode(0);

        $this->artisan('scalpel:scan')
            ->expectsOutputToContain('Running scanner: Structural Anomaly')
            ->expectsOutputToContain('No findings detected')
            ->assertExitCode(0);
    }

    public function test_scan_command_fails_when_intrusion_detected(): void
    {
        $this->createSandboxFile('public/backdoor.php', '<?php eval($_POST["cmd"]);');
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");

        $this->artisan('scalpel:baseline --force')->assertExitCode(0);

        $this->artisan('scalpel:scan')
            ->expectsOutputToContain('Structural Anomaly')
            ->expectsOutputToContain('backdoor.php')
            ->assertExitCode(1);
    }

    public function test_scan_command_json_output(): void
    {
        $this->createSandboxFile('public/backdoor.php', '<?php eval(base64_decode($_POST["cmd"]));');
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");

        $this->artisan('scalpel:baseline --force')->assertExitCode(0);

        $this->artisan('scalpel:scan --format=json')
            ->expectsOutputToContain('"total": 2')
            ->assertExitCode(1);
    }

    public function test_scan_command_only_flag_matches_htaccess_scanner(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");

        $this->artisan('scalpel:scan --only=htaccess')
            ->expectsOutputToContain('Running scanner: Htaccess')
            ->doesntExpectOutput('Running scanner: Obfuscated Code')
            ->assertExitCode(0);
    }

    public function test_scan_command_production_flag_enforces_production_checks(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=local\nAPP_DEBUG=true\nAPP_KEY=base64:1234567890=");
        $this->createSandboxFile('.env.example', "APP_ENV=\nAPP_DEBUG=\nAPP_KEY=");

        $this->artisan('scalpel:baseline --force')->assertExitCode(0);

        $this->artisan('scalpel:scan --production')
            ->expectsOutputToContain('APP_DEBUG is enabled')
            ->assertExitCode(1);
    }

    public function test_scan_command_json_format_suppresses_banner_and_progress(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $this->createSandboxFile('.env.example', "APP_ENV=\nAPP_KEY=");
        $this->createBaselineProgrammatically();

        $exitCode = Artisan::call('scalpel:scan', ['--format' => 'json']);
        $this->assertSame(0, $exitCode);

        $output = Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringNotContainsString('Running scanner', $output);
        $this->assertStringContainsString('"total"', $output);
    }

    public function test_scan_command_no_banner_option_suppresses_banner(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $this->createSandboxFile('.env.example', "APP_ENV=\nAPP_KEY=");
        $this->createBaselineProgrammatically();

        $exitCode = Artisan::call('scalpel:scan', ['--no-banner' => true]);
        $this->assertSame(0, $exitCode);

        $output = Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringContainsString('Running scanner', $output);
    }

    public function test_scan_command_no_ansi_option_suppresses_banner(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $this->createSandboxFile('.env.example', "APP_ENV=\nAPP_KEY=");
        $this->createBaselineProgrammatically();

        $exitCode = Artisan::call('scalpel:scan', ['--no-ansi' => true]);
        $this->assertSame(0, $exitCode);

        $output = Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringContainsString('Running scanner', $output);
    }

    public function test_scan_command_config_suppress_banner_suppresses_banner(): void
    {
        config(['scalpel.suppress_banner' => true]);
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $this->createSandboxFile('.env.example', "APP_ENV=\nAPP_KEY=");
        $this->createBaselineProgrammatically();

        $exitCode = Artisan::call('scalpel:scan');
        $this->assertSame(0, $exitCode);

        $output = Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringContainsString('Running scanner', $output);
    }

    private function createBaselineProgrammatically(): void
    {
        /** @var Scalpel $scalpel */
        $scalpel = app(Scalpel::class);

        /** @var BaselineDiffScanner $scanner */
        $scanner = $scalpel->getScanner('Baseline Diff');

        $scanner->createBaseline(base_path());
    }
}
