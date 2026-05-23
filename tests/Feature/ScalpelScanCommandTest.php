<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Feature;

use Hryagstn\Scalpel\Tests\TestCase;

class ScalpelScanCommandTest extends TestCase
{
    private array $createdFiles = [];

    protected function setUp(): void
    {
        parent::setUp();

        \Illuminate\Support\Facades\Storage::fake('local');

        config([
            'scalpel.non_php_zones' => ['public'],
            'scalpel.structural_allowed_files' => ['public/index.php'],
            'scalpel.excluded_paths' => ['vendor', 'node_modules', '.git'],
            'scalpel.baseline_excluded_paths' => ['storage', 'bootstrap'],
            'scalpel.severity_threshold' => 'LOW',
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

        if (!is_dir($dir)) {
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
        // Make sure no anomalous files exist, but we must make sure .env exists to avoid CRITICAL finding in EnvIntegrityScanner
        $this->createSandboxFile('.env', 'APP_ENV=testing');
        $this->createSandboxFile('.env.example', 'APP_ENV=');

        // Create baseline to satisfy BaselineDiffScanner
        $this->artisan('scalpel:baseline --force')->assertExitCode(0);

        $this->artisan('scalpel:scan')
            ->expectsOutputToContain('Running scanner: Structural Anomaly')
            ->expectsOutputToContain('No findings detected')
            ->assertExitCode(0);
    }

    public function test_scan_command_fails_when_intrusion_detected(): void
    {
        // Add anomalous PHP file in public/
        $this->createSandboxFile('public/backdoor.php', '<?php eval($_POST["cmd"]);');
        $this->createSandboxFile('.env', 'APP_ENV=testing');

        // Create baseline to satisfy BaselineDiffScanner
        $this->artisan('scalpel:baseline --force')->assertExitCode(0);

        $this->artisan('scalpel:scan')
            ->expectsOutputToContain('Structural Anomaly')
            ->expectsOutputToContain('backdoor.php')
            ->assertExitCode(1); // Exit code 1 due to HIGH severity finding
    }

    public function test_scan_command_json_output(): void
    {
        // Use an obfuscated pattern to trigger ObfuscatedCodeScanner (CRITICAL) and StructuralAnomalyScanner (HIGH)
        $this->createSandboxFile('public/backdoor.php', '<?php eval(base64_decode($_POST["cmd"]));');
        $this->createSandboxFile('.env', 'APP_ENV=testing');

        // Create baseline to satisfy BaselineDiffScanner
        $this->artisan('scalpel:baseline --force')->assertExitCode(0);

        $this->artisan('scalpel:scan --format=json')
            ->expectsOutputToContain('"total": 2') // backdoor.php (Structural) + backdoor.php (Obfuscated)
            ->assertExitCode(1);
    }

    public function test_scan_command_only_flag(): void
    {
        $this->createSandboxFile('.env', 'APP_ENV=testing');

        $this->artisan('scalpel:scan --only=structural')
            ->expectsOutputToContain('Running scanner: Structural Anomaly')
            ->doesntExpectOutput('Running scanner: Obfuscated Code')
            ->assertExitCode(0);
    }
}
