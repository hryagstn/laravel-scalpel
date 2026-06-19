<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Feature;

use Hryagstn\Scalpel\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Storage;

class ScalpelVerifyCommandTest extends TestCase
{
    private array $createdFiles = [];

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        config([
            'scalpel.non_php_zones'               => ['public'],
            'scalpel.structural_allowed_files'     => ['public/index.php'],
            'scalpel.excluded_paths'               => ['node_modules', '.git'],
            'scalpel.content_scan_excluded_paths'  => ['vendor', 'bootstrap/cache'],
            'scalpel.baseline_excluded_paths'      => ['storage', 'bootstrap'],
            'scalpel.severity_threshold'           => 'LOW',
        ]);
    }

    protected function tearDown(): void
    {
        foreach ($this->createdFiles as $file) {
            if (file_exists($file)) {
                @unlink($file);
            }
        }

        parent::tearDown();
    }

    private function createSandboxFile(string $relativePath, string $content): string
    {
        $path = base_path($relativePath);
        $dir  = dirname($path);

        if (! is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        file_put_contents($path, $content);

        if ($relativePath === '.env') {
            @chmod($path, 0600);
        }

        $this->createdFiles[] = $path;
        return $path;
    }

    public function test_scan_produces_unsigned_json_when_disabled(): void
    {
        $this->createSandboxFile('.env', 'APP_ENV=testing');
        $this->createSandboxFile('.env.example', 'APP_ENV=');
        
        // Ensure baseline diff is clean
        $scalpel = app(\Hryagstn\Scalpel\Scalpel::class);
        $scalpel->getScanner('Baseline Diff')->createBaseline(base_path());

        config(['scalpel.signing.enabled' => false]);

        $exitCode = Artisan::call('scalpel:scan', ['--format' => 'json']);
        $this->assertSame(0, $exitCode);

        $output = Artisan::output();
        $this->assertStringNotContainsString('"signature"', $output);
        
        $data = json_decode($output, true);
        $this->assertArrayHasKey('total', $data);
        $this->assertArrayHasKey('findings', $data);
        $this->assertArrayNotHasKey('signature', $data);
    }

    public function test_scan_produces_signed_json_when_enabled(): void
    {
        $this->createSandboxFile('.env', 'APP_ENV=testing');
        $this->createSandboxFile('.env.example', 'APP_ENV=');
        
        // Ensure baseline diff is clean
        $scalpel = app(\Hryagstn\Scalpel\Scalpel::class);
        $scalpel->getScanner('Baseline Diff')->createBaseline(base_path());

        config([
            'scalpel.signing.enabled' => true,
            'scalpel.signing.key' => 'secret-test-key',
        ]);

        $exitCode = Artisan::call('scalpel:scan', ['--format' => 'json']);
        $this->assertSame(0, $exitCode);

        $output = Artisan::output();
        $this->assertStringContainsString('"signature"', $output);

        $data = json_decode($output, true);
        $this->assertArrayHasKey('signature', $data);
        $signature = $data['signature'];

        // Recompute signature to verify correctness
        unset($data['signature']);
        $canonicalJson = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $expectedSignature = hash_hmac('sha256', $canonicalJson, 'secret-test-key');

        $this->assertSame($expectedSignature, $signature);
    }

    public function test_scan_throws_exception_when_signing_enabled_but_key_missing(): void
    {
        $this->createSandboxFile('.env', 'APP_ENV=testing');
        
        config([
            'scalpel.signing.enabled' => true,
            'scalpel.signing.key' => null,
        ]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Scalpel signing is enabled but the signing key (SCALPEL_SIGNING_KEY) is not configured.');

        Artisan::call('scalpel:scan', ['--format' => 'json']);
    }

    public function test_verify_command_validates_correct_signature(): void
    {
        config([
            'scalpel.signing.key' => 'secret-test-key',
        ]);

        $payload = [
            'total' => 0,
            'findings' => [],
        ];
        $canonicalJson = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $signature = hash_hmac('sha256', $canonicalJson, 'secret-test-key');
        $payload['signature'] = $signature;

        $signedJson = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $filePath = $this->createSandboxFile('storage/scalpel-test.json', $signedJson);

        $exitCode = Artisan::call('scalpel:verify', ['file' => $filePath]);
        $this->assertSame(0, $exitCode);

        $output = Artisan::output();
        $this->assertStringContainsString('verified successfully', $output);
    }

    public function test_verify_command_fails_on_tampered_payload(): void
    {
        config([
            'scalpel.signing.key' => 'secret-test-key',
        ]);

        $payload = [
            'total' => 0,
            'findings' => [],
        ];
        $canonicalJson = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $signature = hash_hmac('sha256', $canonicalJson, 'secret-test-key');
        $payload['signature'] = $signature;

        // Tamper payload after signing
        $payload['total'] = 1;

        $signedJson = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $filePath = $this->createSandboxFile('storage/scalpel-test.json', $signedJson);

        $exitCode = Artisan::call('scalpel:verify', ['file' => $filePath]);
        $this->assertSame(1, $exitCode);

        $output = Artisan::output();
        $this->assertStringContainsString('Signature verification failed', $output);
    }

    public function test_verify_command_fails_when_signature_is_missing(): void
    {
        $payload = [
            'total' => 0,
            'findings' => [],
        ];
        $unsignedJson = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $filePath = $this->createSandboxFile('storage/scalpel-test.json', $unsignedJson);

        $exitCode = Artisan::call('scalpel:verify', ['file' => $filePath]);
        $this->assertSame(1, $exitCode);

        $output = Artisan::output();
        $this->assertStringContainsString('Signature missing', $output);
    }

    public function test_verify_command_fails_when_file_not_found(): void
    {
        $exitCode = Artisan::call('scalpel:verify', ['file' => 'nonexistent.json']);
        $this->assertSame(1, $exitCode);

        $output = Artisan::output();
        $this->assertStringContainsString('File not found', $output);
    }
}
