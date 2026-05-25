<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\EnvIntegrityScanner;
use Hryagstn\Scalpel\Tests\TestCase;

class EnvIntegrityScannerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'scalpel.excluded_paths'              => ['node_modules', '.git'],
            'scalpel.content_scan_excluded_paths' => ['vendor', 'bootstrap/cache'],
        ]);
    }

    public function test_flags_missing_env_file(): void
    {
        // No .env file created at all
        $scanner  = new EnvIntegrityScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('.env', $findings->all()[0]->file);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('missing', $findings->all()[0]->description);
    }

    public function test_flags_world_readable_permissions(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('Unix file permissions are not supported on Windows.');
        }

        $envPath = $this->tempDir . '/.env';
        file_put_contents($envPath, 'APP_ENV=local');

        @chmod($envPath, 0664);

        $perms = fileperms($envPath);
        if ($perms & 0x0004) {
            $scanner  = new EnvIntegrityScanner();
            $findings = $scanner->scan($this->tempDir);

            $this->assertTrue($findings->hasSeverity(\Hryagstn\Scalpel\Data\Severity::HIGH));
        }
    }

    public function test_flags_extra_env_keys(): void
    {
        file_put_contents($this->tempDir . '/.env.example', "
            APP_KEY=
            APP_ENV=
        ");

        $envPath = $this->tempDir . '/.env';
        file_put_contents($envPath, "
            APP_KEY=123
            APP_ENV=local
            STRIPE_SECRET_KEY=sk_test_abc123
            AWS_SECRET_ACCESS_KEY=xyz
        ");
        @chmod($envPath, 0600);

        $scanner  = new EnvIntegrityScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('MEDIUM', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('STRIPE_SECRET_KEY', $findings->all()[0]->description);
        $this->assertStringContainsString('AWS_SECRET_ACCESS_KEY', $findings->all()[0]->description);
    }

    public function test_flags_public_env_file(): void
    {
        $envPath = $this->tempDir . '/.env';
        file_put_contents($envPath, 'APP_ENV=local');
        @chmod($envPath, 0600);

        @mkdir($this->tempDir . '/public', 0777, true);
        file_put_contents($this->tempDir . '/public/.env', 'APP_ENV=production');

        $scanner  = new EnvIntegrityScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertTrue($findings->hasSeverity(\Hryagstn\Scalpel\Data\Severity::CRITICAL));
        $files = array_map(fn ($f) => $f->file, $findings->all());
        $this->assertContains('public/.env', $files);
    }
}