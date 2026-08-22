<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Data\Severity;
use Hryagstn\Scalpel\Scanners\EnvIntegrityScanner;
use Hryagstn\Scalpel\Tests\TestCase;

class EnvIntegrityScannerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'scalpel.excluded_paths' => ['node_modules', '.git'],
            'scalpel.content_scan_excluded_paths' => ['vendor', 'bootstrap/cache'],
            'scalpel.assume_production' => false,
        ]);
    }

    public function test_flags_missing_env_file(): void
    {
        // No .env file created at all
        $scanner = new EnvIntegrityScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertGreaterThanOrEqual(1, count($findings));
        $this->assertEquals('.env', $findings->all()[0]->file);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('missing', $findings->all()[0]->description);
    }

    public function test_flags_world_readable_permissions(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('Unix file permissions are not supported on Windows.');
        }

        $envPath = $this->tempDir.'/.env';
        file_put_contents($envPath, "APP_ENV=local\nAPP_KEY=base64:1234567890=");

        @chmod($envPath, 0664);

        $perms = fileperms($envPath);
        if ($perms & 0x0004) {
            $scanner = new EnvIntegrityScanner;
            $findings = $scanner->scan($this->tempDir);

            $permissionFindings = array_filter(
                $findings->all(),
                fn ($f) => str_contains($f->description, 'world-readable'),
            );

            $this->assertGreaterThanOrEqual(1, count($permissionFindings));
            $this->assertEquals('HIGH', array_values($permissionFindings)[0]->severity->value);
        }

        @chmod($envPath, 0600);
    }

    public function test_flags_extra_env_keys(): void
    {
        file_put_contents($this->tempDir.'/.env.example', '
            APP_KEY=
            APP_ENV=
        ');

        $envPath = $this->tempDir.'/.env';
        file_put_contents($envPath, '
            APP_KEY=base64:1234567890=
            APP_ENV=local
            STRIPE_SECRET_KEY=sk_test_abc123
            AWS_SECRET_ACCESS_KEY=xyz
        ');
        @chmod($envPath, 0600);

        $scanner = new EnvIntegrityScanner;
        $findings = $scanner->scan($this->tempDir);

        $extraKeyFindings = array_filter(
            $findings->all(),
            fn ($f) => str_contains($f->description, 'not present in .env.example'),
        );

        $this->assertCount(1, $extraKeyFindings);
        $finding = array_values($extraKeyFindings)[0];
        $this->assertEquals('MEDIUM', $finding->severity->value);
        $this->assertStringContainsString('STRIPE_SECRET_KEY', $finding->description);
        $this->assertStringContainsString('AWS_SECRET_ACCESS_KEY', $finding->description);
    }

    public function test_flags_public_env_file(): void
    {
        $envPath = $this->tempDir.'/.env';
        file_put_contents($envPath, "APP_ENV=local\nAPP_KEY=base64:1234567890=");
        @chmod($envPath, 0600);

        @mkdir($this->tempDir.'/public', 0777, true);
        file_put_contents($this->tempDir.'/public/.env', 'APP_ENV=production');

        $scanner = new EnvIntegrityScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertTrue($findings->hasSeverity(Severity::CRITICAL));
        $files = array_map(fn ($f) => $f->file, $findings->all());
        $this->assertContains('public/.env', $files);
    }

    public function test_flags_empty_env_file(): void
    {
        $envPath = $this->tempDir.'/.env';
        file_put_contents($envPath, '');
        @chmod($envPath, 0600);

        $scanner = new EnvIntegrityScanner;
        $findings = $scanner->scan($this->tempDir);

        $emptyFindings = array_filter(
            $findings->all(),
            fn ($f) => str_contains($f->description, 'empty'),
        );

        $this->assertGreaterThanOrEqual(1, count($emptyFindings));
        $finding = array_values($emptyFindings)[0];
        $this->assertEquals('HIGH', $finding->severity->value);
    }

    public function test_flags_missing_keys_vs_example(): void
    {
        file_put_contents($this->tempDir.'/.env.example', '
            APP_KEY=
            APP_ENV=
            APP_DEBUG=
            REDIS_HOST=
        ');

        $envPath = $this->tempDir.'/.env';
        file_put_contents($envPath, '
            APP_KEY=base64:1234567890=
            APP_ENV=local
        ');
        @chmod($envPath, 0600);

        $scanner = new EnvIntegrityScanner;
        $findings = $scanner->scan($this->tempDir);

        $missingKeyFindings = array_filter(
            $findings->all(),
            fn ($f) => str_contains($f->description, 'missing from .env'),
        );

        $this->assertCount(1, $missingKeyFindings);
        $finding = array_values($missingKeyFindings)[0];
        $this->assertEquals('LOW', $finding->severity->value);
        $this->assertStringContainsString('APP_DEBUG', $finding->description);
        $this->assertStringContainsString('REDIS_HOST', $finding->description);
    }

    public function test_clean_env_produces_no_findings(): void
    {
        file_put_contents($this->tempDir.'/.env.example', '
            APP_KEY=
            APP_ENV=
            APP_DEBUG=
        ');

        $envPath = $this->tempDir.'/.env';
        file_put_contents($envPath, '
            APP_KEY=base64:abc123
            APP_ENV=production
            APP_DEBUG=false
        ');
        @chmod($envPath, 0600);

        $scanner = new EnvIntegrityScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_flags_missing_app_key(): void
    {
        $envPath = $this->tempDir.'/.env';
        file_put_contents($envPath, 'APP_ENV=local');
        @chmod($envPath, 0600);

        $scanner = new EnvIntegrityScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertTrue($findings->hasSeverity(Severity::CRITICAL));
        $descriptions = array_map(fn ($f) => $f->description, $findings->all());
        $this->assertTrue(collect($descriptions)->contains(fn ($d) => str_contains((string) $d, 'APP_KEY is missing')));
    }

    public function test_flags_app_debug_true_in_production(): void
    {
        $envPath = $this->tempDir.'/.env';
        file_put_contents($envPath, "APP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=base64:1234567890=");
        @chmod($envPath, 0600);

        $scanner = new EnvIntegrityScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertTrue($findings->hasSeverity(Severity::HIGH));
        $descriptions = array_map(fn ($f) => $f->description, $findings->all());
        $this->assertTrue(collect($descriptions)->contains(fn ($d) => str_contains((string) $d, 'APP_DEBUG is enabled')));
    }

    public function test_flags_assume_production_with_local_env(): void
    {
        config(['scalpel.assume_production' => true]);

        $envPath = $this->tempDir.'/.env';
        file_put_contents($envPath, "APP_ENV=local\nAPP_DEBUG=false\nAPP_KEY=base64:1234567890=");
        @chmod($envPath, 0600);

        $scanner = new EnvIntegrityScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertTrue($findings->hasSeverity(Severity::MEDIUM));
        $descriptions = array_map(fn ($f) => $f->description, $findings->all());
        $this->assertTrue(collect($descriptions)->contains(fn ($d) => str_contains((string) $d, 'APP_ENV is set to "local"')));
    }
}
