<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\StructuralAnomalyScanner;
use Hryagstn\Scalpel\Tests\TestCase;

class StructuralAnomalyScannerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Setup mock configurations
        config(['scalpel.non_php_zones' => ['public', 'storage', 'bootstrap/cache']]);
        config(['scalpel.structural_allowed_files' => ['public/index.php']]);
        config(['scalpel.structural_allowed_directories' => ['public/vendor']]);
        config(['scalpel.excluded_paths' => ['vendor', 'node_modules', '.git']]);
    }

    public function test_flags_php_files_in_non_php_zones(): void
    {
        // Create temp directories
        @mkdir($this->tempDir.'/public', 0777, true);
        @mkdir($this->tempDir.'/storage/app', 0777, true);
        @mkdir($this->tempDir.'/bootstrap/cache', 0777, true);

        // Put legitimate/allowed file
        file_put_contents($this->tempDir.'/public/index.php', '<?php echo "Hello";');

        // Put anomalous PHP files
        file_put_contents($this->tempDir.'/public/malicious.php', '<?php eval($_GET["cmd"]);');
        file_put_contents($this->tempDir.'/storage/app/backdoor.php', '<?php phpinfo();');
        file_put_contents($this->tempDir.'/bootstrap/cache/evil.php', '<?php system("whoami");');

        // Put non-PHP files in non-PHP zones (should not be flagged)
        file_put_contents($this->tempDir.'/public/styles.css', 'body {}');
        file_put_contents($this->tempDir.'/storage/app/data.txt', 'some text');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(3, $findings);

        $files = array_map(fn ($f) => $f->file, $findings->all());
        $this->assertContains('public/malicious.php', $files);
        $this->assertContains('storage/app/backdoor.php', $files);
        $this->assertContains('bootstrap/cache/evil.php', $files);
        $this->assertNotContains('public/index.php', $files);
    }

    public function test_respects_allowed_directories(): void
    {
        @mkdir($this->tempDir.'/public/vendor/package', 0777, true);
        file_put_contents($this->tempDir.'/public/vendor/package/asset.php', '<?php return [];');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_always_excludes_laravel_framework_directories(): void
    {
        // storage/framework/views contains compiled Blade templates (legitimate PHP files)
        // storage/framework/cache contains real-time facade cache files (legitimate PHP files)
        // These should NEVER be flagged, even if user config doesn't list them
        @mkdir($this->tempDir.'/storage/framework/views', 0777, true);
        @mkdir($this->tempDir.'/storage/framework/cache', 0777, true);

        // Create compiled Blade view files (empty and non-empty)
        file_put_contents($this->tempDir.'/storage/framework/views/abc123.php', '');
        file_put_contents($this->tempDir.'/storage/framework/views/def456.php', '<?php echo "compiled blade";');

        // Create real-time facade cache files
        file_put_contents($this->tempDir.'/storage/framework/cache/facade-1e06026dbe325cba543b.php', '<?php

namespace Facades\App\Services;

use Illuminate\Support\Facades\Facade;

class MyService extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \'App\Services\MyService\';
    }
}
');

        // Also create a real anomaly elsewhere in storage to make sure scanning still works
        @mkdir($this->tempDir.'/storage/app', 0777, true);
        file_put_contents($this->tempDir.'/storage/app/backdoor.php', '<?php eval("bad");');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $files = array_map(fn ($f) => $f->file, $findings->all());

        // Compiled Blade views should NOT be flagged
        $this->assertNotContains('storage/framework/views/abc123.php', $files);
        $this->assertNotContains('storage/framework/views/def456.php', $files);

        // Real-time facade caches should NOT be flagged
        $this->assertNotContains('storage/framework/cache/facade-1e06026dbe325cba543b.php', $files);

        // But real anomalies in storage should still be flagged
        $this->assertContains('storage/app/backdoor.php', $files);
        $this->assertCount(1, $findings);
    }

    public function test_handles_broken_symlinks_safely(): void
    {
        @mkdir($this->tempDir.'/public', 0777, true);
        @symlink($this->tempDir.'/non_existent_file.php', $this->tempDir.'/public/test.php');

        $scanner = new StructuralAnomalyScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);

        @unlink($this->tempDir.'/public/test.php');
    }
}
