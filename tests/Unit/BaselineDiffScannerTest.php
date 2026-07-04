<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Hryagstn\Scalpel\Tests\TestCase;
use Illuminate\Support\Facades\Storage;

class BaselineDiffScannerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        config([
            'scalpel.excluded_paths' => ['vendor', 'node_modules', '.git'],
            'scalpel.baseline_excluded_paths' => ['storage/logs', 'storage/app/scalpel'],
            'scalpel.baseline_path' => 'scalpel/baseline.json',
        ]);
    }

    public function test_creates_baseline_and_detects_changes(): void
    {
        $scanner = new BaselineDiffScanner();

        // 1. Setup initial project filesystem state
        @mkdir($this->tempDir . '/app', 0777, true);
        file_put_contents($this->tempDir . '/app/User.php', '<?php class User {}');
        file_put_contents($this->tempDir . '/app/Helper.php', '<?php class Helper {}');
        file_put_contents($this->tempDir . '/.env', 'APP_ENV=local');

        // 2. Create the baseline
        $stats = $scanner->createBaseline($this->tempDir);

        $this->assertEquals(3, $stats['files']);
        Storage::assertExists('scalpel/baseline.json');

        // 3. Scan without changes (should return 0 findings)
        $findings = $scanner->scan($this->tempDir);
        $this->assertCount(0, $findings);

        // 4. Modify a file, add a new file, and delete a file
        file_put_contents($this->tempDir . '/app/User.php', '<?php class User { /* modified */ }'); // MODIFIED
        file_put_contents($this->tempDir . '/app/NewFile.php', '<?php class NewFile {}'); // NEW PHP (HIGH severity)
        file_put_contents($this->tempDir . '/non-php.txt', 'Hello world'); // NEW text file (MEDIUM severity)
        @unlink($this->tempDir . '/app/Helper.php'); // DELETED PHP (MEDIUM severity)
        @unlink($this->tempDir . '/.env'); // DELETED .env (CRITICAL severity)

        // 5. Scan and assert findings
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(5, $findings);

        $modifiedUser = null;
        $newPhp = null;
        $newTxt = null;
        $deletedHelper = null;
        $deletedEnv = null;

        foreach ($findings as $finding) {
            if ($finding->file === 'app/User.php') {
                $modifiedUser = $finding;
            } elseif ($finding->file === 'app/NewFile.php') {
                $newPhp = $finding;
            } elseif ($finding->file === 'non-php.txt') {
                $newTxt = $finding;
            } elseif ($finding->file === 'app/Helper.php') {
                $deletedHelper = $finding;
            } elseif ($finding->file === '.env') {
                $deletedEnv = $finding;
            }
        }

        $this->assertNotNull($modifiedUser);
        $this->assertEquals('HIGH', $modifiedUser->severity->value);
        $this->assertStringContainsString('modified since baseline', $modifiedUser->description);

        $this->assertNotNull($newPhp);
        $this->assertEquals('HIGH', $newPhp->severity->value);
        $this->assertStringContainsString('New file detected', $newPhp->description);

        $this->assertNotNull($newTxt);
        $this->assertEquals('MEDIUM', $newTxt->severity->value);

        $this->assertNotNull($deletedHelper);
        $this->assertEquals('MEDIUM', $deletedHelper->severity->value);
        $this->assertStringContainsString('deleted since baseline', $deletedHelper->description);

        $this->assertNotNull($deletedEnv);
        $this->assertEquals('CRITICAL', $deletedEnv->severity->value);
    }

    public function test_progress_callback_is_triggered_during_baseline_creation_and_scan(): void
    {
        $scanner = new BaselineDiffScanner();

        @mkdir($this->tempDir . '/app', 0777, true);
        file_put_contents($this->tempDir . '/app/User.php', '<?php class User {}');
        file_put_contents($this->tempDir . '/app/Helper.php', '<?php class Helper {}');

        // Test progress during creation
        $creationEvents = [];
        $scanner->setProgressCallback(function (string $event, array $data = []) use (&$creationEvents) {
            $creationEvents[] = [$event, $data];
        });

        $scanner->createBaseline($this->tempDir);

        $this->assertNotEmpty($creationEvents);
        $this->assertEquals('start', $creationEvents[0][0]);
        $this->assertEquals(2, $creationEvents[0][1]['total']);
        
        $advanceEvents = array_filter($creationEvents, fn($e) => $e[0] === 'advance');
        $this->assertCount(2, $advanceEvents);

        $finishEvent = end($creationEvents);
        $this->assertEquals('finish', $finishEvent[0]);

        // Test progress during scan (comparison)
        $scanEvents = [];
        $scanner->setProgressCallback(function (string $event, array $data = []) use (&$scanEvents) {
            $scanEvents[] = [$event, $data];
        });

        $scanner->scan($this->tempDir);

        $this->assertNotEmpty($scanEvents);
        $this->assertEquals('start', $scanEvents[0][0]);
        $this->assertEquals(2, $scanEvents[0][1]['total']);

        $scanAdvanceEvents = array_filter($scanEvents, fn($e) => $e[0] === 'advance');
        $this->assertCount(2, $scanAdvanceEvents);

        $scanFinishEvent = end($scanEvents);
        $this->assertEquals('finish', $scanFinishEvent[0]);
    }

    public function test_handles_broken_symlinks_safely(): void
    {
        $scanner = new BaselineDiffScanner();

        @mkdir($this->tempDir . '/app', 0777, true);
        file_put_contents($this->tempDir . '/app/User.php', '<?php class User {}');

        // Create a broken symlink in the project root
        @symlink($this->tempDir . '/non_existent_file.php', $this->tempDir . '/broken_link.php');

        // 1. Baseline creation should complete without TypeError or failure
        $stats = $scanner->createBaseline($this->tempDir);
        $this->assertEquals(1, $stats['files']); // Only app/User.php, broken link is ignored

        // 2. Scan should complete and find 0 findings
        $findings = $scanner->scan($this->tempDir);
        $this->assertCount(0, $findings);

        // Clean up symlink specifically
        @unlink($this->tempDir . '/broken_link.php');
    }
}
