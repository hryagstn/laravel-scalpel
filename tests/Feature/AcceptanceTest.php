<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Feature;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;
use Hryagstn\Scalpel\Events\ScanFinished;
use Hryagstn\Scalpel\Scalpel;
use Hryagstn\Scalpel\Scanners\BaselineDiffScanner;
use Hryagstn\Scalpel\Scanners\BaseScanner;
use Hryagstn\Scalpel\Scanners\ObfuscatedCodeScanner;
use Hryagstn\Scalpel\Tests\TestCase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Storage;

class AcceptanceTest extends TestCase
{
    /** @var string[] */
    private array $createdFiles = [];

    /** @var string[] */
    private array $createdDirs = [];

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
            if (file_exists($file) || is_link($file)) {
                @chmod($file, 0644);
                @unlink($file);
            }
        }

        // Restore dir permissions and remove
        foreach (array_reverse($this->createdDirs) as $dir) {
            if (is_dir($dir)) {
                @chmod($dir, 0777);
                @rmdir($dir);
            }
        }

        parent::tearDown();
    }

    private function createSandboxFile(string $relativePath, string $content): string
    {
        $path = base_path($relativePath);
        $dir = dirname($path);

        if (! is_dir($dir)) {
            @mkdir($dir, 0777, true);
            $this->createdDirs[] = $dir;
        }

        file_put_contents($path, $content);
        $this->createdFiles[] = $path;

        return $path;
    }

    private function createSandboxDir(string $relativePath): string
    {
        $path = base_path($relativePath);
        if (! is_dir($path)) {
            @mkdir($path, 0777, true);
            $this->createdDirs[] = $path;
        }

        return $path;
    }

    /**
     * Test 1: Baseline snapshot remains identical when createBaseline fails.
     */
    public function test_baseline_snapshot_preserved_on_creation_failure(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $this->createSandboxFile('app/Valid.php', '<?php class Valid {}');

        $this->artisan('scalpel:baseline --force')->assertExitCode(0);

        $baselinePath = config('scalpel.baseline_path', 'scalpel/baseline.json');
        $originalBaseline = Storage::disk('local')->get($baselinePath);
        $this->assertNotNull($originalBaseline);

        // Create an unreadable subdirectory
        $unreadableDir = $this->createSandboxDir('app/unreadable_sub');
        file_put_contents($unreadableDir.'/File.php', '<?php class File {}');
        $this->createdFiles[] = $unreadableDir.'/File.php';
        @chmod($unreadableDir, 0000);

        if (@scandir($unreadableDir) === false) {
            // Attempt baseline recreation
            $scanner = new BaselineDiffScanner;
            $failed = false;

            try {
                $scanner->createBaseline(base_path());
            } catch (\RuntimeException) {
                $failed = true;
            }

            @chmod($unreadableDir, 0777);

            $this->assertTrue($failed, 'Expected createBaseline to throw RuntimeException when traversal fails.');

            // Assert baseline content was NOT overwritten
            $currentBaseline = Storage::disk('local')->get($baselinePath);
            $this->assertSame($originalBaseline, $currentBaseline);
        } else {
            @chmod($unreadableDir, 0777);
            $this->markTestSkipped('Filesystem does not honor chmod 0000 in this environment.');
        }
    }

    /**
     * Test 2: Unreadable subtree does NOT produce false deleted findings.
     */
    public function test_unreadable_subtree_does_not_produce_deleted_finding(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $this->createSandboxFile('app/sub/Important.php', '<?php class Important {}');

        $this->artisan('scalpel:baseline --force')->assertExitCode(0);

        $subDir = base_path('app/sub');
        @chmod($subDir, 0000);

        if (@scandir($subDir) === false) {
            $scanner = new BaselineDiffScanner;
            $findings = $scanner->scan(base_path());

            @chmod($subDir, 0777);

            // Assert no DELETED finding was produced
            foreach ($findings->all() as $finding) {
                $this->assertStringNotContainsString(
                    'deleted',
                    strtolower($finding->description),
                    "Unreadable file was falsely reported as deleted: {$finding->file}",
                );
            }

            // Assert operational error was recorded
            $this->assertTrue($findings->hasErrors());
            $this->assertSame('partial', $findings->status());
        } else {
            @chmod($subDir, 0777);
            $this->markTestSkipped('Filesystem does not honor chmod 0000 in this environment.');
        }
    }

    /**
     * Test 3: Operational metadata is preserved through severity filtering and reaches output.
     */
    public function test_operational_metadata_preserved_through_severity_filter(): void
    {
        Event::fake([ScanFinished::class]);

        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        // An unreadable htaccess produces operational error
        $htaccess = $this->createSandboxFile('public/.htaccess', 'AddHandler cgi-script .py');
        @chmod($htaccess, 0000);

        if (@fopen($htaccess, 'r') === false) {
            $this->artisan('scalpel:scan --only=htaccess --fail-on=CRITICAL --format=json')
                ->assertExitCode(2)
                ->execute();

            @chmod($htaccess, 0644);

            Event::assertDispatched(ScanFinished::class, function (ScanFinished $event) {
                return $event->findings->status() === 'partial'
                    && $event->findings->hasErrors()
                    && $event->findings->skippedFilesCount() === 1;
            });
        } else {
            @chmod($htaccess, 0644);
            $this->markTestSkipped('Filesystem does not honor chmod 0000 in this environment.');
        }
    }

    /**
     * Test 4: File > 2MB produces operational error and partial status.
     */
    public function test_large_file_over_2mb_produces_operational_error(): void
    {
        $largeFile = base_path('app/large.php');
        $fh = fopen($largeFile, 'w');
        $this->assertNotFalse($fh);
        fwrite($fh, "<?php\n// ".str_repeat('A', 2500000)."\n");
        fclose($fh);
        $this->createdFiles[] = $largeFile;

        $scanner = new ObfuscatedCodeScanner;
        $findings = $scanner->scan(base_path());

        $this->assertTrue($findings->hasErrors());
        $this->assertSame('partial', $findings->status());
        $this->assertSame(1, $findings->skippedFilesCount());

        $errors = $findings->errors();
        $this->assertNotEmpty($errors);
        $this->assertStringContainsString('exceeds maximum scan size limit', $errors[0]['error']);
    }

    /**
     * Test 5: Progress callback cleanup via finally and scanner reuse.
     */
    public function test_progress_callback_cleanup_on_exception(): void
    {
        $failingScanner = new class extends BaseScanner
        {
            public function name(): string
            {
                return 'FailingScanner';
            }

            public function scan(string $basePath): FindingCollection
            {
                $this->notifyProgress('start', ['total' => 10]);
                throw new \RuntimeException('Unexpected scanner failure mid-run');
            }

            public function getProgressCallback(): ?\Closure
            {
                return $this->progressCallback;
            }
        };

        $scalpel = new Scalpel([$failingScanner]);
        $this->app->instance(Scalpel::class, $scalpel);

        // Run scanner via command
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $this->artisan('scalpel:scan')
            ->assertExitCode(2)
            ->execute();

        // Verify progress callback was reset to null
        $this->assertNull($failingScanner->getProgressCallback());
    }

    /**
     * Test 6: SARIF output contains valid notifications, properties, and schema.
     */
    public function test_sarif_output_contains_notifications_and_properties(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $htaccess = $this->createSandboxFile('public/.htaccess', 'AddHandler cgi-script .py');
        @chmod($htaccess, 0000);

        if (@fopen($htaccess, 'r') === false) {
            $exitCode = Artisan::call('scalpel:scan', [
                '--only' => 'htaccess',
                '--format' => 'sarif',
            ]);
            $this->assertSame(2, $exitCode);

            $output = Artisan::output();
            @chmod($htaccess, 0644);

            $this->assertNotEmpty($output);
            /** @var array{'$schema'?: string, version?: string, runs?: array<int, array{invocations?: array<int, array{executionSuccessful?: bool, toolExecutionNotifications?: array<int, array{level?: string, message?: array{text?: string}}>, properties?: array<string, mixed>}>}>} $sarif */
            $sarif = json_decode($output, true);
            $this->assertIsArray($sarif);
            $this->assertSame('https://json.schemastore.org/sarif-2.1.0.json', $sarif['$schema'] ?? null);
            $this->assertSame('2.1.0', $sarif['version'] ?? null);
            $this->assertArrayHasKey('runs', $sarif);
            $this->assertNotEmpty($sarif['runs']);

            $run = $sarif['runs'][0];
            $this->assertArrayHasKey('invocations', $run);
            $this->assertNotEmpty($run['invocations']);

            $invocation = $run['invocations'][0];
            $this->assertFalse($invocation['executionSuccessful'] ?? true);
            $this->assertArrayHasKey('toolExecutionNotifications', $invocation);
            $this->assertNotEmpty($invocation['toolExecutionNotifications']);

            $notification = $invocation['toolExecutionNotifications'][0];
            $this->assertSame('error', $notification['level'] ?? null);
            $this->assertStringContainsString('Unable to open .htaccess', $notification['message']['text'] ?? '');
            $this->assertSame('public/.htaccess', $notification['locations'][0]['physicalLocation']['artifactLocation']['uri'] ?? null);

            $this->assertArrayHasKey('properties', $invocation);
            $props = $invocation['properties'];
            $this->assertSame('partial', $props['status'] ?? null);
            $this->assertSame(1, $props['skippedFiles'] ?? null);
            $this->assertSame(0, $props['skippedDirectories'] ?? null);
            $this->assertArrayHasKey('scannedFiles', $props);
        } else {
            @chmod($htaccess, 0644);
            $this->markTestSkipped('Filesystem does not honor chmod 0000 in this environment.');
        }
    }

    /**
     * Test 7: SARIF output correctly omits region for line-less findings and preserves it for line findings.
     */
    public function test_sarif_output_valid_for_findings_with_and_without_line_numbers(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        // Finding with line: obfuscated payload
        $this->createSandboxFile('app/Malicious.php', "<?php\n\n\neval(base64_decode('cGhwaW5mbygpOw=='));\n");
        // Finding without line: .user.ini
        $this->createSandboxFile('public/.user.ini', "auto_prepend_file = evil.php\n");

        $exitCode = Artisan::call('scalpel:scan', ['--format' => 'sarif']);
        $this->assertSame(1, $exitCode);

        $output = Artisan::output();
        $this->assertNotEmpty($output);
        $sarif = json_decode($output, true);
        $this->assertIsArray($sarif);
        $this->assertSame('https://json.schemastore.org/sarif-2.1.0.json', $sarif['$schema'] ?? null);
        $this->assertSame('2.1.0', $sarif['version'] ?? null);

        $results = $sarif['runs'][0]['results'] ?? [];
        $this->assertNotEmpty($results);

        $foundWithLine = false;
        $foundWithoutLine = false;

        foreach ($results as $result) {
            $this->assertArrayHasKey('ruleId', $result);
            $this->assertContains($result['level'], ['error', 'warning', 'note', 'none']);
            $this->assertArrayHasKey('text', $result['message']);
            $this->assertNotEmpty($result['locations']);

            foreach ($result['locations'] as $loc) {
                $physical = $loc['physicalLocation'];
                $this->assertArrayHasKey('artifactLocation', $physical);
                $this->assertNotEmpty($physical['artifactLocation']['uri']);

                // Critical SARIF compliance: region must NEVER be an empty array []
                if (array_key_exists('region', $physical)) {
                    $foundWithLine = true;
                    $region = $physical['region'];
                    $this->assertIsArray($region);
                    $this->assertArrayHasKey('startLine', $region);
                    $this->assertGreaterThan(0, $region['startLine']);
                } else {
                    $foundWithoutLine = true;
                }
            }
        }

        $this->assertTrue($foundWithLine, 'Expected at least one SARIF result with region.');
        $this->assertTrue($foundWithoutLine, 'Expected at least one SARIF result without region.');
    }

    /**
     * Test 8: --only=htaccess runs both HtaccessScanner and UserIniScanner without duplication.
     */
    public function test_only_htaccess_flag_runs_both_htaccess_and_user_ini(): void
    {
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $this->createSandboxFile('public/.htaccess', 'AddHandler cgi-script .py');
        $this->createSandboxFile('public/.user.ini', 'auto_prepend_file = shell.php');

        // Running --only=htaccess should detect both .htaccess and .user.ini
        $this->artisan('scalpel:scan --only=htaccess')
            ->expectsOutputToContain('cgi-script')
            ->expectsOutputToContain('auto_prepend_file')
            ->assertExitCode(1);

        // Running default scan should have each scanner run exactly once without duplication
        $scalpel = app(Scalpel::class);
        $scanners = $scalpel->getScanners();
        $names = array_map(fn ($s) => $s->name(), $scanners);
        $this->assertSame($names, array_unique($names));
    }

    /**
     * Test 8: Aggregate status logic, symlink traversal, and baseline path preservation.
     */
    public function test_aggregate_status_and_symlink_traversal(): void
    {
        $c1 = (new FindingCollection)->setScannerStatus('Scan1', 'complete');
        $c2 = (new FindingCollection)->setScannerStatus('Scan2', 'failed');
        $c1->merge($c2);
        $this->assertSame('partial', $c1->status());

        $cAllFailed = (new FindingCollection)
            ->setScannerStatus('Scan1', 'failed')
            ->setScannerStatus('Scan2', 'failed');
        $this->assertSame('failed', $cAllFailed->status());

        // External symlink traversal
        $externalDir = $this->tempDir.'/external_dir';
        @mkdir($externalDir, 0777, true);
        file_put_contents($externalDir.'/test.php', "<?php\n// original symlinked file\n");

        $symlink = base_path('public/symlink_dir');
        @symlink($externalDir, $symlink);
        $this->createdFiles[] = $symlink;

        $scanner = new BaselineDiffScanner;
        $this->createSandboxFile('.env', "APP_ENV=testing\nAPP_KEY=base64:1234567890=");
        $scanner->createBaseline(base_path());

        // Verify baseline file map contains the logical project-relative path
        $baselinePath = config('scalpel.baseline_path', 'scalpel/baseline.json');
        /** @var array{files: array<string, array{hash: string, size: int}>} $loadedBaseline */
        $loadedBaseline = json_decode(Storage::disk('local')->get($baselinePath) ?? '', true);
        $this->assertIsArray($loadedBaseline);
        $this->assertArrayHasKey('public/symlink_dir/test.php', $loadedBaseline['files']);

        // Assert no external physical path is present in baseline snapshot keys
        foreach (array_keys($loadedBaseline['files']) as $fileKey) {
            $this->assertStringNotContainsString($externalDir, $fileKey);
            $this->assertStringNotContainsString('/private/var', $fileKey);
        }

        // Modify the file behind the symlink
        file_put_contents($externalDir.'/test.php', "<?php\n// modified content\n");

        // Scan and verify the modified file is detected at the relative path
        $findings = $scanner->scan(base_path());
        $modifiedFindings = array_filter(
            $findings->all(),
            fn ($f) => $f->file === 'public/symlink_dir/test.php' && str_contains($f->description, 'hash mismatch')
        );
        $this->assertNotEmpty($modifiedFindings, 'Expected modified finding for file inside symlinked directory.');

        @unlink($symlink);
        @unlink($externalDir.'/test.php');
        @rmdir($externalDir);
    }

    /**
     * Test 9: Unreadable root directory does not falsely report all files as deleted.
     */
    public function test_unreadable_root_does_not_produce_deleted_findings(): void
    {
        $isolatedProject = $this->tempDir.'/isolated_sandbox';
        @mkdir($isolatedProject.'/app', 0777, true);
        file_put_contents($isolatedProject.'/.env', "APP_KEY=base64:1234567890=\n");
        file_put_contents($isolatedProject.'/app/File.php', '<?php');

        $isolatedScanner = new BaselineDiffScanner;
        $isolatedScanner->createBaseline($isolatedProject);

        @chmod($isolatedProject, 0000);
        if (@scandir($isolatedProject) === false) {
            $findings = $isolatedScanner->scan($isolatedProject);
            @chmod($isolatedProject, 0777);

            // Assert NO false DELETED findings
            foreach ($findings->all() as $finding) {
                $this->assertStringNotContainsString(
                    'deleted',
                    strtolower($finding->description),
                    "Unreadable root falsely reported file as deleted: {$finding->file}",
                );
            }

            // Assert status is failed or partial with errors
            $this->assertTrue($findings->hasErrors());
            $this->assertContains($findings->status(), ['failed', 'partial']);
        } else {
            @chmod($isolatedProject, 0777);
            $this->markTestSkipped('Filesystem does not honor chmod 0000 on directory in this environment.');
        }

        @unlink($isolatedProject.'/app/File.php');
        @unlink($isolatedProject.'/.env');
        @rmdir($isolatedProject.'/app');
        @rmdir($isolatedProject);
    }
}
