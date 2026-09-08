<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\UserIniScanner;
use Hryagstn\Scalpel\Tests\TestCase;

class UserIniScannerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'scalpel.excluded_paths' => ['vendor', 'node_modules', '.git'],
            'scalpel.user_ini_dangerous_directives' => [
                'auto_prepend_file',
                'auto_append_file',
                'include_path',
                'open_basedir',
                'disable_functions',
                'disable_classes',
                'zend_extension',
                'extension',
            ],
        ]);
    }

    public function test_flags_auto_prepend_file_in_public_user_ini(): void
    {
        @mkdir($this->tempDir.'/public', 0777, true);
        file_put_contents($this->tempDir.'/public/.user.ini', "auto_prepend_file = /var/www/backdoor.php\n");

        $scanner = new UserIniScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('auto_prepend_file', $findings->all()[0]->description);
        $this->assertEquals('public/.user.ini', $findings->all()[0]->file);
    }

    public function test_flags_auto_append_file_in_storage_user_ini(): void
    {
        @mkdir($this->tempDir.'/storage/app', 0777, true);
        file_put_contents($this->tempDir.'/storage/app/.user.ini', "auto_append_file = shell.php\n");

        $scanner = new UserIniScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('auto_append_file', $findings->all()[0]->description);
        $this->assertEquals('storage/app/.user.ini', $findings->all()[0]->file);
    }

    public function test_flags_multiple_directives(): void
    {
        @mkdir($this->tempDir.'/public', 0777, true);
        file_put_contents($this->tempDir.'/public/.user.ini', "auto_prepend_file = backdoor.php\ndisable_functions = exec\n");

        $scanner = new UserIniScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(2, $findings);
    }

    public function test_skips_comments_and_empty_lines(): void
    {
        @mkdir($this->tempDir.'/public', 0777, true);
        file_put_contents($this->tempDir.'/public/.user.ini', "; auto_prepend_file = backdoor.php\n# auto_append_file = shell.php\n\nauto_prepend_file = real.php\n");

        $scanner = new UserIniScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals(3, $findings->all()[0]->line); // Line 3 is the actual directive
    }

    public function test_scans_user_ini_across_entire_project_including_root(): void
    {
        // .user.ini in project root should be scanned
        file_put_contents($this->tempDir.'/.user.ini', "auto_prepend_file = backdoor.php\n");
        // .user.ini in app/ should also be scanned
        @mkdir($this->tempDir.'/app', 0777, true);
        file_put_contents($this->tempDir.'/app/.user.ini', "auto_prepend_file = backdoor.php\n");

        $scanner = new UserIniScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(2, $findings);
    }

    public function test_respects_custom_dangerous_directives_config(): void
    {
        config(['scalpel.user_ini_dangerous_directives' => ['custom_directive']]);

        @mkdir($this->tempDir.'/public', 0777, true);
        file_put_contents($this->tempDir.'/public/.user.ini', "custom_directive = value\nauto_prepend_file = backdoor.php\n");

        $scanner = new UserIniScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertStringContainsString('custom_directive', $findings->all()[0]->description);
    }

    public function test_handles_broken_symlinks_safely(): void
    {
        @mkdir($this->tempDir.'/public', 0777, true);
        @symlink($this->tempDir.'/non_existent.ini', $this->tempDir.'/public/.user.ini');

        $scanner = new UserIniScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);

        @unlink($this->tempDir.'/public/.user.ini');
    }
}
