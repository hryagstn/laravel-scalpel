<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\HtaccessScanner;
use Hryagstn\Scalpel\Tests\TestCase;

class HtaccessScannerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'scalpel.excluded_paths' => ['vendor', 'node_modules', '.git'],
            'scalpel.htaccess_dangerous_handlers' => [
                'cgi-script',
                'python-program',
                'perl-script',
                'ruby-script',
                'application/x-httpd-python',
            ],
        ]);
    }

    public function test_flags_dangerous_add_handler(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'AddHandler cgi-script .py');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('cgi-script', $findings->all()[0]->description);
    }

    public function test_flags_dangerous_add_handler_python(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'AddHandler application/x-httpd-python .php');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('application/x-httpd-python', $findings->all()[0]->description);
    }

    public function test_flags_dangerous_add_type(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'AddType application/x-httpd-php .jpg');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('application/x-httpd-php', $findings->all()[0]->description);
    }

    public function test_flags_security_disabling_php_flags(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', '
            php_flag allow_url_include on
            php_value disable_functions none
        ');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(2, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertEquals('CRITICAL', $findings->all()[1]->severity->value);
    }

    public function test_flags_auto_prepend_file_in_htaccess(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'php_value auto_prepend_file /tmp/shell.txt');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('auto_prepend_file', $findings->all()[0]->description);
    }

    public function test_flags_malicious_user_ini(): void
    {
        @mkdir($this->tempDir.'/public', 0777, true);
        file_put_contents($this->tempDir.'/public/.user.ini', "; PHP-FPM config\nauto_prepend_file = c99.txt\ndisable_functions = \n");

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertGreaterThanOrEqual(2, count($findings));

        $descriptions = array_map(fn ($f) => $f->description, $findings->all());
        $this->assertNotEmpty(array_filter($descriptions, fn ($d) => str_contains((string) $d, 'auto_prepend_file')));

        foreach ($findings->all() as $finding) {
            $this->assertEquals('CRITICAL', $finding->severity->value);
            $this->assertStringEndsWith('.user.ini', $finding->file);
        }
    }

    public function test_ignores_benign_user_ini(): void
    {
        file_put_contents($this->tempDir.'/.user.ini', "upload_max_filesize = 10M\nmemory_limit = 256M\n");

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);
    }

    public function test_flags_external_redirects(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'RewriteRule ^(.*)$ http://attacker.com/$1 [R=301,L]');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_flags_exec_cgi_options(): void
    {
        file_put_contents($this->tempDir.'/.htaccess', 'Options +ExecCGI');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }

    public function test_handles_broken_symlinks_safely(): void
    {
        // Create a broken symlink named .htaccess
        @symlink($this->tempDir.'/non_existent_file.htaccess', $this->tempDir.'/.htaccess');

        $scanner = new HtaccessScanner;
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(0, $findings);

        @unlink($this->tempDir.'/.htaccess');
    }
}
