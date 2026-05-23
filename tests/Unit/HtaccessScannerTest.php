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
        file_put_contents($this->tempDir . '/.htaccess', 'AddHandler cgi-script .py');

        $scanner = new HtaccessScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('cgi-script', $findings->all()[0]->description);
    }

    public function test_flags_dangerous_add_handler_python(): void
    {
        file_put_contents($this->tempDir . '/.htaccess', 'AddHandler application/x-httpd-python .php');

        $scanner = new HtaccessScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('application/x-httpd-python', $findings->all()[0]->description);
    }

    public function test_flags_dangerous_add_type(): void
    {
        file_put_contents($this->tempDir . '/.htaccess', 'AddType application/x-httpd-php .jpg');

        $scanner = new HtaccessScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
        $this->assertStringContainsString('application/x-httpd-php', $findings->all()[0]->description);
    }

    public function test_flags_security_disabling_php_flags(): void
    {
        file_put_contents($this->tempDir . '/.htaccess', "
            php_flag allow_url_include on
            php_value disable_functions none
        ");

        $scanner = new HtaccessScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(2, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
        $this->assertEquals('CRITICAL', $findings->all()[1]->severity->value);
    }

    public function test_flags_external_redirects(): void
    {
        file_put_contents($this->tempDir . '/.htaccess', 'RewriteRule ^(.*)$ http://attacker.com/$1 [R=301,L]');

        $scanner = new HtaccessScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('HIGH', $findings->all()[0]->severity->value);
    }

    public function test_flags_exec_cgi_options(): void
    {
        file_put_contents($this->tempDir . '/.htaccess', 'Options +ExecCGI');

        $scanner = new HtaccessScanner();
        $findings = $scanner->scan($this->tempDir);

        $this->assertCount(1, $findings);
        $this->assertEquals('CRITICAL', $findings->all()[0]->severity->value);
    }
}
