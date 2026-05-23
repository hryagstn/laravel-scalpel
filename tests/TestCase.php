<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests;

use Hryagstn\Scalpel\ScalpelServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tempDir = __DIR__ . '/temp';
        if (!is_dir($this->tempDir)) {
            mkdir($this->tempDir, 0777, true);
        }
    }

    protected function tearDown(): void
    {
        $this->cleanDir($this->tempDir);
        if (is_dir($this->tempDir)) {
            @rmdir($this->tempDir);
        }

        parent::tearDown();
    }

    protected function cleanDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $files = scandir($dir);
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') {
                continue;
            }

            $path = $dir . '/' . $file;
            if (is_dir($path)) {
                $this->cleanDir($path);
                @rmdir($path);
            } else {
                @unlink($path);
            }
        }
    }

    protected function getPackageProviders($app): array
    {
        return [
            ScalpelServiceProvider::class,
        ];
    }
}
