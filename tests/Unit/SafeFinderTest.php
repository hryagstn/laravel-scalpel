<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scanners\SafeFinder;
use Hryagstn\Scalpel\Tests\TestCase;

class SafeFinderTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Fixture tree:
        //   outside/secret.php                 <- reachable only via dir symlink
        //   public/link -> ../outside          <- directory symlink into scanned tree
        //   loop/a/marker_a.php                <- part of a symlink cycle
        //   loop/b/back -> ../a                <- closes the cycle back onto loop/a
        //   vendor/top.php                     <- top-level excluded dir
        //   app/vendor/nested.php              <- nested dir sharing an excluded name
        //   index.php                          <- plain match
        //   .hidden.php                        <- dot-file
        @mkdir($this->tempDir.'/outside', 0777, true);
        @mkdir($this->tempDir.'/public', 0777, true);
        @mkdir($this->tempDir.'/loop/a', 0777, true);
        @mkdir($this->tempDir.'/loop/b', 0777, true);
        @mkdir($this->tempDir.'/vendor', 0777, true);
        @mkdir($this->tempDir.'/app/vendor', 0777, true);

        file_put_contents($this->tempDir.'/outside/secret.php', '<?php // secret');
        file_put_contents($this->tempDir.'/loop/a/marker_a.php', '<?php // a');
        file_put_contents($this->tempDir.'/vendor/top.php', '<?php // top');
        file_put_contents($this->tempDir.'/app/vendor/nested.php', '<?php // nested');
        file_put_contents($this->tempDir.'/index.php', '<?php // index');
        file_put_contents($this->tempDir.'/.hidden.php', '<?php // hidden');

        @symlink('../outside', $this->tempDir.'/public/link');
        @symlink('../a', $this->tempDir.'/loop/b/back');
    }

    public function test_follows_directory_symlinks_and_finds_hidden_payload(): void
    {
        $basenames = $this->collect(
            (new SafeFinder)->in($this->tempDir)->files()->ignoreDotFiles(false)->name('*.php'),
        );

        $this->assertContains('secret.php', $basenames);
    }

    public function test_symlink_cycle_terminates_with_single_visit(): void
    {
        $basenames = $this->collect(
            (new SafeFinder)->in($this->tempDir.'/loop')->files()->name('*.php'),
        );

        $this->assertSame(['marker_a.php'], array_values($basenames));
    }

    public function test_excludes_nested_directories_sharing_excluded_name(): void
    {
        $basenames = $this->collect(
            (new SafeFinder)->in($this->tempDir)->files()->exclude(['vendor'])->name('*.php'),
        );

        $this->assertNotContains('top.php', $basenames);
        $this->assertNotContains('nested.php', $basenames);
    }

    public function test_dot_files_are_skipped_when_ignore_dot_files_enabled(): void
    {
        $basenames = $this->collect(
            (new SafeFinder)->in($this->tempDir)->files()->ignoreDotFiles(true)->exclude(['vendor', 'outside', 'public', 'loop'])->name('*.php'),
        );

        $this->assertSame(['index.php'], array_values($basenames));
    }

    public function test_supports_regex_name_patterns(): void
    {
        file_put_contents($this->tempDir.'/outside/test.phtml', '<?php // phtml');

        $finder = (new SafeFinder)
            ->in($this->tempDir.'/outside')
            ->name('/\.(?:php|phtml)$/i');

        $basenames = $this->collect($finder);
        $this->assertContains('secret.php', $basenames);
        $this->assertContains('test.phtml', $basenames);
    }

    public function test_yields_symfony_spl_file_info_with_relative_pathname(): void
    {
        $finder = (new SafeFinder)
            ->in($this->tempDir)
            ->exclude(['vendor', 'outside', 'public', 'loop'])
            ->name('index.php');

        $files = iterator_to_array($finder, false);
        $this->assertCount(1, $files);
        $this->assertSame('index.php', $files[0]->getRelativePathname());
    }

    /**
     * Collect sorted basenames from the finder.
     *
     * @return string[]
     */
    private function collect(SafeFinder $finder): array
    {
        $names = [];

        foreach ($finder as $file) {
            $names[] = $file->getFilename();
        }

        sort($names);

        return $names;
    }
}
