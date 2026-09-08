<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Scanners;

use Symfony\Component\Finder\SplFileInfo;

/**
 * Cycle-safe, symlink-aware replacement for Symfony Finder traversal.
 *
 * Symfony Finder does not descend into symlinked directories by default,
 * which causes payloads behind directory symlinks to be missed (e.g. the
 * testbench skeleton symlinks base_path()/vendor back to the project vendor tree).
 * Enabling Finder::followLinks() risks infinite recursion on cyclic symlinks.
 *
 * SafeFinder always follows directory symlinks but keeps a visited-realpath
 * registry so cyclic structures are traversed exactly once.
 *
 * @implements \IteratorAggregate<int, SplFileInfo>
 */
final class SafeFinder implements \IteratorAggregate
{
    private const VCS_DIRS = ['.git', '.svn', '.hg', '_darcs', '.bzr'];

    private string $basePath = '';

    /** @var string[] */
    private array $nameGlobs = [];

    /** @var string[] */
    private array $excludedDirs = [];

    /** @var string[] */
    private array $excludedPaths = [];

    /** @var string[] */
    private array $unreadablePaths = [];

    private bool $ignoreDotFiles = true;

    private bool $ignoreVCS = false;

    public function in(string $basePath): self
    {
        $this->basePath = rtrim($basePath, '/');

        return $this;
    }

    /**
     * No-op kept for Finder API parity — directories are never yielded.
     */
    public function files(): self
    {
        return $this;
    }

    public function ignoreDotFiles(bool $ignore = true): self
    {
        $this->ignoreDotFiles = $ignore;

        return $this;
    }

    public function ignoreVCS(bool $ignore = true): self
    {
        $this->ignoreVCS = $ignore;

        return $this;
    }

    /**
     * @param  string|string[]  $globs  Basename globs or regex patterns (e.g. '*.php' or '/\.(?:php|phtml)$/i')
     */
    public function name(string|array $globs): self
    {
        $this->nameGlobs = array_merge($this->nameGlobs, (array) $globs);

        return $this;
    }

    /**
     * Exclude directory trees by base-relative path segments, e.g. 'vendor'
     * or 'bootstrap/cache'.
     *
     * @param  string[]  $dirs
     */
    public function exclude(array $dirs): self
    {
        $this->excludedDirs = array_merge($this->excludedDirs, $dirs);

        return $this;
    }

    /**
     * Skip files whose base-relative path matches one of the given paths.
     *
     * @param  string|string[]  $paths
     */
    public function notPath(string|array $paths): self
    {
        $this->excludedPaths = array_merge($this->excludedPaths, (array) $paths);

        return $this;
    }

    /**
     * Get any directory paths that could not be opened or read.
     *
     * @return string[]
     */
    public function getUnreadablePaths(): array
    {
        return $this->unreadablePaths;
    }

    /**
     * @return \Generator<int, SplFileInfo>
     */
    public function getIterator(): \Generator
    {
        $visitedRealPaths = [];

        yield from $this->walk($this->basePath, $this->basePath, '', $visitedRealPaths);
    }

    /**
     * @param  array<string, true>  $visitedRealPaths
     * @return \Generator<int, SplFileInfo>
     */
    private function walk(string $dirLogicalPath, string $dirPhysicalPath, string $relativePrefix, array &$visitedRealPaths): \Generator
    {
        $entries = @scandir($dirPhysicalPath, SCANDIR_SORT_ASCENDING);

        if ($entries === false) {
            $this->unreadablePaths[] = $dirLogicalPath;

            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            if ($this->ignoreDotFiles && str_starts_with($entry, '.')) {
                continue;
            }

            if ($this->ignoreVCS && in_array($entry, self::VCS_DIRS, true)) {
                continue;
            }

            $logicalPath = $dirLogicalPath.'/'.$entry;
            $physicalPath = $dirPhysicalPath.'/'.$entry;
            $relativePath = $relativePrefix === '' ? $entry : $relativePrefix.'/'.$entry;

            if (is_dir($physicalPath)) {
                if ($this->isExcludedPath($relativePath)) {
                    continue;
                }

                // realpath() collapses symlinks so each physical directory is
                // walked at most once — this is the cycle guard.
                $realPath = realpath($physicalPath);

                if ($realPath === false || isset($visitedRealPaths[$realPath])) {
                    continue;
                }

                $visitedRealPaths[$realPath] = true;

                yield from $this->walk($logicalPath, $realPath, $relativePath, $visitedRealPaths);

                continue;
            }

            if (! is_file($physicalPath)) {
                continue; // Broken symlinks, sockets, fifos, ...
            }

            if ($this->isExcludedPath($relativePath)) {
                continue;
            }

            if ($this->nameGlobs !== [] && ! $this->matchesName($entry)) {
                continue;
            }

            $relativeDir = dirname($relativePath);
            yield new SplFileInfo(
                $logicalPath,
                $relativeDir === '.' ? '' : $relativeDir,
                $relativePath,
            );
        }
    }

    private function isExcludedPath(string $relativePath): bool
    {
        foreach ([$this->excludedDirs, $this->excludedPaths] as $exclusions) {
            foreach ($exclusions as $excluded) {
                $excluded = trim(str_replace('\\', '/', $excluded), '/');

                if ($excluded === '') {
                    continue;
                }

                if ($this->containsSegmentSequence($relativePath, $excluded)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Match when the excluded path appears as a consecutive segment sequence
     * anywhere in the relative path, so 'vendor' also excludes 'app/vendor/x'
     * like Symfony Finder's exclude() does.
     */
    private function containsSegmentSequence(string $relativePath, string $excluded): bool
    {
        $parts = explode('/', $relativePath);
        $excludedParts = explode('/', $excluded);
        $length = count($excludedParts);

        for ($offset = 0; $offset + $length <= count($parts); $offset++) {
            if (array_slice($parts, $offset, $length) === $excludedParts) {
                return true;
            }
        }

        return false;
    }

    private function matchesName(string $basename): bool
    {
        foreach ($this->nameGlobs as $pattern) {
            if ($this->isRegex($pattern)) {
                if (preg_match($pattern, $basename) === 1) {
                    return true;
                }
            } elseif (fnmatch($pattern, $basename)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if a pattern string is a regular expression with delimiters.
     */
    private function isRegex(string $pattern): bool
    {
        if (strlen($pattern) < 3) {
            return false;
        }

        $first = $pattern[0];
        if (! in_array($first, ['/', '#', '~', '!'], true)) {
            return false;
        }

        $lastDelimPos = strrpos($pattern, $first);
        if ($lastDelimPos === false || $lastDelimPos === 0) {
            return false;
        }

        $modifiers = substr($pattern, $lastDelimPos + 1);

        return preg_match('/^[imsxu]*$/', $modifiers) === 1;
    }
}
