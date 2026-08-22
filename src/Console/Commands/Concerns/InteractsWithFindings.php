<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Commands\Concerns;

use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;
use Illuminate\Console\Command;

/**
 * Shared behaviour for commands that report FindingCollections:
 * failure-threshold resolution and GitHub Actions annotation output.
 *
 * @mixin Command
 */
trait InteractsWithFindings
{
    /**
     * Cached failure severity after first resolution.
     */
    private ?Severity $resolvedFailOnSeverity = null;

    /**
     * Reset per-run state.
     *
     * Command instances can be reused across multiple artisan calls within
     * a single process (tests, queue workers), so the cached severity must
     * be cleared at the start of each run.
     */
    public function resetFindingsState(): void
    {
        $this->resolvedFailOnSeverity = null;
    }

    /**
     * Resolve the process exit code from the findings.
     *
     * 0 = clean, 1 = findings at or above the failure severity
     * (--fail-on, default HIGH), 2 = findings below that threshold.
     */
    public function resolveExitCode(FindingCollection $findings): int
    {
        if ($findings->isEmpty()) {
            return 0;
        }

        return $findings->hasSeverity($this->failOnSeverity()) ? 1 : 2;
    }

    /**
     * Get the severity threshold that constitutes a failure.
     *
     * Resolved and cached on first call so an invalid --fail-on value
     * produces exactly one warning per command run.
     */
    public function failOnSeverity(): Severity
    {
        if ($this->resolvedFailOnSeverity !== null) {
            return $this->resolvedFailOnSeverity;
        }

        /** @var string|null $failOn */
        $failOn = $this->option('fail-on');

        if ($failOn === null || $failOn === '') {
            return $this->resolvedFailOnSeverity = Severity::HIGH;
        }

        $severity = Severity::tryFrom(strtoupper($failOn));

        if ($severity === null) {
            if ($this->option('format') !== 'json') {
                $this->warn("Unknown --fail-on value '{$failOn}'. Falling back to HIGH.");
            }

            return $this->resolvedFailOnSeverity = Severity::HIGH;
        }

        return $this->resolvedFailOnSeverity = $severity;
    }

    /**
     * Output findings as GitHub Actions workflow commands (annotations).
     *
     * CRITICAL/HIGH become ::error, MEDIUM becomes ::warning and LOW
     * becomes ::notice so findings render inline on pull requests.
     */
    public function outputGithubAnnotations(FindingCollection $findings): void
    {
        foreach ($findings as $finding) {
            $type = match ($finding->severity) {
                Severity::CRITICAL, Severity::HIGH => 'error',
                Severity::MEDIUM => 'warning',
                Severity::LOW => 'notice',
            };

            $title = "[{$finding->severity->value}] {$finding->scannerName}";

            $this->line(sprintf(
                '::%s file=%s,line=%d,title=%s::%s',
                $type,
                $finding->file,
                $finding->line ?? 1,
                $this->escapeGithubAnnotationValue($title),
                $this->escapeGithubAnnotationValue($finding->description),
            ));
        }

        $this->newLine();
        $this->line("Total findings: {$findings->count()}");
    }

    /**
     * Escape a value for use inside a GitHub Actions workflow command.
     */
    private function escapeGithubAnnotationValue(string $value): string
    {
        return str_replace(
            ['%', "\r\n", "\r", "\n", ':', ','],
            ['%25', '%0A', '%0A', '%0A', '%3A', '%2C'],
            $value,
        );
    }
}
