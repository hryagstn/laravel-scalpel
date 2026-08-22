<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Concerns;

use Hryagstn\Scalpel\Scalpel;

trait HasBanner
{
    /**
     * Display the package banner.
     */
    protected function displayBanner(string $subtitle = ''): void
    {
        $version = ltrim(Scalpel::version(), 'v');
        $this->newLine();
        $this->line('  ╔══════════════════════════════════════════════════╗');
        $this->line($this->formatBoxLine('  🔬 <fg=cyan;options=bold>Laravel Scalpel</> — '.($subtitle !== '' ? $subtitle : 'Intrusion Evidence Scanner')));
        $this->line($this->formatBoxLine("  <fg=gray>v{$version} • Filesystem Security Analysis</>"));
        $this->line('  ╚══════════════════════════════════════════════════╝');
        $this->newLine();
    }

    /**
     * Determine if the banner/header should be suppressed.
     */
    protected function shouldSuppressBanner(): bool
    {
        return ($this->hasOption('format') && in_array($this->option('format'), ['json', 'github'], true))
            || ($this->hasOption('no-ansi') && $this->option('no-ansi'))
            || ($this->hasOption('no-banner') && $this->option('no-banner'))
            || (bool) config('scalpel.suppress_banner', false);
    }

    /**
     * Format a line to fit perfectly inside the banner's double box.
     */
    protected function formatBoxLine(string $content, int $innerWidth = 50): string
    {
        $visibleContent = preg_replace('/<[^>]*>/', '', $content);
        $visibleLength = mb_strlen($visibleContent ?? '', 'UTF-8');
        $padLength = max(0, $innerWidth - $visibleLength);

        return '  ║'.$content.str_repeat(' ', $padLength).'║';
    }
}
