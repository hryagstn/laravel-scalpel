<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Events;

use Hryagstn\Scalpel\Data\FindingCollection;

/**
 * Dispatched after a scalpel:scan or scalpel:diff command finishes.
 *
 * Listen for this event to integrate alerting channels (Mail, Slack,
 * Telegram, webhooks) without leaving the Laravel ecosystem:
 *
 *   Event::listen(ScanFinished::class, function (ScanFinished $event) {
 *       if ($event->findings->hasCriticalOrHigh()) {
 *           // notify...
 *       }
 *   });
 */
final class ScanFinished
{
    /**
     * @param  FindingCollection  $findings  The (threshold-filtered) findings of the run.
     * @param  string  $context  Which command produced the findings: 'scan' or 'diff'.
     * @param  float  $durationMs  Total wall-clock duration of the scan in milliseconds.
     */
    public function __construct(
        public readonly FindingCollection $findings,
        public readonly string $context,
        public readonly float $durationMs,
    ) {}
}
