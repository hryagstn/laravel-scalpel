<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\FindingCollection;
use Hryagstn\Scalpel\Data\Severity;
use Hryagstn\Scalpel\Tests\TestCase;

class FindingCollectionTest extends TestCase
{
    public function test_can_add_findings_and_count_them(): void
    {
        $collection = new FindingCollection;
        $this->assertTrue($collection->isEmpty());

        $finding = Finding::make(Severity::CRITICAL, 'file.php', 10, 'Error', 'Scanner');
        $collection->add($finding);

        $this->assertFalse($collection->isEmpty());
        $this->assertCount(1, $collection);
        $this->assertEquals([$finding], $collection->all());
    }

    public function test_can_merge_collections(): void
    {
        $c1 = new FindingCollection([
            Finding::make(Severity::CRITICAL, 'file1.php', 10, 'Error 1', 'Scanner A'),
        ]);

        $c2 = new FindingCollection([
            Finding::make(Severity::HIGH, 'file2.php', 20, 'Error 2', 'Scanner B'),
        ]);

        $c1->merge($c2);

        $this->assertCount(2, $c1);
        $this->assertEquals('file1.php', $c1->all()[0]->file);
        $this->assertEquals('file2.php', $c1->all()[1]->file);
    }

    public function test_can_filter_by_severity(): void
    {
        $collection = new FindingCollection([
            Finding::make(Severity::CRITICAL, 'f1.php', null, 'D1', 'Scanner'),
            Finding::make(Severity::HIGH, 'f2.php', null, 'D2', 'Scanner'),
            Finding::make(Severity::MEDIUM, 'f3.php', null, 'D3', 'Scanner'),
            Finding::make(Severity::LOW, 'f4.php', null, 'D4', 'Scanner'),
        ]);

        $filtered = $collection->filterBySeverity(Severity::HIGH);

        $this->assertCount(2, $filtered);
        $this->assertEquals(Severity::CRITICAL, $filtered->all()[0]->severity);
        $this->assertEquals(Severity::HIGH, $filtered->all()[1]->severity);
    }

    public function test_can_group_by_severity_and_scanner(): void
    {
        $collection = new FindingCollection([
            Finding::make(Severity::CRITICAL, 'f1.php', null, 'D1', 'Scanner A'),
            Finding::make(Severity::CRITICAL, 'f2.php', null, 'D2', 'Scanner B'),
            Finding::make(Severity::MEDIUM, 'f3.php', null, 'D3', 'Scanner A'),
        ]);

        $bySeverity = $collection->groupBySeverity();
        $this->assertCount(2, $bySeverity['CRITICAL']);
        $this->assertCount(1, $bySeverity['MEDIUM']);
        $this->assertArrayNotHasKey('HIGH', $bySeverity);

        $byScanner = $collection->groupByScanner();
        $this->assertCount(2, $byScanner['Scanner A']);
        $this->assertCount(1, $byScanner['Scanner B']);
    }

    public function test_severity_checks(): void
    {
        $collection = new FindingCollection([
            Finding::make(Severity::HIGH, 'f1.php', null, 'D1', 'Scanner'),
        ]);

        $this->assertTrue($collection->hasSeverity(Severity::HIGH));
        $this->assertTrue($collection->hasSeverity(Severity::MEDIUM));
        $this->assertFalse($collection->hasSeverity(Severity::CRITICAL));
        $this->assertTrue($collection->hasCriticalOrHigh());

        $collection2 = new FindingCollection([
            Finding::make(Severity::MEDIUM, 'f1.php', null, 'D1', 'Scanner'),
        ]);
        $this->assertFalse($collection2->hasCriticalOrHigh());
    }

    public function test_with_finding_is_immutable(): void
    {
        $collection = new FindingCollection;
        $finding = Finding::make(Severity::LOW, 'test.php', 1, 'Notice', 'Test');

        $newCollection = $collection->withFinding($finding);

        $this->assertCount(0, $collection);
        $this->assertCount(1, $newCollection);
        $this->assertNotSame($collection, $newCollection);
    }

    public function test_directory_errors_increment_directory_counter_not_files(): void
    {
        $collection = new FindingCollection;
        $collection->addDirectoryError('storage/secret', 'Permission denied', 'Test Scanner');

        $this->assertSame(0, $collection->skippedFilesCount());
        $this->assertSame(1, $collection->skippedDirectoriesCount());
        $this->assertTrue($collection->hasErrors());
        $this->assertTrue($collection->errors()[0]['is_directory']);
    }

    public function test_filter_by_severity_preserves_operational_metadata(): void
    {
        $collection = new FindingCollection([
            Finding::make(Severity::LOW, 'low.php', 1, 'Low issue', 'Scanner'),
            Finding::make(Severity::HIGH, 'high.php', 2, 'High issue', 'Scanner'),
        ]);
        $collection->incrementScannedFiles(50);
        $collection->addError('bad.php', 'Read failed', 'Scanner');
        $collection->addDirectoryError('unreadable_dir', 'Cannot open', 'Scanner');
        $collection->setScannerStatus('Scanner', 'partial');

        $filtered = $collection->filterBySeverity(Severity::HIGH);

        $this->assertCount(1, $filtered);
        $this->assertSame(50, $filtered->scannedFilesCount());
        $this->assertSame(1, $filtered->skippedFilesCount());
        $this->assertSame(1, $filtered->skippedDirectoriesCount());
        $this->assertCount(2, $filtered->errors());
        $this->assertSame('partial', $filtered->status());
    }

    public function test_status_aggregation_per_scanner(): void
    {
        // 1. All complete
        $c1 = new FindingCollection;
        $c1->setScannerStatus('Scanner A', 'complete');
        $c1->setScannerStatus('Scanner B', 'complete');
        $this->assertSame('complete', $c1->status());

        // 2. All failed
        $c2 = new FindingCollection;
        $c2->setScannerStatus('Scanner A', 'failed');
        $c2->setScannerStatus('Scanner B', 'failed');
        $this->assertSame('failed', $c2->status());

        // 3. Mixed: 1 complete, 1 failed -> partial
        $c3 = new FindingCollection;
        $c3->setScannerStatus('Scanner A', 'complete');
        $c3->setScannerStatus('Scanner B', 'failed');
        $this->assertSame('partial', $c3->status());

        // 4. Merge preserves aggregate status
        $merged = (new FindingCollection)->setScannerStatus('Scanner A', 'complete');
        $merged->merge((new FindingCollection)->setScannerStatus('Scanner B', 'failed'));
        $this->assertSame('partial', $merged->status());
    }

    public function test_merge_order_commutativity_across_all_statuses(): void
    {
        $factory = [
            'empty' => fn () => new FindingCollection,
            'complete_explicit' => fn () => (new FindingCollection)->markComplete(),
            'partial_explicit' => fn () => (new FindingCollection)->markPartial(),
            'failed_explicit' => fn () => (new FindingCollection)->markFailed(),
            'complete_scanner' => fn () => (new FindingCollection)->setScannerStatus('Scan', 'complete')->incrementScannedFiles(5),
            'partial_scanner' => fn () => (new FindingCollection)->setScannerStatus('Scan', 'partial')->incrementScannedFiles(3),
            'failed_scanner' => fn () => (new FindingCollection)->setScannerStatus('Scan', 'failed'),
            'error_implicit' => fn () => (new FindingCollection)->addError('file.php', 'cannot read', 'Scan'),
        ];

        foreach ($factory as $key1 => $fn1) {
            foreach ($factory as $key2 => $fn2) {
                $c1_then_c2 = $fn1()->merge($fn2());
                $c2_then_c1 = $fn2()->merge($fn1());

                $this->assertSame(
                    $c1_then_c2->status(),
                    $c2_then_c1->status(),
                    "Merge status mismatch for ({$key1}, {$key2}) vs ({$key2}, {$key1}): {$c1_then_c2->status()} vs {$c2_then_c1->status()}",
                );
            }
        }
    }
}
