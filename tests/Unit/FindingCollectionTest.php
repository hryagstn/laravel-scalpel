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
        $collection = new FindingCollection();
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
}
