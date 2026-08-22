<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Data\Finding;
use Hryagstn\Scalpel\Data\Severity;
use Hryagstn\Scalpel\Tests\TestCase;

class FindingTest extends TestCase
{
    public function test_can_instantiate_and_convert_to_array(): void
    {
        $finding = Finding::make(
            severity: Severity::CRITICAL,
            file: 'app/Http/Controllers/BadController.php',
            line: 42,
            description: 'Backdoor found',
            scannerName: 'Test Scanner'
        );

        $this->assertEquals(Severity::CRITICAL, $finding->severity);
        $this->assertEquals('app/Http/Controllers/BadController.php', $finding->file);
        $this->assertEquals(42, $finding->line);
        $this->assertEquals('Backdoor found', $finding->description);
        $this->assertEquals('Test Scanner', $finding->scannerName);

        $expectedArray = [
            'severity' => 'CRITICAL',
            'file' => 'app/Http/Controllers/BadController.php',
            'line' => 42,
            'description' => 'Backdoor found',
            'scanner' => 'Test Scanner',
        ];

        $this->assertEquals($expectedArray, $finding->toArray());
    }

    public function test_severity_levels(): void
    {
        $this->assertEquals(4, Severity::CRITICAL->weight());
        $this->assertEquals(3, Severity::HIGH->weight());
        $this->assertEquals(2, Severity::MEDIUM->weight());
        $this->assertEquals(1, Severity::LOW->weight());

        $this->assertTrue(Severity::CRITICAL->meetsThreshold(Severity::HIGH));
        $this->assertTrue(Severity::HIGH->meetsThreshold(Severity::HIGH));
        $this->assertFalse(Severity::MEDIUM->meetsThreshold(Severity::HIGH));
        $this->assertFalse(Severity::LOW->meetsThreshold(Severity::HIGH));
    }
}
