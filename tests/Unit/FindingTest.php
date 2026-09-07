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

    public function test_supports_legacy_snake_case_scanner_name_named_parameter(): void
    {
        $finding = Finding::make(
            severity: Severity::HIGH,
            file: 'public/index.php',
            line: null,
            description: 'Suspicious change',
            scanner_name: 'Baseline Diff'
        );

        $this->assertEquals('Baseline Diff', $finding->scannerName);
        $this->assertEquals('Baseline Diff', $finding->scanner_name);
        $this->assertEquals('Baseline Diff', $finding->toArray()['scanner']);
    }

    public function test_constructor_supports_both_named_parameters(): void
    {
        $finding1 = new Finding(
            severity: Severity::MEDIUM,
            file: 'config/app.php',
            line: 15,
            description: 'Env mismatch',
            scannerName: 'Env Integrity'
        );

        $this->assertEquals('Env Integrity', $finding1->scannerName);
        $this->assertEquals('Env Integrity', $finding1->scanner_name);

        $finding2 = new Finding(
            severity: Severity::MEDIUM,
            file: 'config/app.php',
            line: 15,
            description: 'Env mismatch',
            scanner_name: 'Env Integrity'
        );

        $this->assertEquals('Env Integrity', $finding2->scannerName);
        $this->assertEquals('Env Integrity', $finding2->scanner_name);
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
