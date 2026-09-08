<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Data\Severity;
use Hryagstn\Scalpel\Tests\TestCase;

class SeverityTest extends TestCase
{
    public function test_try_from_string_resolves_case_insensitively(): void
    {
        $this->assertEquals(Severity::CRITICAL, Severity::tryFromString('critical'));
        $this->assertEquals(Severity::HIGH, Severity::tryFromString('HIGH'));
        $this->assertEquals(Severity::MEDIUM, Severity::tryFromString('Medium'));
        $this->assertEquals(Severity::LOW, Severity::tryFromString('low'));
    }

    public function test_try_from_string_returns_null_for_missing_or_unknown_values(): void
    {
        $this->assertNull(Severity::tryFromString(null));
        $this->assertNull(Severity::tryFromString(''));
        $this->assertNull(Severity::tryFromString('BOGUS'));
    }
}
