<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Unit;

use Hryagstn\Scalpel\Scalpel;
use Hryagstn\Scalpel\Tests\TestCase;

class ScalpelTest extends TestCase
{
    public function test_can_retrieve_version(): void
    {
        $version = Scalpel::version();

        $this->assertNotEmpty($version);
        // It should either be the composer.json version, fallback 1.0.0-dev or a dynamic version string
        $this->assertIsString($version);
    }
}
