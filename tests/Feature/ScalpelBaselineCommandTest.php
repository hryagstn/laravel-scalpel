<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Tests\Feature;

use Hryagstn\Scalpel\Tests\TestCase;
use Illuminate\Support\Facades\Storage;

class ScalpelBaselineCommandTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('local');

        config([
            'scalpel.excluded_paths' => ['vendor', 'node_modules', '.git'],
            'scalpel.baseline_excluded_paths' => ['storage/logs', 'storage/app/scalpel'],
            'scalpel.baseline_path' => 'scalpel/baseline.json',
        ]);
    }

    public function test_creates_baseline_snapshot(): void
    {
        Storage::assertMissing('scalpel/baseline.json');

        $this->artisan('scalpel:baseline')
            ->expectsOutputToContain('Creating baseline snapshot')
            ->expectsOutputToContain('Baseline created successfully')
            ->assertExitCode(0);

        Storage::assertExists('scalpel/baseline.json');
    }

    public function test_baseline_already_exists_prompts_to_overwrite(): void
    {
        // 1. Create initial baseline
        Storage::put('scalpel/baseline.json', json_encode(['created_at' => date('c'), 'files' => []]));

        // 2. Run baseline and decline overwrite
        $this->artisan('scalpel:baseline')
            ->expectsQuestion('A baseline snapshot already exists. Do you want to overwrite it?', false)
            ->expectsOutputToContain('Baseline creation cancelled')
            ->assertExitCode(0);

        // 3. Run baseline and accept overwrite
        $this->artisan('scalpel:baseline')
            ->expectsQuestion('A baseline snapshot already exists. Do you want to overwrite it?', true)
            ->expectsOutputToContain('Baseline created successfully')
            ->assertExitCode(0);
    }

    public function test_baseline_already_exists_force_flag(): void
    {
        Storage::put('scalpel/baseline.json', json_encode(['created_at' => date('c'), 'files' => []]));

        $this->artisan('scalpel:baseline --force')
            ->expectsOutputToContain('Baseline created successfully')
            ->assertExitCode(0);
    }

    public function test_baseline_command_no_banner_option_suppresses_banner(): void
    {
        Storage::assertMissing('scalpel/baseline.json');

        $exitCode = \Illuminate\Support\Facades\Artisan::call('scalpel:baseline', ['--no-banner' => true]);
        $this->assertSame(0, $exitCode);

        $output = \Illuminate\Support\Facades\Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringContainsString('Creating baseline snapshot', $output);
    }

    public function test_baseline_command_no_ansi_option_suppresses_banner(): void
    {
        Storage::assertMissing('scalpel/baseline.json');

        $exitCode = \Illuminate\Support\Facades\Artisan::call('scalpel:baseline', ['--no-ansi' => true]);
        $this->assertSame(0, $exitCode);

        $output = \Illuminate\Support\Facades\Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringContainsString('Creating baseline snapshot', $output);
    }

    public function test_baseline_command_config_suppress_banner_suppresses_banner(): void
    {
        config(['scalpel.suppress_banner' => true]);
        Storage::assertMissing('scalpel/baseline.json');

        $exitCode = \Illuminate\Support\Facades\Artisan::call('scalpel:baseline');
        $this->assertSame(0, $exitCode);

        $output = \Illuminate\Support\Facades\Artisan::output();
        $this->assertStringNotContainsString('Laravel Scalpel', $output);
        $this->assertStringContainsString('Creating baseline snapshot', $output);
    }
}

