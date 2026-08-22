<?php

declare(strict_types=1);

namespace Hryagstn\Scalpel\Console\Commands;

use Illuminate\Console\Command;

final class ScalpelVerifyCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'scalpel:verify
        {file? : The path to the JSON file to verify, or -/blank for stdin}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Verify the signature of a signed scalpel scan JSON output';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $argument = $this->argument('file');
        $file = null;

        if (is_string($argument)) {
            $file = $argument;
        } elseif (is_array($argument) && is_string($argument[0] ?? null)) {
            $file = $argument[0];
        }

        if ($file === null || $file === '-') {
            $jsonContent = @file_get_contents('php://stdin');
        } else {
            if (! file_exists($file)) {
                $this->error("  ❌ File not found: {$file}");

                return 1;
            }
            $jsonContent = @file_get_contents($file);
        }

        if ($jsonContent === false || $jsonContent === '') {
            $this->error('  ❌ Empty or missing JSON input.');

            return 1;
        }

        $data = json_decode($jsonContent, true);
        if (! is_array($data)) {
            $this->error('  ❌ Invalid JSON format.');

            return 1;
        }

        if (! isset($data['signature']) || ! is_string($data['signature'])) {
            $this->error('  ❌ Signature missing from JSON payload.');

            return 1;
        }

        $signature = $data['signature'];
        unset($data['signature']);

        // Rebuilt canonical JSON structure
        $canonicalJson = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($canonicalJson === false) {
            $this->error('  ❌ Unable to rebuild canonical JSON payload.');

            return 1;
        }

        $key = config('scalpel.signing.key');
        if (! is_string($key) || $key === '') {
            $this->error('  ❌ Scalpel signing key is not configured.');

            return 1;
        }

        $expectedSignature = hash_hmac('sha256', $canonicalJson, $key);

        if (hash_equals($expectedSignature, $signature)) {
            $this->info('  ✅ Output integrity verified successfully.');

            return 0;
        }

        $this->error('  ❌ Signature verification failed. The payload has been tampered with or signed with a different key.');

        return 1;
    }
}
