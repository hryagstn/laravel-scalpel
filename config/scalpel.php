<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Non-PHP Zones
    |--------------------------------------------------------------------------
    |
    | Directories where PHP files should NOT exist. Any .php file found inside
    | these directories will be flagged as a structural anomaly. Paths are
    | relative to the project root.
    |
    | The StructuralAnomalyScanner will automatically exclude known legitimate
    | files such as public/index.php.
    |
    */

    'non_php_zones' => [
        'public',
        'storage',
    ],

    /*
    |--------------------------------------------------------------------------
    | Structural Anomaly Allowed Files
    |--------------------------------------------------------------------------
    |
    | Files within non-PHP zones that are known to be legitimate. These will
    | be excluded from structural anomaly scanning. Paths are relative to the
    | project root.
    |
    */

    'structural_allowed_files' => [
        'public/index.php',
    ],

    /*
    |--------------------------------------------------------------------------
    | Structural Anomaly Allowed Directories
    |--------------------------------------------------------------------------
    |
    | Subdirectories within non-PHP zones where PHP files are expected.
    | For example, public/vendor/ may contain legitimately published assets.
    | Paths are relative to the project root.
    |
    */

    'structural_allowed_directories' => [
        'public/vendor',
        'storage/framework/views',
        'storage/framework/cache',
    ],

    /*
    |--------------------------------------------------------------------------
    | Excluded Paths (Global)
    |--------------------------------------------------------------------------
    |
    | Paths excluded from ALL scanners including BaselineDiffScanner.
    | Keep this list minimal — only paths that have no security relevance
    | whatsoever and should never be monitored.
    |
    | Note: vendor/ is intentionally NOT here. It is excluded from content
    | scanners via content_scan_excluded_paths but is still monitored by
    | BaselineDiffScanner via hash comparison to detect unauthorized
    | modifications to installed packages.
    |
    */

    'excluded_paths' => [
        'node_modules',
        '.git',
    ],

    /*
    |--------------------------------------------------------------------------
    | Content Scan Excluded Paths
    |--------------------------------------------------------------------------
    |
    | Paths excluded from content scanners only (ObfuscatedCodeScanner,
    | StructuralAnomalyScanner, HtaccessScanner).
    |
    | These paths are skipped during content analysis for performance reasons,
    | but are still monitored by BaselineDiffScanner via SHA-256 hash
    | comparison. If an attacker plants a backdoor in vendor/, the baseline
    | diff will detect the new or modified file even though the content
    | scanner does not scan vendor/ on every run.
    |
    | To also scan vendor/ for obfuscated code (slower, recommended after
    | deployments): php artisan scalpel:scan --include-vendor
    | (available via --include-vendor)
    |
    */

    'content_scan_excluded_paths' => [
        'vendor',
        'bootstrap/cache',
    ],

    /*
    |--------------------------------------------------------------------------
    | Suspicious PHP Extensions
    |--------------------------------------------------------------------------
    |
    | File extensions treated as executable PHP by the StructuralAnomalyScanner.
    | Attackers use lesser-known extensions (.phtml, .pht, .phar, .php5)
    | because servers are sometimes configured to execute them while
    | scanners only look for .php. Double-extension files (shell.php.jpg)
    | are also detected based on this list.
    |
    */

    'suspicious_php_extensions' => [
        'php',
        'pht',
        'phtm',
        'phtml',
        'phar',
        'php3',
        'php4',
        'php5',
        'php7',
    ],

    /*
    |--------------------------------------------------------------------------
    | Obfuscation Patterns
    |--------------------------------------------------------------------------
    |
    | Each obfuscation pattern can be individually enabled or disabled.
    | Set a pattern to false to skip detection for that specific pattern.
    |
    */

    'obfuscation_patterns' => [
        'eval_base64_decode' => true,
        'eval_gzinflate' => true,
        'eval_str_rot13' => true,
        'eval_gzuncompress' => true,
        'eval_gzdecode' => true,
        'assert_dynamic' => true,
        'eval_direct_input' => true,
        'backtick_operator' => true,
        'variable_variables' => true,
        'extract_input' => true,
        'variable_functions' => true,
        'preg_replace_e' => true,
        'long_encoded_string' => true,
        'create_function' => true,
        'file_put_contents_encoded' => true,
        'superglobal_eval' => true,
        'chr_chaining' => true,
        'hex_escape_sequence' => true,
        'dynamic_include' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Long String Threshold
    |--------------------------------------------------------------------------
    |
    | Minimum length for a string to be considered a suspiciously long encoded
    | payload. Applied by the ObfuscatedCodeScanner.
    |
    */

    'long_string_threshold' => 500,

    /*
    |--------------------------------------------------------------------------
    | Dangerous .htaccess Handlers
    |--------------------------------------------------------------------------
    |
    | Script handlers that should be flagged when found in AddHandler or
    | AddType directives within .htaccess files.
    |
    */

    'htaccess_dangerous_handlers' => [
        'cgi-script',
        'python-program',
        'perl-script',
        'ruby-script',
        'application/x-httpd-python',
        'application/x-httpd-perl',
        'application/x-httpd-ruby',
        'application/x-httpd-cgi',
    ],

    /*
    |--------------------------------------------------------------------------
    | Baseline Excluded Paths
    |--------------------------------------------------------------------------
    |
    | Paths excluded from BaselineDiffScanner in addition to global
    | excluded_paths. These are high-churn paths that change frequently
    | during normal operation and would produce excessive false positives
    | if included in baseline comparisons.
    |
    | bootstrap/cache is intentionally NOT here — it is a high-value target
    | for attackers who want to inject malicious service providers.
    | Changes here should always be investigated.
    |
    */

    'baseline_excluded_paths' => [
        'storage/logs',
        'storage/framework/cache',
        'storage/framework/sessions',
        'storage/framework/views',
        'storage/app/scalpel',
        'storage/app/private/scalpel',
        'storage/app',
    ],

    /*
    |--------------------------------------------------------------------------
    | Baseline Storage Path
    |--------------------------------------------------------------------------
    |
    | The path where baseline snapshots are stored, relative to the
    | storage/app directory. Uses the configured baseline_disk.
    |
    */

    'baseline_path' => 'scalpel/baseline.json',

    /* Filesystem disk used for baseline snapshots. Keep this outside the web root. */
    'baseline_disk' => env('SCALPEL_BASELINE_DISK', 'local'),

    /*
    |--------------------------------------------------------------------------
    | Baseline Fast Scan Mode
    |--------------------------------------------------------------------------
    |
    | When enabled, Scalpel will compare a file's size and modified time (mtime)
    | against the baseline before calculating its SHA-256 hash. If they match,
    | the hash computation is skipped, drastically improving performance.
    |
    | Default: false (strict mode) for maximum security against sophisticated
    | 'timestomping' attacks. Enable this explicitly using the --fast CLI flag.
    |
    */

    'baseline_fast_scan' => env('SCALPEL_BASELINE_FAST_SCAN', false),

    /*
    |--------------------------------------------------------------------------
    | Assume Production Environment
    |--------------------------------------------------------------------------
    |
    | Force strict production security checks in EnvIntegrityScanner even if
    | APP_ENV is not explicitly set to production.
    |
    */

    'assume_production' => env('SCALPEL_ASSUME_PRODUCTION', false),

    /*
    |--------------------------------------------------------------------------
    | Severity Threshold
    |--------------------------------------------------------------------------
    |
    | Minimum severity level to include in scan results. Findings below this
    | threshold will be silently ignored. Options: CRITICAL, HIGH, MEDIUM, LOW
    |
    */

    'severity_threshold' => 'LOW',

    /*
    |--------------------------------------------------------------------------
    | Suppress Banner
    |--------------------------------------------------------------------------
    |
    | When enabled, the Laravel Scalpel banner is hidden from command output.
    | Useful for cron jobs and CI pipelines where clean logs are preferred.
    | The banner is always suppressed automatically for --format=json or
    | --format=github.
    |
    */

    'suppress_banner' => env('SCALPEL_SUPPRESS_BANNER', false),

    /*
    |--------------------------------------------------------------------------
    | Output Signing
    |--------------------------------------------------------------------------
    |
    | When enabled, laravel-scalpel will sign its JSON scan results using HMAC.
    | This prevents tampering with the JSON report after it is written to disk.
    | Note that the signing key should NOT default to APP_KEY, but must be
    | a separate, dedicated secret.
    |
    */

    'signing' => [
        'enabled' => env('SCALPEL_SIGNING_ENABLED', false),
        'key' => env('SCALPEL_SIGNING_KEY'),
    ],

];
