<?php

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
    ],

    /*
    |--------------------------------------------------------------------------
    | Excluded Paths
    |--------------------------------------------------------------------------
    |
    | Paths or patterns to exclude from ALL scans. These paths will be skipped
    | by every scanner. Paths are relative to the project root.
    |
    */

    'excluded_paths' => [
        'vendor',
        'node_modules',
        '.git',
        'bootstrap/cache',
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
        'eval_base64_decode'  => true,
        'eval_gzinflate'      => true,
        'eval_str_rot13'      => true,
        'eval_gzuncompress'   => true,
        'eval_gzdecode'       => true,
        'assert_dynamic'      => true,
        'variable_functions'  => true,
        'preg_replace_e'      => true,
        'long_encoded_string' => true,
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
    | Additional paths to exclude from baseline snapshot creation and diff
    | comparison. These are in addition to the global excluded_paths above.
    | Paths are relative to the project root.
    |
    */

    'baseline_excluded_paths' => [
        'storage/logs',
        'storage/framework/cache',
        'storage/framework/sessions',
        'storage/framework/views',
        'storage/app/private/scalpel',
    ],

    /*
    |--------------------------------------------------------------------------
    | Baseline Storage Path
    |--------------------------------------------------------------------------
    |
    | The path where baseline snapshots are stored, relative to the
    | storage/app directory. Uses Laravel's Storage facade with local disk.
    |
    */

    'baseline_path' => 'scalpel/baseline.json',

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

];
