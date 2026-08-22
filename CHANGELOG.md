# Changelog

All notable changes to `laravel-scalpel` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - 2026-08-22

### Added
- **Baseline tamper protection:** baseline snapshots are now HMAC-signed when output signing is enabled. `scalpel:diff` verifies the signature before trusting the snapshot — a regenerated/tampered baseline is reported as CRITICAL.
- **`.user.ini` scanning:** the Htaccess scanner now also detects dangerous directives in `.user.ini` files (the PHP-FPM persistence vector), including `auto_prepend_file` / `auto_append_file`.
- **Non-standard PHP extension detection:** the Structural Anomaly Scanner now flags `.phtml`, `.pht`, `.phar`, `.php5`, etc. (configurable via new `suspicious_php_extensions` key), plus double-extension upload bypasses such as `shell.php.jpg`.
- **Env Integrity enhancements:** detects empty or unreadable `.env` files, world-readable `.env` permissions, injected keys (present in `.env` but not `.env.example`) and removed keys (present in `.env.example` but missing from `.env`).
- **New obfuscation patterns** (all toggleable): `eval_direct_input`, `backtick_operator`, `variable_variables`, `extract_input`.
- **`ScanFinished` event** dispatched by `scalpel:scan` and `scalpel:diff` for native Laravel alerting integrations (Mail/Slack/Telegram listeners).
- **`--format=github` output** producing GitHub Actions annotations (`::error` / `::warning` / `::notice`) that render inline on pull requests.
- **`--include-vendor` flag** to include `vendor/` in content scanning on demand (previously teased in config comments).
- **`--fail-on=<severity>` flag** to control which severity constitutes a failing exit code (default: `HIGH`).
- Baseline snapshots now embed a `schema_version` field for future structure migrations.

### Fixed
- Exit codes now match documented behaviour in all cases: missing baseline in `scalpel:diff` returns `2` (MEDIUM finding) instead of `1`.

### Changed
- Tightened encoded-string heuristics in the Obfuscated Code Scanner to reduce false positives on long prose and minified code (hex must be even-length; base64 requires structural characters; density threshold raised from 85% to 95%).
- Comment-line detection now recognizes `|`-prefixed lines used inside Laravel-style config docblocks, avoiding false positives on inline code references.
- Added a test coverage CI job, Renovate config, and Codecov badge.
- Published config now includes the previously implicit `suppress_banner` key.

## [1.6.1] - 2026-07-29

### Documentation
- Updated GitHub Pages landing page website (`docs/index.html`) with v1.6.0 features, configuration options, and updated requirements.

## [1.6.0] - 2026-07-29

### Added
- Added 6 new obfuscation detection patterns to `ObfuscatedCodeScanner`: `create_function`, `file_put_contents_encoded`, `superglobal_eval`, `chr_chaining`, `hex_escape_sequence`, and `dynamic_include`.
- Added production-aware environment security checks to `EnvIntegrityScanner` (`APP_KEY` presence check, `APP_DEBUG=true` in production check, `APP_ENV=local` when assume production is active).
- Added `--production` CLI option to `scalpel:scan` command to force production security checks.
- Added `scalpel.assume_production` configuration option (via `SCALPEL_ASSUME_PRODUCTION` env).
- Added HMAC-SHA256 output signing parity to `scalpel:diff --format=json` when signing is enabled.
- Added PHPStan Level 8 static analysis (`phpstan.neon`) and Larastan integration.
- Added Laravel Pint code formatter (`pint.json`) and automated formatting standards.
- Added Laravel 13 compatibility testing to CI matrix.

### Changed
- **Minimum PHP version raised to 8.2+**. PHP 8.1 support has been dropped.
- Refactored console commands using shared concerns traits (`HasBanner`, `HasScannerProgress`, `OutputsFindings`) to eliminate duplicate code.

### Fixed
- Fixed scanner alias mismatch in `ScalpelScanCommand` where `htaccess` alias mapped to `.htaccess` instead of `Htaccess`, causing `--only=htaccess` to fail silently.
- Cleaned up root repository by removing residual debug `test.php` file.

## [1.5.2] - 2026-07-12

### Added
- Added `--fast` CLI option to `scalpel:baseline`, `scalpel:scan`, and `scalpel:diff` commands.

### Changed
- Changed `baseline_fast_scan` default setting to `false` (Strict Mode) to provide maximum security by default, especially suitable for automated integration environments like n8n. Passing the `--fast` flag enables the metadata-based fast scan mode for individual executions.

## [1.5.1] - 2026-07-12

### Fixed
- Optimized baseline creation (`scalpel:baseline` / `createBaseline`) and comparison (`scalpel:scan` / `buildCurrentFileMap`) to perform only a **single filesystem crawl** instead of two, by resolving Symfony Finder iterators to arrays.
- Added **Deferred Hashing** to baseline recreation. Overwriting or recreating an existing baseline now skips SHA-256 calculation for unchanged files, making baseline updates extremely fast (instant) even with 14,000+ files.

## [1.5.0] - 2026-07-12

### Added
- Added metadata-based fast scan (Deferred Hashing) to `BaselineDiffScanner`. When enabled, files with matching size and modification time (mtime) skip SHA-256 hash recalculation, resulting in extremely fast scan performance.
- Added `scalpel.baseline_fast_scan` configuration option (via `SCALPEL_BASELINE_FAST_SCAN` env).

### Changed
- Excluded `storage/app` from `baseline_excluded_paths` by default to avoid slow baseline hashing of dynamic user uploads, while keeping it secured via `StructuralAnomalyScanner`.

## [1.4.1] - 2026-07-05

### Fixed
- Fixed `TypeError: BaseScanner::relativePath(): Argument #1 ($fullPath) must be of type string, false given` caused by `getRealPath()` returning `false` on broken symlinks or unreadable files.

### Added
- Added `SECURITY.md` security policy.
- Updated documentation under `docs/` and `README.md` to keep configurations and security models aligned with recent features.

## [1.4.0] - 2026-06-19
- Added `signing.enabled` and `signing.key` configuration options to sign JSON scan outputs using HMAC-SHA256.
- Added `scalpel:verify` command to verify the output integrity of signed scan reports.
- Added a "Security Model & Limitations" section to the README and landing page outlining trust boundaries and mitigations.
- Added centered branding logo inside `README.md` and `CONTRIBUTING.md`.

## [1.3.3] - 2026-06-18

### Fixed
- Fixed `StructuralAnomalyScanner` false positives for Laravel framework directories (`storage/framework/views/` and `storage/framework/cache/`). These directories contain legitimate auto-generated PHP files (compiled Blade templates and real-time facade caches). They are now recognized as built-in framework directories, while `ObfuscatedCodeScanner` continues to scan them for actual obfuscated code.

## [1.3.1] - 2026-06-18

### Fixed
- Fixed double "v" prefix in CLI version display (e.g., `vv1.3.0` → `v1.3.0`) across all commands (scan, baseline, diff).

## [1.3.0] - 2026-06-13

### Added
- Added `--no-banner` option to `scalpel:scan`, `scalpel:diff`, and `scalpel:baseline` commands to suppress the header banner.
- Added `scalpel.suppress_banner` configuration option to globally disable the CLI header banner.
- Added comprehensive feature tests for banner and progress suppression in scan, diff, and baseline commands.

### Changed
- Automatically suppress the Laravel Scalpel banner when `--format=json` or `--no-ansi` is specified.
- Automatically suppress the real-time scanning progress bar and related scanner runner console outputs when `--format=json` is specified in `scalpel:scan`.

## [1.2.0] - 2026-06-12

### Added
- Added dynamic version resolution using Composer's `InstalledVersions` for accurate CLI output headers and banners.
- Added real-time Symfony progress bar output to CLI commands (`scalpel:scan`, `scalpel:baseline`, `scalpel:diff`) during file scanning/hashing.
- Added progress listener callbacks to `BaseScanner` and `BaselineDiffScanner`.
- Added unit tests for dynamic version resolution and scanner progress callbacks.

## [0.1.0] - 2026-05-23

### Added
- Initial release
- StructuralAnomalyScanner: detects PHP files in non-standard locations
- ObfuscatedCodeScanner: detects eval/base64, gzinflate, str_rot13 patterns and more
- HtaccessScanner: detects dangerous .htaccess directives
- BaselineDiffScanner: filesystem baseline snapshots and diff comparison
- EnvIntegrityScanner: .env file integrity checks
- `scalpel:scan` command with --only and --format options
- `scalpel:baseline` command for creating filesystem snapshots
- `scalpel:diff` command for comparing against baseline
- Configurable non-PHP zones, obfuscation patterns, and exclusions
- CI/CD integration via exit codes
- JSON output format for machine-readable results
