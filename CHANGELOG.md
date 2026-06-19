# Changelog

All notable changes to `laravel-scalpel` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-06-19

### Added
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
