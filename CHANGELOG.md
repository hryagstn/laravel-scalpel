# Changelog

All notable changes to `laravel-scalpel` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
