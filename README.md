[![Build Status](https://img.shields.io/github/actions/workflow/status/hryagstn/laravel-scalpel/tests.yml?branch=main&style=flat-square)](https://github.com/hryagstn/laravel-scalpel/actions)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/hryagstn/laravel-scalpel.svg?style=flat-square)](https://packagist.org/packages/hryagstn/laravel-scalpel)
[![PHP Version](https://img.shields.io/packagist/php-v/hryagstn/laravel-scalpel?style=flat-square)](https://packagist.org/packages/hryagstn/laravel-scalpel)
[![Laravel Version](https://img.shields.io/badge/laravel-10.x%20|%2011.x%20|%2012.x%20|%2013.x-blue?style=flat-square)](https://packagist.org/packages/hryagstn/laravel-scalpel)
[![License](https://img.shields.io/packagist/l/hryagstn/laravel-scalpel?style=flat-square)](LICENSE)

# 🔪 laravel-scalpel

**Intrusion Evidence Scanner for Laravel**

A zero-dependency, filesystem-level forensic scanner that detects signs of compromise in your Laravel application — obfuscated backdoors, rogue PHP files, tampered `.htaccess` directives, missing `.env` files, and unexpected filesystem changes.

---

## 🚨 The Problem

It often starts the same way: a production Laravel app is quietly compromised. Obfuscated PHP backdoors appear in directories like `public/icons/` or `storage/`. An `.htaccess` file is modified to allow Python script execution. The `.env` file is deleted or tampered with to disable error reporting and cover tracks.

These attacks don't trigger your WAF. They don't show up in your application logs. The malicious files sit silently on disk, waiting.

**laravel-scalpel is not a WAF, firewall, or runtime protection layer.** It is a *forensic filesystem scanner* — a post-incident or preventive tool that examines your project's file structure and contents for evidence of intrusion. Think of it as a security audit you can run on-demand or in CI/CD.

Unlike configuration auditors that check for *potential* vulnerabilities, 
laravel-scalpel looks for *evidence that a compromise has already occurred* — 
making it the tool you reach for when something feels wrong, not just as a 
preventive checklist.

---

## 📦 Installation

```bash
composer require hryagstn/laravel-scalpel
```

Publish the configuration file:

```bash
php artisan vendor:publish --tag=scalpel-config
```

This creates `config/scalpel.php` where you can customize scan behavior, exclusion lists, and severity thresholds.

> **Requirements:** PHP 8.1+ · Laravel 10.x, 11.x, 12.x, or 13.x

---

## ⚡ Quick Start

Run all scanners at once:

```bash
php artisan scalpel:scan
```

Create a filesystem baseline snapshot:

```bash
php artisan scalpel:baseline
```

Compare current state against the baseline:

```bash
php artisan scalpel:diff
```

That's it. Three commands to audit your entire project for intrusion evidence.

> **Important:** Always run `vendor:publish` and complete your initial setup 
> **before** running `scalpel:baseline`. The baseline should capture your 
> application's known-good state after all configuration is in place.

---

## 📖 Command Reference

### `scalpel:scan`

Run one or more scanners against your project.

```bash
# Run all scanners
php artisan scalpel:scan

# Run specific scanners only
php artisan scalpel:scan --only=structural,obfuscated

# Output results as JSON (for machine consumption)
php artisan scalpel:scan --format=json
```

**Options:**

| Option     | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| `--only`   | Comma-separated list of scanners to run: `structural`, `obfuscated`, `htaccess`, `env` |
| `--format` | Output format: `table` (default) or `json`                                 |

**Exit codes:**

| Code | Meaning                                      |
|------|----------------------------------------------|
| `0`  | No findings (clean)                          |
| `1`  | Findings detected (CRITICAL or HIGH)         |
| `2`  | Findings detected (MEDIUM or LOW only)       |

---

### `scalpel:baseline`

Create a snapshot of your project's current filesystem state. This snapshot is stored at the path configured in `scalpel.baseline_path` (default: `storage/app/private/scalpel/baseline.json`).

```bash
# Create a baseline (fails if one already exists)
php artisan scalpel:baseline

# Overwrite an existing baseline
php artisan scalpel:baseline --force
```

**Options:**

| Option    | Description                          |
|-----------|--------------------------------------|
| `--force` | Overwrite an existing baseline file  |

---

### `scalpel:diff`

Compare the current filesystem state against a previously created baseline snapshot. Reports added, removed, and modified files.

```bash
# Compare against baseline
php artisan scalpel:diff

# Output diff as JSON
php artisan scalpel:diff --format=json
```

**Options:**

| Option     | Description                                    |
|------------|------------------------------------------------|
| `--format` | Output format: `table` (default) or `json`     |

**Exit codes:** Same as `scalpel:scan`.

---

## 🔍 How It Works

laravel-scalpel ships with five independent scanners. Each focuses on a specific class of intrusion evidence.

### Structural Anomaly Scanner

Detects PHP files in directories where they should never exist — `public/`, `storage/`, `bootstrap/cache/`, and any other paths you define as "non-PHP zones."

Attackers commonly drop webshells into public-facing directories disguised as image folders (e.g., `public/icons/shell.php`). This scanner catches them.

- Scans all configured `non_php_zones` for `.php` files
- Automatically excludes known legitimate files (`public/index.php`) and directories (`public/vendor/`)
- Configurable allow-lists for both files and directories

### Obfuscated Code Scanner

Detects common PHP obfuscation patterns used in backdoors and webshells. Scans all `.php` files in the project for:

| Pattern                | Description                                        | Severity |
|------------------------|----------------------------------------------------|----------|
| `eval(base64_decode)`  | Classic obfuscation — decode and execute            | CRITICAL |
| `eval(gzinflate)`      | Compressed payload execution                        | CRITICAL |
| `eval(str_rot13)`      | ROT13 obfuscation with eval                         | CRITICAL |
| `eval(gzuncompress)`   | Compressed payload execution (variant)              | CRITICAL |
| `eval(gzdecode)`       | Compressed payload execution (variant)              | CRITICAL |
| `assert()` with vars   | Dynamic code execution via assert                   | HIGH     |
| Variable functions     | `$var()` style dynamic function calls               | MEDIUM   |
| `preg_replace` `/e`    | Code execution via deprecated regex modifier        | HIGH     |
| Long encoded strings   | Suspiciously long base64/hex strings (≥500 chars)   | MEDIUM   |

Each pattern can be individually toggled in the configuration.

### Htaccess Scanner

Scans all `.htaccess` files in your project for dangerous directives that could allow execution of non-PHP scripts. Attackers often modify `.htaccess` to register Python, Perl, or CGI handlers, enabling them to run arbitrary scripts through the web server.

Detects:
- `AddHandler` directives mapping to dangerous script types
- `AddType` directives mapping to dangerous MIME types
- Custom handler registrations for `cgi-script`, `python-program`, `perl-script`, etc.

### Baseline Diff Scanner

Creates a cryptographic snapshot of your entire project filesystem and detects changes over time. This is your "known good state" mechanism.

**Workflow:**
1. Run `php artisan scalpel:baseline` after a clean deployment
2. Run `php artisan scalpel:diff` periodically or in CI to detect unauthorized changes
3. Added, removed, or modified files are reported with severity ratings

Baseline snapshots exclude volatile directories like `storage/logs/`, `storage/framework/cache/`, and other paths configured in `baseline_excluded_paths`.

### Env Integrity Scanner

Verifies the existence and basic integrity of your `.env` file. Attackers sometimes delete or truncate the `.env` file to disable error reporting, remove debug information, or reset application keys.

Checks:
- `.env` file exists
- `.env` file is not empty
- `.env` file is readable

---

## ⚙️ Configuration Reference

After publishing, the configuration file lives at `config/scalpel.php`. Below is a reference for every key.

### `non_php_zones`

Directories where PHP files should not exist. Relative to the project root.

```php
'non_php_zones' => [
    'public',
    'storage',
    'bootstrap/cache',
],
```

### `structural_allowed_files`

Individual files within non-PHP zones that are known to be legitimate. Relative to the project root.

```php
'structural_allowed_files' => [
    'public/index.php',
],
```

### `structural_allowed_directories`

Subdirectories within non-PHP zones where PHP files are expected (e.g., published assets).

```php
'structural_allowed_directories' => [
    'public/vendor',
],
```

### `excluded_paths`

Paths to exclude from **all** scanners. Relative to the project root.

```php
'excluded_paths' => [
    'vendor',
    'node_modules',
    '.git',
],
```

### `obfuscation_patterns`

Toggle individual obfuscation detection patterns on or off.

```php
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
```

### `long_string_threshold`

Minimum character length for a string to be flagged as a suspiciously long encoded payload.

```php
'long_string_threshold' => 500,
```

### `htaccess_dangerous_handlers`

Script handlers and MIME types that are flagged when found in `.htaccess` directives.

```php
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
```

### `baseline_excluded_paths`

Additional paths excluded from baseline snapshots and diff comparisons (on top of `excluded_paths`).

```php
'baseline_excluded_paths' => [
    'storage/logs',
    'storage/framework/cache',
    'storage/framework/sessions',
    'storage/framework/views',
    'storage/app/private/scalpel',
],
```

### `baseline_path`

Where the baseline snapshot JSON file is stored, relative to `storage/app/private/` (or `storage/app/` depending on your local disk configuration).

```php
'baseline_path' => 'scalpel/baseline.json',
```

### `severity_threshold`

Minimum severity level to include in results. Findings below this level are silently filtered out. Options: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.

```php
'severity_threshold' => 'LOW',
```

---

## 🔄 CI/CD Integration

laravel-scalpel uses exit codes to signal results, making it straightforward to integrate into CI/CD pipelines.

### GitHub Actions Example

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM UTC

jobs:
  scalpel-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'

      - name: Install Dependencies
        run: composer install --no-interaction --prefer-dist

      - name: Run Scalpel Scan
        run: php artisan scalpel:scan --format=json

      - name: Run Baseline Diff
        run: php artisan scalpel:diff --format=json
```

> **Tip:** Store a baseline snapshot in your repository (or generate it during deployment) so `scalpel:diff` can detect unauthorized post-deployment changes.

## Known False Positives

**`bootstrap/cache/` files modified or deleted**
These files are regenerated by Laravel when running `php artisan optimize` 
or `php artisan optimize:clear`. If you see changes here after running 
these commands, it is expected. If you see changes without having run 
these commands, investigate immediately.

## Recommended Workflow

1. Deploy new code
2. Run `php artisan optimize`
3. Run `php artisan scalpel:baseline --force`

This ensures the baseline always reflects the post-deployment known-good state.

## Automation & Monitoring

Pair laravel-scalpel with [n8n-bastion](https://github.com/hryagstn/n8n-bastion)
for automated scheduled scanning and real-time Telegram alerts when
CRITICAL or HIGH findings are detected on your VPS.

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`composer test`)
5. Commit your changes (`git commit -m 'Add my feature'`)
6. Push to your branch (`git push origin feature/my-feature`)
7. Open a Pull Request

Please make sure your code follows the existing style and includes appropriate tests.

---

## 📄 License

laravel-scalpel is open-sourced software licensed under the [MIT License](LICENSE).
