<p align="center">
  <img src="docs/logo.png" alt="Laravel Scalpel Logo" width="120">
</p>

<h1 align="center">Security Policy</h1>

We take the security of **Laravel Scalpel** seriously. If you believe you have found a security vulnerability in this package, please report it to us responsibly using the instructions below.

---

## Supported Versions

Currently, the following versions of Laravel Scalpel receive security updates and support:

| Version | Supported | PHP Version | Laravel Version |
|---------|-----------|-------------|-----------------|
| `1.x`   | Yes       | `8.1+`      | `10.x`, `11.x`, `12.x`, `13.x` |
| `< 1.0` | No        | `8.1`       | `10.x`, `11.x` |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub issues.**

Instead, please submit any security-related findings through one of the following private channels:

1. **GitHub Private Vulnerability Reporting:** Go to the [Security tab](https://github.com/hryagstn/laravel-scalpel/security) of our repository, click on **Advisories**, and then click **Report a vulnerability**.
2. **Direct Email:** Send an email to **harry.agustiana@gmail.com**.

When reporting, please include as much detail as possible to help us reproduce and address the issue:
* A clear description of the vulnerability.
* Step-by-step instructions or a proof-of-concept (PoC) to reproduce the vulnerability.
* The potential impact or how an attacker could exploit the issue.
* Your recommended mitigation steps, if any.

Once received, we will:
* Acknowledge receipt of your report within **48 hours**.
* Work on a fix and coordinate a release.
* Provide credit to you in the security advisory/changelog (unless you prefer to remain anonymous).

---

## Security Model & Limitations

Laravel Scalpel is a **detection layer** rather than a containment or sandbox layer. 

### In-Process Execution Boundary
Because Laravel Scalpel runs as a PHP Artisan command within your web application's environment:
* It executes with the same operating system user and permissions as your web server/PHP process (e.g., `www-data`).
* It shares the same memory namespace, process space, and filesystem access as standard web requests.
* It operates within the same trust boundary as the application code it is inspecting.

### Known Limitations
If an attacker achieves arbitrary code execution (ACE) with write permissions:
* They could theoretically modify the Laravel Scalpel source files or configuration keys to suppress scan results.
* They could delete or tamper with generated JSON reports to hide signs of intrusion.

### Recommended Hardening
To secure your Laravel Scalpel deployment in production:
1. **Trigger Scans Externally:** Execute scans via a system cron job or task runner (e.g., `sentinel.sh` in [n8n-bastion](https://github.com/hryagstn/n8n-bastion)) running under a separate, secure user profile rather than web-accessible triggers.
2. **Infrastructure Isolation:** Use read-only filesystems (e.g., in Docker containers) for code zones (`app/`, `bootstrap/`, `config/`, `public/`) so that code cannot be modified, making scans highly robust and predictable.
3. **Output Signature Verification:** Always enable **HMAC Output Signing** in `config/scalpel.php` and use the `scalpel:verify` command to verify reports before pushing them to log consumers.
