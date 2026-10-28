# PHP-Hardening-Kit 🛡️

[![CI Test Matrix](https://github.com/Anton-Barinov/PHP-Hardening-Kit/actions/workflows/ci.yml/badge.svg)](https://github.com/Anton-Barinov/PHP-Hardening-Kit/actions/workflows/ci.yml)
[![PHP Versions](https://img.shields.io/badge/PHP-5.4%20to%208.4%2B-blue.svg)](https://www.php.net)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)](#architecture)
[![Fleet Tested](https://img.shields.io/badge/Fleet--Tested-OpenCart%20%7C%20WordPress%20%7C%20Bitrix%20%7C%20HestiaCP-orange.svg)](#compatibility)

> **Production-grade security hardening & hotfix toolkit for legacy and active PHP (5.4 through 8.4+).**  
> Neutralizes the Top-5 critical remote code execution (RCE) and injection attack vectors with **zero CMS code modifications**.

Developed and maintained by **[Anton Barinov](https://github.com/Anton-Barinov)** (creator of [`php2shell-patches`](https://github.com/Anton-Barinov/php2shell-patches) and [`TropaTT`](https://github.com/Anton-Barinov/TropaTT)).

---

## 🚨 Why PHP-Hardening-Kit?

Millions of production stores and portals run on legacy or EOL PHP versions (PHP 5.4–8.1) across **OpenCart, WordPress, Bitrix, Drupal, PrestaShop, HestiaCP, and aaPanel**. 

When critical vulnerabilities emerge, upstream vendors do not provide binary updates for EOL versions. Migrating an entire monolith to PHP 8.3/8.4 takes months, but servers are under active automated exploitation **today**.

**PHP-Hardening-Kit** bridges this gap:
1. **Drop-in Runtime WAF (`guard/`)**: Plugs into `auto_prepend_file` or `.user.ini`. Intercepts and blocks exploit vectors at sub-millisecond speeds (< 0.2ms) before application code ever runs.
2. **C-Level Core Patches (`patches/`)**: Battle-tested C-patches backported for PHP 5.4, 5.5, 5.6, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, and 8.1.
3. **Automated CLI Server Auditor (`bin/php-hardening-check`)**: Instantly inspects all installed PHP runtimes, pools, and ini settings for vulnerability exposure.
4. **Server Hardening Blueprints (`server-configs/`)**: Drop-in snippets for Nginx, Apache (`.htaccess`), and PHP-FPM pools.

---

## 🛡️ Top-5 Critical Attack Vectors Mitigated

| Vector | Vulnerabilities / CVEs | Severity | Upstream on EOL | PHP-Hardening-Kit Defense |
|---|---|:---:|:---:|---|
| **1. Multipart OOM & Upload Progress UAF** | **CVE-2026-109618**<br>**CVE-2026-109619**<br>**CVE-2026-115560** (*php2shell*) | **CRITICAL (9.8)** | ❌ Unpatched | Backported C-patches (`main/rfc1867.c`, `ext/session/session.c`) + Runtime WAF sanitization of progress keys & headers. |
| **2. CGI Argument Injection & Unicode Best-Fit** | **CVE-2024-4577**<br>**CVE-2012-1823** | **CRITICAL (9.8)** | ❌ Unpatched | Blocks `%ad` soft-hyphen best-fit mapping, `-d allow_url_include=1`, and CLI argument injection in SAPI parameters. |
| **3. PHP Filter Chains & Stream Wrapper RCE** | **CVE-2024-2961**<br>glibc iconv buffer overflow | **HIGH (8.8)** | ❌ Unpatched | Deep inspection of `php://filter` chains (depth limits), blocks vulnerable iconv charset sequences and `data://`/`expect://` exploits. |
| **4. Phar Deserialization & POP Gadget Chains** | **CVE-2018-17082**<br>PHPGGC POP Chains | **HIGH (8.1)** | ❌ Partial | Proactively blocks `phar://` stream wrappers in user input; detects serialized objects matching known exploit gadget signatures. |
| **5. Dangerous Function & Sendmail Injection** | **CVE-2016-10033**<br>**CVE-2016-10045**<br>Null-byte poisoning (`%00`) | **HIGH (7.8)** | ❌ Partial | Neutralizes `mail()` 5th parameter `-X`/`-O` web-shell drops, blocks `%00` path truncation, and provides strict `disable_functions` templates. |

---

## ⚡ Quick Server Audit (Zero-Install)

Audit your server across all multi-PHP stacks (CLI, FPM, cgi, aaPanel, HestiaCP, Plesk) in 3 seconds:

```bash
curl -fsSL https://raw.githubusercontent.com/Anton-Barinov/PHP-Hardening-Kit/main/bin/php-hardening-check | bash
```

### Advanced Auditor Modes:
* **Generate Emergency Remediation Commands for `php.ini`:**
  ```bash
  ./bin/php-hardening-check --fix-config
  ```
* **Non-Destructive Remote Web Audit against a live domain:**
  ```bash
  ./bin/php-hardening-check --url https://my-store.com
  ```
* **Machine-Readable JSON Output (for SIEM, Datadog, Prometheus, CI/CD):**
  ```bash
  ./bin/php-hardening-check --json
  ```

---

## 🚀 Installation & Deployment

### Option A: Per-Site Drop-In via Webroot (Recommended for CMS)

No root access or server restarts required. Deploy directly into your website directory:

```bash
git clone https://github.com/Anton-Barinov/PHP-Hardening-Kit.git
cd PHP-Hardening-Kit
./scripts/install.sh --install --webroot /var/www/my-store.com
```

This automatically configures `.user.ini` and `.htaccess` with zero downtime.

### Option B: System-Wide via `php.ini` (All Sites / Shared Hosting)

Add the runtime guard to your global `php.ini` or PHP-FPM pool:

```ini
; /etc/php/7.4/fpm/php.ini or /etc/php/*/fpm/pool.d/www.conf
auto_prepend_file = "/opt/PHP-Hardening-Kit/guard/php-hardening-kit.php"
```

Then restart your PHP-FPM service:
```bash
sudo systemctl restart php*-fpm
```

### Option C: Composer Integration

```bash
composer require anton-barinov/php-hardening-kit
```

---

## ⚙️ Configuration & Operational Modes

Copy `guard/config.sample.php` to `guard/config.php` to customize behavior:

```php
return [
    // 'block'   - Drop malicious requests with HTTP 403 (Default)
    // 'monitor' - Dry-run / audit mode: logs attacks without blocking
    // 'off'     - Disable inspection
    'mode' => 'block',

    'rules' => [
        'php2shell'            => true,
        'cgi_injection'        => true,
        'filter_chains'        => true,
        'phar_deserialization' => true,
        'command_mail_abuse'   => true,
    ],

    'logging' => [
        'enabled'     => true,
        'handler'     => 'file', // 'file', 'syslog', or 'error_log'
        'log_file'    => __DIR__ . '/../logs/security.log',
        'log_format'  => 'json',
    ],

    'whitelist' => [
        'ips'   => ['127.0.0.1'],
        'paths' => ['/admin/trusted-sync.php'],
    ],
];
```

---

## 📊 Benchmark & Performance

Tested on Intel Xeon E-2288G @ 3.70GHz, PHP 7.4 FPM under ApacheBench (`ab -n 10000 -c 100`):

| Metric | Without Guard | With PHP-Hardening-Kit | Impact |
|---|:---:|:---:|:---:|
| **Avg Request Latency** | 3.42 ms | 3.59 ms | **+0.17 ms** |
| **Memory Footprint** | 4.2 MB | 4.28 MB | **+80 KB** |
| **Throughput (req/sec)** | 2,840 | 2,795 | **< 1.6% overhead** |

---

## 🧪 Testing & Verification

The test suite validates both attack mitigation and zero false-positives against real-world CMS forms:

```bash
./tests/run-tests.sh
```

Tests include:
* ✅ Exploit vector simulations (CVE-2026-109618, CVE-2024-4577, CVE-2024-2961, CVE-2018-17082, CVE-2016-10033).
* ✅ OpenCart / Bitrix multilingual forms (Cyrillic, umlauts, CJK characters).
* ✅ Standard image uploads, multipart product attributes, and checkout webhooks.

---

## 🧩 Relationship with `php2shell-patches`

* **[`php2shell-patches`](https://github.com/Anton-Barinov/php2shell-patches)** was created as an emergency response specifically for the October 2026 PHP multipart & session upload progress exploit wave (CVE-2026-109618 / 19 / 60).
* **`PHP-Hardening-Kit`** is the comprehensive, long-term evolution: uniting C-level patches, zero-downtime runtime WAF guards, automated CLI auditing, and multi-vector defenses into a unified, modular toolkit.

---

## 👤 Author & Acknowledgments

Maintained by **Anton Barinov**  
GitHub: [@Anton-Barinov](https://github.com/Anton-Barinov)

If you find this toolkit valuable for safeguarding your servers and stores, please **★ Star the repository** and share it with DevOps and PHP communities!

Also check out **[TropaTT](https://github.com/Anton-Barinov/TropaTT)** — modern, free, self-hosted open-source CRM, project management, and automation platform with native AI agent support.

## 📄 License

This project is licensed under the [MIT License](LICENSE).
