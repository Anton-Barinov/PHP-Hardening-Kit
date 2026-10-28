# C-Level Patches for EOL PHP (5.4 – 8.1)

This directory contains battle-tested, C-level backported patches fixing critical vulnerabilities in the PHP core (`rfc1867.c`, `ext/session/session.c`, `Zend/zend_alloc.c`).

## Vulnerability Coverage

* **CVE-2026-109618**: Multipart form-data memory exhaustion leading to OOM bailout state corruption and unauthenticated RCE.
* **CVE-2026-109619**: Session upload progress use-after-free (UAF) causing dangling pointer reuse and arbitrary code execution.
* **CVE-2026-115560**: Session serializer mismatch RCE via corrupted upload progress delimiters.

---

## Patch Flavors

For each PHP version, you have choices depending on your requirements:

| Flavor | Best For | Description |
|---|---|---|
| **`*-minimal.patch`** | Conservative servers | Disables session upload progress entirely while fixing OOM bailout and multipart header limits. Upstream PHP-Group approach. |
| **`*-enhanced-universal.patch`** | E-commerce & CMS (OpenCart, WP, Bitrix) | **Root-cause fix** for UAF. Keeps session upload progress bars working, sanitizes session filenames, and resets serializer state. |
| **`*-enhanced-remicollet.patch`** | RHEL / AlmaLinux / CentOS / aaPanel | Tailored specifically for Remi Collet's backport trees (`remicollet/php-src-security`). |

---

## How to Apply & Build

### 1. For Vanilla Source Tarballs (php.net)

```bash
# Example for PHP 7.4:
cd /usr/src/php-7.4.33
patch -p1 < /path/to/PHP-Hardening-Kit/patches/php-7.4/php-7.4-enhanced-universal.patch

# Recompile:
make -j$(nproc)
make test
sudo make install
```

### 2. For Remi RPMs / Custom Spec Files

Add the patch to your `.spec` file:
```spec
Patch100: php-7.4-enhanced-remicollet.patch
%patch100 -p1
```

### 3. Pairing with Runtime Guard

If compiling PHP from source is not an option (shared hosting, unmanaged appliances), use the **[PHP-Hardening-Kit Runtime Guard](../guard/)** via `auto_prepend_file` to block exploitation at the application layer without rebuilding PHP binaries.
