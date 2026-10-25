# Mitigation and Hardening Guide: PHP2Shell

**Vulnerabilities:** CVE-2026-109618 & CVE-2026-109619  
**Impact:** Unauthenticated Remote Code Execution (RCE)  

---

## 1. Primary Remediation: Upgrade PHP Runtime

The **only complete and permanent fix** is to update the PHP interpreter to an official release containing patches for both CVE-2026-109618 and CVE-2026-109619.

### Official Upstream Releases
Ensure your PHP package is at or above these versions:
- **PHP 8.5 Branch:** Upgrade to **`8.5.12`** or later.
- **PHP 8.4 Branch:** Upgrade to **`8.4.27`** or later.
- **PHP 8.3 Branch:** Upgrade to **`8.3.36`** or later.
- **PHP 8.2 Branch:** Upgrade to **`8.2.35`** or later.

### Linux Distribution Packages
Major Linux vendors (Debian, Ubuntu, Red Hat Enterprise Linux, AlmaLinux, Alpine, SUSE) backported security fixes to their respective package versions. Check package change logs to verify patch inclusion:

```bash
# Debian / Ubuntu:
apt-get update && apt-get --only-upgrade install php*-common php*-fpm

# RHEL / Rocky Linux / AlmaLinux:
dnf upgrade php php-fpm php-common

# Alpine Linux:
apk update && apk upgrade php83 php83-fpm
```

> **CRITICAL**: After upgrading packages, **you must restart web server and PHP daemon processes** (e.g. `systemctl restart php-fpm` or `systemctl restart apache2`). Simply replacing files on disk does not patch running workers in memory.

---

## 2. Temporary Mitigations (If Immediate Upgrading is Not Feasible)

If an environment runs End-of-Life PHP (e.g. PHP 5.4 through 8.1) or cannot immediately reboot/upgrade production clusters, apply these compensatory controls:

### Mitigation A: Disable Session Upload Progress
The overwhelming majority of active PHP2Shell exploit tooling relies on the built-in session upload progress tracking feature (`session.upload_progress.enabled`). This feature is **enabled by default** in stock PHP distributions and does not require an application to explicitly invoke `session_start()`.

Edit your `php.ini` configuration (typically `/etc/php/[version]/fpm/php.ini` and `/etc/php/[version]/cli/php.ini`):

```ini
; Disable upload progress tracking
session.upload_progress.enabled = Off
```

Apply the change by restarting the PHP service:
```bash
sudo systemctl restart php*-fpm
```

### Mitigation B: Restrict Request Body Sizes at Web Server Reverse Proxy
Attackers deliver large multipart payloads (1 MB to 2 MB) filled with junk bytes and nested parameters to force PHP to trigger out-of-memory bailouts. Restrict maximum client request body sizes on reverse proxies to the minimum needed by the application:

#### Nginx
```nginx
# Limit client upload body size to 10MB (or lower if uploads are not required)
client_max_body_size 10M;
```

#### Apache HTTP Server
```apache
# Limit HTTP request body size to 10MB
LimitRequestBody 10485760
```

---

## 3. Architecture Hardening: Deprecate `mod_php`

If you are running Apache with `mod_php` (`libapache2-mod-php`), **migrate to PHP-FPM immediately**.

### Why `mod_php` is Exceptionally Dangerous
In `mod_php`, the PHP interpreter runs inside the Apache worker process itself. The vulnerability triggers before any request filtering or application hooks can run, and memory corruption can directly hijack the web server thread.

### Migration Steps (Debian/Ubuntu Example)
```bash
# 1. Install PHP-FPM
sudo apt update && sudo apt install php8.3-fpm

# 2. Disable mod_php and mpm_prefork
sudo a2dismod php8.3
sudo a2dismod mpm_prefork

# 3. Enable mpm_event, proxy, and proxy_fcgi
sudo a2enmod mpm_event proxy proxy_fcgi setenvif

# 4. Enable PHP-FPM configuration and restart
sudo a2enconf php8.3-fpm
sudo systemctl restart apache2
sudo systemctl restart php8.3-fpm
```
