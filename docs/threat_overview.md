# Technical Threat Overview: PHP2Shell (CVE-2026-109618 & CVE-2026-109619)

**Vulnerability Classification:** Dual Zero-Day Remote Code Execution (RCE) Chain  
**Severity:** Critical — CVSS v4.0 Score: 9.2  
**Vector:** Unauthenticated HTTP/HTTPS Multipart Request Handling  
**First Observed Exploitation:** October 17, 2026 (4 days prior to public disclosure)  

---

## 1. Executive Summary

In October 2026, two critical vulnerabilities in the core PHP runtime interpreter were publicly disclosed and simultaneously exploited in the wild. Collectively tracked as **PHP2Shell**, these flaws enable unauthenticated remote code execution with the permissions of the underlying web worker process across virtually every web application running on vulnerable versions of PHP (including WordPress, Drupal, Magento, Laravel, and custom application codebases).

Because the flaws reside within PHP's core memory allocator and multipart request handler (`rfc1867.c`), vulnerabilities trigger **before application routing or framework authorization logic executes**.

---

## 2. Vulnerability Deep Dive

### CVE-2026-109618: Out-of-Memory (OOM) Multipart Memory Corruption
- **Component:** `main/rfc1867.c` (RFC 1867 Multipart/Form-Data Parser)
- **Vulnerability Type:** CWE-119 / CWE-400 (Memory Allocation Handling Failure)
- **Mechanics:**
  When a web client transmits a multipart form request, PHP parses headers, boundary tokens, and file content incrementally. If an allocation exhausts `memory_limit` during request initialization, PHP aborts execution via a longjmp/bailout mechanism.
  During this bailout, internal data structures (`zval`, hash tables, file upload trackers) remain only partially initialized. When PHP executes request shutdown handlers (`php_request_shutdown`), cleanup routines treat these partially initialized memory structures as valid, leading to heap corruption and potential memory disclosure or code execution.
- **Trigger Surface:** Attackers construct deeply nested array field names (e.g., `f0[k0][k1]...[k59]`) or repeated payload buffers that push memory consumption to the boundary edge without exceeding the web server's request body limit.

### CVE-2026-109619: Cross-Request Use-After-Free (UAF)
- **Component:** Zend Engine Request Lifecycle & Worker Memory Recycling
- **Vulnerability Type:** CWE-416 (Use-After-Free)
- **Mechanics:**
  In multi-request persistent worker architectures (e.g. PHP-FPM worker pools, Apache MPM event/worker with mod_php, FrankenPHP, and LiteSpeed LSPHP), workers handle multiple sequential requests before terminating.
  Under CVE-2026-109619, request-owned pointers and state fail to clear cleanly when execution is interrupted by memory bailouts, timeouts, or unhandled fatal errors. The worker retains stale memory pointers across the request boundary. When the subsequent request is assigned to that recycled worker, it references dangling pointers, allowing an adversary to manipulate memory layout and execute arbitrary machine code.

---

## 3. Timeline of Exploitation

| Date / Time (UTC) | Event |
|---|---|
| **2026-10-17** | **First Observed In-The-Wild Exploitation**: Amazon MadPot honeypot sensors record earliest targeted attack probing session upload progress handlers from anonymized IP `103.216.220.92`. |
| **2026-10-20 21:57** | **Memory Pressure Probing**: OffSeq Mirage sensor fleet observes 1 MB multipart request sweeps designed to identify memory bailout thresholds. |
| **2026-10-21 02:00** | **Pre-Disclosure Leak**: Technical details leak into public channels; multiple weaponized PoCs begin circulating on threat forums. |
| **2026-10-21 14:00** | **Coordinated Patch Release**: PHP project releases versions 8.5.12, 8.4.27, 8.3.36, and 8.2.35. |
| **2026-10-21 16:21** | **Mass Exploitation Wave**: Automated scanning networks and multi-actor botnet infrastructure launch worldwide exploitation sweeps. |
| **2026-10-22** | **National Cyber Security Alerts**: Amazon AWS, Wordfence, and NCSC-NL publish urgent threat advisories noting widespread active campaigns. |

---

## 4. Affected SAPI Matrix

| Server API (SAPI) | Risk Profile | Exploitation Timing & Impact |
|---|---|---|
| **Apache `mod_php`** | **CRITICAL (Highest)** | Executes directly inside Apache worker thread. Can trigger and exploit before any application code, `.htaccess`, or PHP router executes. |
| **PHP-FPM** | **CRITICAL** | Default architecture for modern Nginx, Caddy, and Apache deployments. Worker reuse enables reliable CVE-2026-109619 UAF exploitation. |
| **FrankenPHP** | **CRITICAL** | Worker-mode execution keeps state in memory; highly susceptible to cross-request persistence. |
| **LiteSpeed / LSPHP** | **CRITICAL** | Process recycling enables pointer hijack. |
| **PHP-CGI** | **HIGH** | Out-of-memory corruption triggers worker crash and memory disclosure. |

---

## 5. Affected Version Matrix

| PHP Branch | Vulnerable Versions | Fixed Upstream Version | Patch Status |
|---|---|---|---|
| **8.5** | <= 8.5.11 | **8.5.12** | Active Support |
| **8.4** | <= 8.4.26 | **8.4.27** | Active Support |
| **8.3** | <= 8.3.35 | **8.3.36** | Security-Only Support |
| **8.2** | <= 8.2.34 | **8.2.35** | Security-Only Support |
| **8.1** | All versions | Source backport only | End of Life (EOL) |
| **8.0** | All versions | Source backport only | End of Life (EOL) |
| **7.4** | All versions | Source backport only | End of Life (EOL) |
| **<= 7.3** | All versions (5.4 to 7.3) | **No official patch** | End of Life (EOL) — Mitigate immediately |
