# Detection Engineering & Threat Hunting Guide: PHP2Shell

**Target Vulnerabilities:** CVE-2026-109618 (Multipart OOM) & CVE-2026-109619 (UAF)  
**Attack Surface:** HTTP Multipart parsing and Web Worker Process Execution  

Because PHP2Shell exploits occur in the runtime layer before application logging runs, **traditional web application access logs may record normal 200/500 HTTP responses without visible payload indicators**. Defenders must implement multi-layered detection across network perimeter, WAF, endpoint process auditing (EDR), and Linux host telemetry.

---

## 1. Sigma Detection Rule

This rule detects PHP web server workers (`php-fpm`, `apache2`, `httpd`, `frankenphp`, `lsphp`) spawning interactive shells, command interpreters, or download utilities.

```yaml
title: Suspicious Child Process Spawned by PHP Web Worker (PHP2Shell)
id: 3b0f6c2e-9a41-4d7e-8f5a-6c1d2e7b9a10
status: experimental
description: Detects PHP worker processes spawning command shells, network reconnaissance utilities, or scripting interpreters following exploitation of CVE-2026-109618 / CVE-2026-109619.
references:
    - https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
    - https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
author: php2shell-ioc Security Contributors
date: 2026/10/22
tags:
    - attack.initial-access
    - attack.t1190
    - attack.execution
    - attack.t1059.004
    - attack.persistence
    - attack.t1505.003
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/php-fpm'
            - '/php-cgi'
            - '/httpd'
            - '/apache2'
            - '/frankenphp'
            - '/lsphp'
    selection_parent_versioned:
        ParentImage|contains:
            - '/php-fpm'
            - '/php8.'
            - '/php7.'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
            - '/zsh'
            - '/curl'
            - '/wget'
            - '/python'
            - '/python3'
            - '/perl'
            - '/nc'
            - '/ncat'
            - '/netcat'
            - '/socat'
            - '/busybox'
    condition: (1 of selection_parent* ) and selection_child
falsepositives:
    - Web applications legitimately executing image transformation utilities (e.g. ImageMagick `convert`) or PDF generators. Tune allowlists per specific application environment.
level: high
```

---

## 2. Web Application Firewall (WAF) Inspection Rules

### ModSecurity / OWASP Coraza WAF
Ensure `SecRequestBodyAccess On` is enabled in your engine configuration.

```apache
# ------------------------------------------------------------------------
# PHP2Shell Request Mitigation Rules (CVE-2026-109618 / CVE-2026-109619)
# ------------------------------------------------------------------------

# Rule 96181: Known exploit tool multipart boundary header
SecRule REQUEST_HEADERS:Content-Type "@contains p2shell" \
    "id:96181,phase:1,deny,status:403,log,\
    msg:'PHP2Shell: exploit tool multipart boundary detected',\
    tag:'CVE-2026-109618',tag:'CVE-2026-109619'"

# Rule 96182: Known exploit scanner User-Agent
SecRule REQUEST_HEADERS:User-Agent "@beginsWith B8RAT/" \
    "id:96182,phase:1,deny,status:403,log,\
    msg:'PHP2Shell: B8RAT exploit scanner client'"

# Rule 96183: Deeply nested multipart field names (20+ nesting levels)
SecRule ARGS_NAMES|FILES_NAMES "@rx (?:\[[^\]]*\]){20,}" \
    "id:96183,phase:2,deny,status:403,log,\
    msg:'PHP2Shell: deeply nested multipart array parameter attack'"

# Rule 96184: PHP Session Upload Progress indicator in unexpected paths (Log Only)
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
    "id:96184,phase:2,pass,log,\
    msg:'PHP2Shell: PHP_SESSION_UPLOAD_PROGRESS key observed in request'"
```

---

## 3. SIEM & EDR Threat Hunting Queries

### Microsoft Defender XDR (Kusto Query Language / KQL)
```kql
// Query 1: Suspicious child process spawned from PHP web server worker
DeviceProcessEvents
| where Timestamp >= datetime(2026-10-17)
| where InitiatingProcessFileName has_any ("php-fpm", "php-cgi", "httpd", "apache2", "frankenphp", "lsphp")
| where FileName in~ ("sh", "bash", "dash", "curl", "wget", "python3", "perl", "nc", "ncat", "socat")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine

// Query 2: Inbound traffic matching PHP2Shell IoC Blocklist
let php2shell_ips = dynamic(["103.216.220.92","31.223.184.166","37.19.200.5","134.209.159.64","103.114.163.188","95.217.98.37","94.154.43.7","38.180.45.91","80.66.66.66","217.60.242.76","87.192.237.19","34.19.34.88","34.76.232.95","34.76.218.47","194.42.196.44","206.188.197.105"]);
DeviceNetworkEvents
| where Timestamp >= datetime(2026-10-17)
| where RemoteIP in (php2shell_ips)
| project Timestamp, DeviceName, ActionType, RemoteIP, LocalPort, InitiatingProcessFileName
```

### Splunk Search Processing Language (SPL)
```spl
index=* sourcetype="sysmon:linux" OR sourcetype="linux_secure"
| where parent_process_name IN ("php-fpm", "php-cgi", "httpd", "apache2", "frankenphp", "lsphp")
| where process_name IN ("sh", "bash", "dash", "curl", "wget", "python3", "perl", "nc", "ncat")
| stats count min(_time) as earliest max(_time) as latest by host, parent_process_name, process_name, process
```

### Elasticsearch (ES|QL)
```sql
FROM logs-endpoint.events.process-*
| WHERE @timestamp >= "2026-10-17T00:00:00Z"
  AND process.parent.name IN ("php-fpm", "php-cgi", "httpd", "apache2", "frankenphp", "lsphp")
  AND process.name IN ("sh", "bash", "dash", "curl", "wget", "python3", "perl", "nc", "ncat")
| KEEP @timestamp, host.name, process.parent.name, process.name, process.command_line
| SORT @timestamp DESC
```

---

## 4. Linux Host-Level Forensic Audit

Execute these read-only commands on servers running PHP to look for signs of exploitation attempts:

```bash
# 1. Search for PHP worker segfaults and heap corruption messages
grep -hE "SIGSEGV|exited on signal 11|zend_mm_heap corrupted" \
    /var/log/php*-fpm.log /var/log/apache2/error.log* /var/log/httpd/error_log* 2>/dev/null | tail -50

# 2. Check for fatal errors thrown before request script execution (Unknown on line 0)
grep -hE "in Unknown on line 0" \
    /var/log/php*.log /var/log/apache2/error.log* /var/log/httpd/error_log* 2>/dev/null | tail -50

# 3. Look for memory exhaustion bursts (indicates attacker threshold calibration)
grep -hc "Allowed memory size" \
    /var/log/php*.log /var/log/apache2/error.log* 2>/dev/null

# 4. Check session files containing embedded PHP script tags or upload progress
grep -lE "<\?php|upload_progress_" /var/lib/php/sessions/* 2>/dev/null

# 5. Locate newly modified or created PHP files in web roots since Oct 17, 2026
find /var/www /srv/http -type f -name "*.php" -newermt "2026-10-17" 2>/dev/null
```
