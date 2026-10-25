# PHP2Shell Indicators of Compromise (IoC) & Threat Intelligence

[![CI / Testing](https://github.com/naravid19/php2shell-ioc/actions/workflows/lint-and-test.yml/badge.svg)](https://github.com/naravid19/php2shell-ioc/actions/workflows/lint-and-test.yml)
[![Scheduled Feed Update](https://github.com/naravid19/php2shell-ioc/actions/workflows/update-iocs.yml/badge.svg)](https://github.com/naravid19/php2shell-ioc/actions/workflows/update-iocs.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Active Indicators](https://img.shields.io/badge/Active%20IoCs-1%2C279-red.svg)](iocs/php2shell_iocs.csv)
[![PHP Versions Affected](https://img.shields.io/badge/PHP%20Affected-5.4%20--%208.5.11-critical.svg)](docs/threat_overview.md)

An open-source threat intelligence repository providing curated, normalized Indicators of Compromise (IoCs), detection engineering rules, and automated collection pipelines for the **PHP2Shell** zero-day vulnerabilities (**CVE-2026-109618** and **CVE-2026-109619**).

---

## 🚀 Quick Feeds for Defenders

These feeds are line-delimited plaintext blocklists directly consumable by firewalls (FortiGate, Palo Alto, pfSense), EDRs, and DNS sinkholes (Pi-hole) without authentication:

| Resource | Direct Raw Link | Description |
|---|---|---|
| **IPv4 Blocklist** | [`ips.txt`](https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/ips.txt) ([view](iocs/ips.txt)) | Plain list of unique attacking/scanning IPs |
| **Domain Blocklist** | [`domains.txt`](https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/domains.txt) ([view](iocs/domains.txt)) | Malicious domains used for C2 and dropper delivery |
| **SHA-256 Hashes** | [`hashes.txt`](https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/hashes.txt) ([view](iocs/hashes.txt)) | 64-char hashes of dropper payloads & webshells |
| **Canonical CSV** | [`php2shell_iocs.csv`](https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/php2shell_iocs.csv) ([view](iocs/php2shell_iocs.csv)) | Full dataset with timestamps, sources, and context |
| **Canonical JSON** | [`php2shell_iocs.json`](https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/php2shell_iocs.json) ([view](iocs/php2shell_iocs.json)) | Complete structured JSON dataset |

---

## ⚡ Threat Overview

| Attribute | Details |
|---|---|
| **Vulnerabilities** | **CVE-2026-109618** (OOM Multipart Corruption) & **CVE-2026-109619** (Worker Use-After-Free) |
| **Severity** | **Critical — CVSS v4.0: 9.2** |
| **Exploitation Vector** | Unauthenticated HTTP Multipart body parsing |
| **Impact** | Remote Code Execution (RCE) with web server worker privileges |
| **Affected Versions** | PHP 5.4 through 8.5.11 across all web SAPIs (`php-fpm`, `mod_php`, `frankenphp`, `lsphp`) |
| **Remediation** | Upgrade to **PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35** |

For an in-depth vulnerability breakdown and attack mechanics, read [docs/threat_overview.md](docs/threat_overview.md).

---

## 📚 Technical Documentation

- **[Threat Overview](docs/threat_overview.md)**: Technical breakdown of the OOM and Use-After-Free mechanics, exploitation timeline, and SAPI risk matrix.
- **[Detection & Hunting Guide](docs/detection_and_hunting.md)**: Sigma rules for PHP worker child processes, ModSecurity/Coraza WAF rules, KQL/Splunk/Elastic hunting queries, and host forensic commands.
- **[Mitigation & Hardening Guide](docs/mitigation.md)**: Official patching matrix, immediate `php.ini` mitigations (`session.upload_progress.enabled = Off`), and Apache `mod_php` deprecation steps.
- **[Defender Integration Guide](docs/ioc_guide.md)**: Step-by-step instructions for pfSense, FortiGate, Palo Alto Networks, Pi-hole, and SIEM automated ingestion.

---

## 🛠️ Collection & Development

This repository includes a test-driven, modular Python collector that aggregates and validates IoCs from structured vendor tables, CSV feeds, and threat bulletins.

### Quick Start
```bash
# Clone the repository
git clone https://github.com/naravid19/php2shell-ioc.git
cd php2shell-ioc

# Install dependencies (requests, beautifulsoup4, pytest)
pip install -r requirements.txt

# Run the test suite
python -m pytest -v

# Run the IoC collector
python scripts/collect_iocs.py
```

### CLI Options
- `--dry-run`: Parse and validate sources without writing files to disk.
- `--source <NAME>`: Run a specific configured source from `config/sources.json`.
- `--config <PATH>`: Provide custom source definitions.
- `--output-dir <PATH>`: Specify custom export directory.

---

## 🛡️ License

This project is licensed under the [MIT License](LICENSE).
