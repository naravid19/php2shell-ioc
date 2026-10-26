<a id="readme-top"></a>

<!-- PROJECT SHIELDS -->
<div align="center">

[![CI / Testing](https://img.shields.io/github/actions/workflow/status/naravid19/php2shell-ioc/lint-and-test.yml?branch=main&label=CI%20Pipeline&logo=githubactions&logoColor=white&style=flat-square)](https://github.com/naravid19/php2shell-ioc/actions/workflows/lint-and-test.yml)
[![Scheduled Feed Update](https://img.shields.io/github/actions/workflow/status/naravid19/php2shell-ioc/update-iocs.yml?branch=main&label=Feed%20Sync&logo=github&logoColor=white&style=flat-square)](https://github.com/naravid19/php2shell-ioc/actions/workflows/update-iocs.yml)
[![Active IoCs](https://img.shields.io/badge/Active%20IoCs-210%2B%20Verified-dc2626?style=flat-square&logo=shield)](iocs/php2shell_iocs.csv)
[![Vulnerability Severity](https://img.shields.io/badge/CVSS%20v4.0-9.2%20Critical-991b1b?style=flat-square)](docs/threat_overview.md)
[![PHP Affected](https://img.shields.io/badge/PHP%20Affected-5.4%20--%208.5.11-b91c1c?style=flat-square&logo=php&logoColor=white)](docs/threat_overview.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-0284c7?style=flat-square)](LICENSE)

</div>

<!-- PROJECT LOGO & HEADER -->
<div align="center">
  <br />
  <h1 align="center">PHP2Shell Indicators of Compromise (IoC)</h1>
  <p align="center">
    <strong>Curated threat intelligence feeds, high-fidelity blocklists, and detection engineering artifacts for PHP zero-day vulnerabilities (CVE-2026-109618 &amp; CVE-2026-109619).</strong>
    <br />
    <br />
    <a href="#-quick-feeds-for-defenders"><strong>Consume Feeds »</strong></a>
    &nbsp;·&nbsp;
    <a href="docs/threat_overview.md"><strong>Threat Overview</strong></a>
    &nbsp;·&nbsp;
    <a href="docs/detection_and_hunting.md"><strong>Detection Rules</strong></a>
    &nbsp;·&nbsp;
    <a href="docs/ioc_guide.md"><strong>Defender Guide</strong></a>
    &nbsp;·&nbsp;
    <a href="https://github.com/naravid19/php2shell-ioc/issues/new?labels=needs-triage&template=ioc_submission.md"><strong>Report IoC</strong></a>
  </p>
</div>

<br />

<!-- TABLE OF CONTENTS -->
<details>
  <summary><strong style="font-size: 1.05em;">Table of Contents</strong> (click to expand)</summary>
  <ol>
    <li><a href="#-about-the-project">About The Project</a>
      <ul>
        <li><a href="#core-principles">Core Principles</a></li>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li><a href="#-quick-feeds-for-defenders">Quick Feeds for Defenders</a>
      <ul>
        <li><a href="#automated-ingestion-snippets">Automated Ingestion Snippets</a></li>
      </ul>
    </li>
    <li><a href="#-vulnerability-matrix--threat-landscape">Vulnerability Matrix &amp; Threat Landscape</a></li>
    <li><a href="#-technical-documentation">Technical Documentation</a></li>
    <li><a href="#-getting-started--local-development">Getting Started &amp; Local Development</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation--setup">Installation &amp; Setup</a></li>
        <li><a href="#cli-usage">CLI Usage</a></li>
        <li><a href="#running-tests">Running Tests</a></li>
      </ul>
    </li>
    <li><a href="#-roadmap">Roadmap</a></li>
    <li><a href="#-contributing">Contributing</a></li>
    <li><a href="#-license--disclaimer">License &amp; Disclaimer</a></li>
    <li><a href="#-acknowledgments--sources">Acknowledgments &amp; Sources</a></li>
  </ol>
</details>

<br />

---

## 📌 About The Project

**PHP2Shell** refers to two actively exploited, critical zero-day vulnerabilities in PHP core:
- **CVE-2026-109618** (Out-Of-Memory Multipart Parser Corruption)
- **CVE-2026-109619** (PHP Worker Thread Use-After-Free)

These vulnerabilities allow unauthenticated attackers to achieve Remote Code Execution (RCE) on target web servers simply by delivering crafted multipart HTTP payloads—affecting PHP versions from **5.4 through 8.5.11** across all major Server APIs (`php-fpm`, `mod_php`, `frankenphp`, and `lsphp`).

This repository acts as an **authoritative, centralized defender asset**. It collects threat telemetry from global honeypots, vendor advisories, and active scanning networks, normalizes indicators into validated formats, and publishes line-delimited plain-text blocklists ready for instant firewall, EDR, and SIEM consumption.

### Core Principles

- **Defenders First**: Feeds are zero-friction and line-delimited. No API keys, tokens, or parsing wrappers are required for edge enforcement.
- **Strict Provenance**: Every indicator retains earliest `first_seen` timestamps, reporter attribution, confidence rating, and vulnerability context.
- **Zero Weaponized Code**: This repository does **not** host exploits, weaponized payloads, or binary drops.
- **Surgical & Lean**: Minimal standard-library-first pipelines with 100% test coverage and strict validation schemas.

### Built With

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Pytest-Automated%20Testing-0A9EDC?style=flat-square&logo=pytest&logoColor=white" alt="Pytest">
  <img src="https://img.shields.io/badge/GitHub%20Actions-Continuous%20Sync-2088FF?style=flat-square&logo=githubactions&logoColor=white" alt="GitHub Actions">
  <img src="https://img.shields.io/badge/Sigma-Detection%20Rules-FF6600?style=flat-square&logo=curseforge&logoColor=white" alt="Sigma">
  <img src="https://img.shields.io/badge/ModSecurity-WAF%20Virtual%20Patches-000000?style=flat-square&logo=owasp&logoColor=white" alt="OWASP ModSecurity">
</p>

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 🚀 Quick Feeds for Defenders

These feeds are raw, line-delimited plaintext blocklists served via GitHub raw CDN. They update automatically and are designed for direct drop-in integration into firewalls, proxies, EDRs, and DNS sinkholes:

| Feed Type | Raw URL (Copy &amp; Paste) | Format | Indicators | Refresh Cadence | Primary Use Case |
|:---|:---|:---|:---:|:---:|:---|
| **IPv4 Blocklist** | [`iocs/ips.txt`](https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/ips.txt) | Plain Text (`\n`) | `150+` | Daily / Scheduled | Firewall Inbound Drop (Palo Alto, FortiGate, pfSense) |
| **Domain Blocklist** | [`iocs/domains.txt`](https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/domains.txt) | Plain Text (`\n`) | `28` | Daily / Scheduled | DNS Sinkholes (Pi-hole, AdGuard), Proxy Deny Lists |
| **SHA-256 Hashes** | [`iocs/hashes.txt`](https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/hashes.txt) | Plain Text (`\n`) | `16` | Daily / Scheduled | EDR File Blocks (CrowdStrike, SentinelOne, Defender) |
| **Canonical CSV** | [`iocs/php2shell_iocs.csv`](https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/php2shell_iocs.csv) | CSV | `210+` | Daily / Scheduled | SIEM Data Lookups, SOAR Enrichment, SOC Analysis |
| **Canonical JSON** | [`iocs/php2shell_iocs.json`](https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/php2shell_iocs.json) | Structured JSON | `210+` | Daily / Scheduled | Automated Ingestion APIs, MISP &amp; Threat Intel Platforms |

### Automated Ingestion Snippets

Fetch the latest threat blocklists in real time with zero overhead:

```bash
# Ingest malicious IPv4 addresses
curl -sSL "https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/ips.txt" -o /etc/firewall/php2shell_ips.txt

# Ingest malicious C2 & dropper domains
curl -sSL "https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/domains.txt" -o /etc/pihole/php2shell_domains.txt

# Ingest malicious payload SHA-256 hashes
curl -sSL "https://raw.githubusercontent.com/naravid19/php2shell-ioc/main/iocs/hashes.txt" -o /etc/edr/php2shell_hashes.txt
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## ⚡ Vulnerability Matrix & Threat Landscape

> [!IMPORTANT]
> Both vulnerabilities are being exploited in the wild across unpatched enterprise workloads. Threat actors actively chain CVE-2026-109618 and CVE-2026-109619 to bypass modern ASLR implementations without requiring local information disclosure.

| Attribute | CVE-2026-109618 | CVE-2026-109619 |
|:---|:---|:---|
| **Vulnerability Class** | Out-of-Memory (OOM) Heap Buffer Corruption | Worker Thread / SAPI Use-After-Free (UAF) |
| **CVSS v4.0 Score** | **9.2 (Critical)** | **9.2 (Critical)** |
| **Attack Vector** | Network (`AV:N`) / Unauthenticated (`PR:N`) | Network (`AV:N`) / Unauthenticated (`PR:N`) |
| **Attack Complexity** | Low (`AC:L`) | Low (`AC:L`) |
| **User Interaction** | None (`UI:N`) | None (`UI:N`) |
| **Scope** | Changed (`S:C`) | Changed (`S:C`) |
| **Affected SAPIs** | `php-fpm`, `mod_php`, `frankenphp`, `lsphp` | `php-fpm`, `mod_php`, `frankenphp`, `lsphp` |
| **Affected Versions** | PHP 5.4 through 8.5.11 | PHP 5.4 through 8.5.11 |
| **Patched Releases** | **PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35** | **PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35** |
| **Emergency Workaround** | Disable `session.upload_progress.enabled` | Restrict body size &amp; deploy virtual WAF patches |

> For complete vulnerability deep-dives, heap layout analysis, and exploitation mechanics, see **[docs/threat_overview.md](docs/threat_overview.md)**.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 📚 Technical Documentation

Explore detailed architectural and operational documentation curated for blue teams, incident responders, and detection engineers:

| Document | Focus &amp; Contents | Primary Audience |
|:---|:---|:---|
| 📖 **[Threat Overview](docs/threat_overview.md)** | Technical analysis of OOM and UAF heap corruption, exploitation timelines, and SAPI impact matrix. | Threat Researchers &amp; Analysts |
| 🛡️ **[Detection & Hunting Guide](docs/detection_and_hunting.md)** | Sigma rules for PHP worker processes, ModSecurity/Coraza WAF rules, KQL/Splunk/Elastic hunting queries. | SOC Analysts &amp; Detection Engineers |
| 🔒 **[Mitigation & Hardening Guide](docs/mitigation.md)** | Official patching matrix, emergency `php.ini` mitigations (`upload_progress = Off`), and Apache hardening. | System Administrators &amp; DevOps |
| 🔌 **[Defender Integration Guide](docs/ioc_guide.md)** | Integration walk-throughs for FortiGate, Palo Alto PAN-OS, pfSense/pfBlockerNG, Pi-hole, and SIEMs. | Firewall Engineers &amp; Network Admins |

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 🛠️ Getting Started & Local Development

### Prerequisites

- **Python 3.10+**
- **Git**
- Optional: Virtual environment manager (`venv` / `pipenv` / `poetry`)

### Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/naravid19/php2shell-ioc.git
   cd php2shell-ioc
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   # On Linux / macOS:
   source .venv/bin/activate
   # On Windows PowerShell:
   .venv\Scripts\Activate.ps1
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### CLI Usage

Execute the collection pipeline locally against all configured sources:

```bash
# Run the collector across all sources in config/sources.json
python scripts/collect_iocs.py

# Perform a dry-run (validates and parses without overwriting output files)
python scripts/collect_iocs.py --dry-run

# Run against a single specific source
python scripts/collect_iocs.py --source fortiguard_outbreak

# Specify custom configuration or export directories
python scripts/collect_iocs.py --config config/sources.json --output-dir iocs/
```

### Running Tests

This project follows strict Test-Driven Development (TDD). Every parser, normalizer rule, and extraction path is covered by automated unit and regression tests:

```bash
# Run pytest with full verbosity
python -m pytest -v

# Run tests with short failure reporting
python -m pytest --tb=short
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 🗺️ Roadmap

- [x] Ingest initial honeypot telemetry (Amazon MadPot &amp; OffSeq Mirage baseline)
- [x] Integrate FortiGuard Outbreak intelligence feed
- [x] Build multi-format export pipeline (`csv`, `json`, `ips.txt`, `domains.txt`, `hashes.txt`)
- [x] Publish Sigma rules, ModSecurity virtual patches, and hunting queries
- [x] Implement automated GitHub Actions feed synchronization
- [ ] Implement direct MISP taxonomy export format (`misp-events.json`)
- [ ] Add STIX 2.1 / TAXII 2.1 server-compatible JSON endpoints
- [ ] Add Suricata / Snort 3 rule generator script from active IPs/domains

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 🤝 Contributing

Contributions from the cybersecurity community, blue teamers, and threat researchers are welcome!

1. Fork the Project.
2. Create your Feature / Indicator Branch (`git checkout -b feat/new-source-feed`).
3. If submitting new IoCs or parsers:
   - Ensure indicators have verified provenance or external report URLs.
   - Add parser test fixtures under `tests/`.
   - Run `pytest -v` to ensure 100% test pass rate.
4. Commit your changes (`git commit -m 'feat: add parser for vendor X threat bulletin'`).
5. Push to the Branch (`git push origin feat/new-source-feed`).
6. Open a Pull Request referencing the relevant issue.

Please consult our **[Agent & Contributor Guidelines](AGENTS.md)** and **[Triage Taxonomy](docs/agents/triage-labels.md)** for operational conventions.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 📄 License & Disclaimer

### License
Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for complete details.

### Disclaimer
> [!CAUTION]
> This repository contains curated threat intelligence intended exclusively for authorized network defense, threat hunting, incident response, and cybersecurity research. Indicators are observed malicious infrastructure from wild exploitation. Always review blocklists in accordance with your organization's operational change control policies prior to implementing blocking rules.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## 💬 Acknowledgments & Sources

Special acknowledgment to the threat researchers, honeypot operators, and threat intelligence teams tracking and publishing PHP2Shell telemetry:

- **[FortiGuard Labs](https://fortiguard.fortinet.com/outbreak-alert/php2shell)** — Outbreak alert and ongoing infrastructure telemetry.
- **[Amazon MadPot &amp; OffSeq Mirage](https://www.socnova.com/php-detection.html)** — Honeypot baseline telemetry.
- **[Amazon Threat Intelligence (AWS Security Blog)](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/)** — MadPot honeypot telemetry observed prior to public disclosure.
- **[OffSeq Threat Radar](https://radar.offseq.com/threat/php2shell-mass-exploitation-looms-for-leaked-critical-php-flaws-47d22162f363ef2c)** — Threat Radar active exploitation infrastructure &amp; campaign tracking.
- **[OffSeq Research](https://offseq.com/en/research/php2shell-first-48-hours/)** — Mirage honeypot fleet first 48-hour attack telemetry.
- **[Wordfence Threat Intelligence](https://www.wordfence.com/blog/2026/10/attacks-on-php2shell-continue-but-no-known-compromises-as-a-result-yet/)** — Firewall block tracking &amp; attack pattern analysis.
- **[Arctic Wolf Labs](https://arcticwolf.com/resources/blog/php2shell-critical-php-vulnerabilities-enable-unauthenticated-remote-code-execution/)** — Technical advisory and exploitation analysis.
- **[SOCRadar Threat Research](https://socradar.io/free-tools/ioc-radar/reports/php2shell-critical-php-rce-4b3415825163)** — IoC Radar telemetry and diamond model threat mapping.
- **[VulnCheck](https://www.vulncheck.com/blog/php2shell-vulnerabilities)** — In-the-wild exploitation tracking and dropper payload hashes.
- **[ThreatLandscape](https://threatlandscape.io/blog/php2shell-campaign-cve-2026-109618-216-hosts)** — Global scanning &amp; exploitation campaign across 216 hosts.
- **[Jorge Liauw / Google Threat Intelligence](https://jorgeliauw.nl/posts/php2shell-google-threat-intelligence-iocs-secops-detections/)** — Google SecOps &amp; GTI emerging threat detection rules.
- **[Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/cve-2026-109618-and-cve-2026-109619-php-vulnerable-unauthenticated-rce)** — Technical exploit analysis and attacking infrastructure telemetry.
- **[Best-README-Template](https://github.com/othneildrew/Best-README-Template)** — Structural layout and typography inspiration.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
