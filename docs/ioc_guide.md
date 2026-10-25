# Defender Integration Guide: Consuming PHP2Shell IoC Feeds

This guide explains how security engineers, firewall administrators, and SOC analysts can consume and ingest the blocklists provided in this repository directly into defensive infrastructure.

---

## 1. Raw Feed Endpoints

All blocklists are served as raw, line-delimited plain text files via GitHub's CDN. No token or authentication is required:

| Feed Type | URL | Description | Refresh Cadence |
|---|---|---|---|
| **IPv4 Blocklist** | `https://raw.githubusercontent.com/username/php2shell-ioc/main/iocs/ips.txt` | Clean list of unique attacking/scanning IPv4 addresses | Automated / Daily |
| **Domain Blocklist** | `https://raw.githubusercontent.com/username/php2shell-ioc/main/iocs/domains.txt` | Malicious FQDNs used for C2 and dropper delivery | Automated / Daily |
| **SHA-256 Hashes** | `https://raw.githubusercontent.com/username/php2shell-ioc/main/iocs/hashes.txt` | 64-char SHA-256 hashes of exploit payloads & webshells | Automated / Daily |
| **Canonical CSV** | `https://raw.githubusercontent.com/username/php2shell-ioc/main/iocs/php2shell_iocs.csv` | Full dataset with metadata, confidence, and timestamps | Automated / Daily |
| **Canonical JSON** | `https://raw.githubusercontent.com/username/php2shell-ioc/main/iocs/php2shell_iocs.json` | Complete machine-readable JSON dataset | Automated / Daily |

---

## 2. Firewall & Network Gateway Integrations

### Fortinet FortiGate (External Dynamic Connector)
1. In the FortiGate Web UI, navigate to **Security Fabric** -> **External Connectors**.
2. Click **Create New** -> **IP List**.
3. Configure:
   - **Name:** `PHP2Shell_Exploit_IPs`
   - **URL:** `https://raw.githubusercontent.com/username/php2shell-ioc/main/iocs/ips.txt`
   - **Refresh Rate:** 60 minutes
4. Click **OK**.
5. Create a Firewall Policy with source matching `PHP2Shell_Exploit_IPs` and action set to **DENY**.

### pfSense / OPNsense (pfBlockerNG)
1. In pfSense, navigate to **Firewall** -> **pfBlockerNG** -> **IPv4**.
2. Click **Add** to create an IPv4 feed.
3. Configure:
   - **List Name:** `PHP2Shell_Attackers`
   - **Source:** `https://raw.githubusercontent.com/username/php2shell-ioc/main/iocs/ips.txt`
   - **Format:** `Auto`
   - **State:** `On`
   - **Action:** `Deny Inbound` (or `Deny Both`)
   - **Update Frequency:** `Every 6 Hours`
4. Click **Save** and trigger an update via **pfBlockerNG** -> **Update** -> **Run**.

### Palo Alto Networks (PAN-OS External Dynamic List)
1. Go to **Objects** -> **External Dynamic Lists**.
2. Click **Add** and select Type **IP List**.
3. Set Source URL to: `https://raw.githubusercontent.com/username/php2shell-ioc/main/iocs/ips.txt`.
4. Apply the list as a Source address in your initial drop security policy.

---

## 3. DNS Sinkholes (Pi-hole / AdGuard Home)

Block command-and-control domains at the local resolver level:

1. Open the **Pi-hole Admin Console**.
2. Go to **Adlists**.
3. In the **Address** field, paste:
   ```text
   https://raw.githubusercontent.com/username/php2shell-ioc/main/iocs/domains.txt
   ```
4. Click **Add**, then run `pihole -g` or click **Update Gravity** under Tools.

---

## 4. Suricata / Snort Signatures

```suricata
# Detect inbound connections from confirmed PHP2Shell IP infrastructure
alert ip any any -> $HOME_NET any (msg:"ET DROP PHP2Shell Inbound Exploitation Attempt (CVE-2026-109618)"; reference:url,github.com/php2shell-ioc; classtype:trojan-activity; sid:2026101; rev:1;)

# Detect exploit tool multipart boundary string
alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:"ET EXPLOIT PHP2Shell Multipart Boundary Pattern"; flow:to_server,established; content:"----p2shell"; nocase; http_header; classtype:attempted-admin; sid:2026102; rev:1;)
```

---

## 5. SIEM Scheduled Ingestion

### Splunk CSV Lookup
Download and update the lookup file daily via cron:
```bash
curl -s -o /opt/splunk/etc/apps/search/lookups/php2shell_iocs.csv \
    https://raw.githubusercontent.com/username/php2shell-ioc/main/iocs/php2shell_iocs.csv
```

Correlate firewall access logs:
```spl
index=firewall 
| lookup php2shell_iocs.csv indicator as src_ip OUTPUT type, reported_by, confidence, context 
| where isnotnull(type)
```
