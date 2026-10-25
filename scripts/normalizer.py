"""Indicator Normalization, Validation, and Deduplication Engine.

Provides core sanitization (defanging), indicator classification (IP, Domain, SHA256, URL),
false positive filtering for benign domains, and deterministic deduplication merging.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

BENIGN_DOMAINS: set[str] = {
    "php.net",
    "github.com",
    "apache.org",
    "wpackagist.org",
    "packagist.org",
    "debian.org",
    "ubuntu.com",
    "redhat.com",
    "cve.org",
    "nist.gov",
    "microsoft.com",
    "google.com",
    "cloudflare.com",
    "oracle.com",
    "fortinet.com",
    "wordfence.com",
    "huntress.com",
    "socradar.io",
    "threatbeaconx.com",
    "arcticwolf.com",
    "socnova.com",
    "calif.io",
    "wiz.io",
    "youtube.com",
    "amazon.com",
    "aws.amazon.com",
    "europa.eu",
    "cert.europa.eu",
    "remirepo.net",
    "openai.com",
    "wordpress.org",
    "drupal.org",
    "joomla.org",
    "laravel.com",
    "symfony.com",
}

NON_DOMAIN_EXTENSIONS: set[str] = {
    "php",
    "py",
    "sh",
    "exe",
    "bin",
    "elf",
    "txt",
    "csv",
    "json",
    "xml",
    "html",
    "htm",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "zip",
    "tar",
    "gz",
    "bak",
    "swp",
    "ini",
    "log",
    "conf",
    "cfg",
    "yml",
    "yaml",
    "service",
    "sock",
    "initial",
    "persistence",
    "execution",
}

VALID_TLDS: set[str] = {
    # Common generic & modern TLDs
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz",
    "st", "online", "pro", "xyz", "tech", "support", "fun", "io", "top",
    "cc", "site", "store", "vip", "live", "club", "shop", "click", "link",
    "space", "app", "dev", "ai", "cloud", "security", "stream", "download",
    "me", "co", "su", "pw", "ws", "tk", "ml", "ga", "cf", "gq",
    # Common ccTLDs
    "ru", "cn", "de", "nl", "fr", "uk", "us", "eu", "ch", "ca", "jp", "kr",
    "in", "br", "za", "au", "pl", "es", "it", "se", "no", "fi", "ro", "bg",
    "ir", "by", "kz", "ua", "vn", "th", "sg", "my", "id", "hk", "tw"
}

IPV4_PATTERN = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)
IPV4_WITH_PORT_PATTERN = re.compile(
    r"^((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}):(\d{1,5})$"
)
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

CONFIDENCE_RANK = {
    "high": 3,
    "medium": 2,
    "low": 1,
}


def defang(val: str) -> str:
    """Neutralize defanged indicators (e.g. hxxp://, [.])."""
    if not val:
        return ""
    cleaned = str(val).strip().strip("'\"`")
    # Defang scheme
    cleaned = re.sub(
        r"^hxxps?://",
        lambda m: "https://" if "hxxps" in m.group(0).lower() else "http://",
        cleaned,
        flags=re.IGNORECASE,
    )
    # Defang dots and colons (handling possible escaped markdown slashes like \[.\])
    cleaned = re.sub(r"\\?\[\\?\.\\?\]|\\?\(\\?\.\\?\)", ".", cleaned)
    cleaned = re.sub(r"\\?\[\\?:\\?\]|\\?\(\\?:\\?\)", ":", cleaned)
    cleaned = re.sub(r"\\[\[\]\\]", "", cleaned)
    return cleaned.strip()


def classify_indicator(val: str) -> tuple[str, str, dict[str, Any]]:
    """Classify an indicator into (cleaned_indicator, type, metadata_extra).

    Returns ("", "", {}) if invalid or classified as a benign false positive.
    """
    cleaned = defang(val)
    if not cleaned:
        return ("", "", {})

    # Check URL
    if cleaned.lower().startswith(("http://", "https://")):
        try:
            parsed = urlparse(cleaned)
            hostname = (parsed.hostname or "").lower()
            if not hostname or hostname in BENIGN_DOMAINS or any(hostname.endswith("." + b) for b in BENIGN_DOMAINS):
                return ("", "", {})
            return (cleaned, "url", {})
        except Exception:
            return ("", "", {})

    # Check IPv4 with port
    m_port = IPV4_WITH_PORT_PATTERN.match(cleaned)
    if m_port:
        ip = m_port.group(1)
        port = m_port.group(2)
        return (ip, "ip", {"port": port})

    # Check pure IPv4
    if IPV4_PATTERN.match(cleaned):
        return (cleaned, "ip", {})

    # Check IPv6
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        if ip_obj.version == 6:
            return (str(ip_obj).lower(), "ip", {})
    except ValueError:
        pass

    # Check SHA256
    if SHA256_PATTERN.match(cleaned):
        return (cleaned.lower(), "sha256", {})

    # Check Domain
    domain_cand = cleaned.lower()
    if DOMAIN_PATTERN.match(domain_cand):
        tld = domain_cand.split(".")[-1]
        if tld in NON_DOMAIN_EXTENSIONS or tld not in VALID_TLDS:
            return ("", "", {})
        # Reject benign domains
        for benign in BENIGN_DOMAINS:
            if domain_cand == benign or domain_cand.endswith("." + benign):
                return ("", "", {})
        return (domain_cand, "domain", {})

    return ("", "", {})


def normalize_record(raw: dict[str, Any], defaults: dict[str, Any] | None = None) -> dict[str, str] | None:
    """Normalize raw indicator dictionary against defaults and schema."""
    if defaults is None:
        defaults = {}

    ind_raw = raw.get("indicator") or ""
    ind, itype, meta = classify_indicator(str(ind_raw))
    if not ind or not itype:
        return None

    first_seen = (
        raw.get("first_seen")
        or defaults.get("first_seen")
        or defaults.get("default_first_seen")
        or ""
    )
    source = (
        raw.get("source")
        or defaults.get("source")
        or defaults.get("url")
        or ""
    )
    reported_by = (
        raw.get("reported_by")
        or defaults.get("reported_by")
        or ""
    )
    confidence = (
        raw.get("confidence")
        or defaults.get("confidence")
        or defaults.get("default_confidence")
        or "medium"
    )

    context_parts: list[str] = []
    if raw.get("context"):
        context_parts.append(str(raw["context"]).strip())
    elif defaults.get("context"):
        context_parts.append(str(defaults["context"]).strip())
    elif defaults.get("default_context"):
        context_parts.append(str(defaults["default_context"]).strip())

    if meta.get("port"):
        port_note = f"port: {meta['port']}"
        if not any(port_note in part for part in context_parts):
            context_parts.append(port_note)

    context = "; ".join(p for p in context_parts if p)

    return {
        "indicator": ind,
        "type": itype,
        "first_seen": str(first_seen).strip(),
        "source": str(source).strip(),
        "reported_by": str(reported_by).strip(),
        "confidence": str(confidence).strip().lower(),
        "context": context,
    }


def _combine_delimited(val1: str, val2: str, delimiter: str = "; ") -> str:
    parts: list[str] = []
    for item in [val1, val2]:
        if not item:
            continue
        for token in re.split(r"\s*;\s*", str(item).strip()):
            cleaned = token.strip()
            if cleaned and cleaned not in parts:
                parts.append(cleaned)
    return delimiter.join(parts)


def merge_indicators(
    existing: list[dict[str, Any]], incoming: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """Deduplicate and merge existing and incoming indicator records."""
    merged_map: dict[str, dict[str, str]] = {}

    for record in existing + incoming:
        ind = str(record.get("indicator", "")).strip().lower()
        if not ind:
            continue

        if ind not in merged_map:
            merged_map[ind] = {
                "indicator": str(record.get("indicator", "")).strip(),
                "type": str(record.get("type", "")).strip().lower(),
                "first_seen": str(record.get("first_seen", "")).strip(),
                "source": str(record.get("source", "")).strip(),
                "reported_by": str(record.get("reported_by", "")).strip(),
                "confidence": str(record.get("confidence", "medium")).strip().lower(),
                "context": str(record.get("context", "")).strip(),
            }
        else:
            curr = merged_map[ind]
            # Preserve earliest first_seen
            curr_date = curr["first_seen"]
            new_date = str(record.get("first_seen", "")).strip()
            if new_date:
                if not curr_date or new_date < curr_date:
                    curr["first_seen"] = new_date

            # Retain higher confidence
            curr_conf = curr["confidence"].lower()
            new_conf = str(record.get("confidence", "medium")).strip().lower()
            if CONFIDENCE_RANK.get(new_conf, 1) > CONFIDENCE_RANK.get(curr_conf, 1):
                curr["confidence"] = new_conf

            # Combine source, reported_by, context
            new_source = str(record.get("source", "")).strip()
            if new_source:
                curr["source"] = _combine_delimited(curr["source"], new_source)

            new_rep = str(record.get("reported_by", "")).strip()
            if new_rep:
                curr["reported_by"] = _combine_delimited(curr["reported_by"], new_rep)

            new_ctx = str(record.get("context", "")).strip()
            if new_ctx:
                curr["context"] = _combine_delimited(curr["context"], new_ctx)

    return sorted(list(merged_map.values()), key=lambda x: (x["type"], x["indicator"]))
