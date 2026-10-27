"""ThreatFox Parser for abuse.ch threat intelligence indicators."""

from __future__ import annotations

import json
from typing import Any

from scripts.normalizer import normalize_record
from scripts.parsers.base_parser import BaseParser


class ThreatFoxParser(BaseParser):
    """Parses ThreatFox IoCs from JSON feeds or API responses."""

    def parse(self, content: str, config: dict[str, Any]) -> list[dict[str, str]]:
        if not content or not content.strip():
            return []

        try:
            data = json.loads(content.strip())
        except Exception:
            return []

        raw_items: list[dict[str, Any]] = []

        if isinstance(data, dict):
            # Standard API response: {"query_status": "ok", "data": [...]}
            if "data" in data and isinstance(data["data"], list):
                raw_items = data["data"]
            # Alternate export response: {"<id>": [{...}]} or {"<id>": {...}}
            elif "query_status" not in data:
                for v in data.values():
                    if isinstance(v, list):
                        raw_items.extend([item for item in v if isinstance(item, dict)])
                    elif isinstance(v, dict):
                        raw_items.append(v)
            # Direct single item
            elif "ioc" in data or "indicator" in data:
                raw_items = [data]
        elif isinstance(data, list):
            raw_items = [item for item in data if isinstance(item, dict)]

        records: list[dict[str, str]] = []
        for item in raw_items:
            rec = self._parse_single_indicator(item, config)
            if rec:
                records.append(rec)

        return records

    def _parse_single_indicator(
        self,
        item: dict[str, Any],
        config: dict[str, Any],
    ) -> dict[str, str] | None:
        indicator_val = item.get("ioc") or item.get("indicator") or ""
        if not indicator_val:
            return None

        # Ignore non-actionable indicator types like cve, cwe, yara, yara_rule
        ioc_type = str(item.get("ioc_type", "")).lower()
        if ioc_type in ("cve", "cwe") or ioc_type.startswith("yara"):
            return None

        # Extract date from first_seen / created
        first_seen = None
        for key in ("first_seen", "created", "last_seen"):
            ts = item.get(key)
            if ts and isinstance(ts, str):
                first_seen = ts.split(" ")[0].split("T")[0].strip()
                break

        # Map confidence level
        confidence = config.get("default_confidence", "high")
        conf_level = item.get("confidence_level")
        if conf_level is not None:
            try:
                c_val = int(conf_level)
                if c_val >= 75:
                    confidence = "high"
                elif c_val >= 50:
                    confidence = "medium"
                else:
                    confidence = "low"
            except (ValueError, TypeError):
                pass
        elif item.get("confidence"):
            confidence = str(item["confidence"]).lower()

        # Reporter
        raw_reporter = item.get("reporter")
        default_reporter = config.get("reported_by", "abuse.ch ThreatFox")
        if raw_reporter:
            if "threatfox" in raw_reporter.lower() or "abuse.ch" in raw_reporter.lower():
                reporter = f"abuse.ch ThreatFox ({raw_reporter})"
            else:
                reporter = f"abuse.ch ThreatFox / {raw_reporter}"
        else:
            reporter = default_reporter

        # Context construction
        malware = item.get("malware_printable") or item.get("malware") or ""
        threat_type = item.get("threat_type_desc") or item.get("threat_type") or ""
        tags = item.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        context_parts: list[str] = []
        if malware:
            context_parts.append(f"Malware: {malware}")
        if threat_type:
            context_parts.append(f"Threat: {threat_type}")
        if tags:
            tag_str = ", ".join(tags[:5])
            context_parts.append(f"Tags: [{tag_str}]")

        context = " | ".join(context_parts) if context_parts else config.get("default_context", "ThreatFox PHP2Shell indicator")

        # Source URL
        ioc_id = item.get("id")
        source_url = item.get("reference")
        if not source_url and ioc_id:
            source_url = f"https://threatfox.abuse.ch/ioc/{ioc_id}/"
        if not source_url:
            source_url = config.get("source", "https://threatfox.abuse.ch/browse.php?search=tag%3APHP2Shell")

        raw_rec = {
            "indicator": indicator_val,
            "first_seen": first_seen,
            "source": source_url,
            "reported_by": reporter,
            "confidence": confidence,
            "context": context,
        }

        return normalize_record(raw_rec, defaults=config)
