"""AlienVault OTX Parser for Pulse indicators and Global Indicator Search."""

from __future__ import annotations

import json
from typing import Any

from scripts.normalizer import normalize_record
from scripts.parsers.base_parser import BaseParser


class AlienVaultOTXParser(BaseParser):
    """Parses AlienVault OTX pulses and search indicators from JSON feeds."""

    def parse(self, content: str, config: dict[str, Any]) -> list[dict[str, str]]:
        if not content or not content.strip():
            return []

        try:
            data = json.loads(content.strip())
        except Exception:
            return []

        records: list[dict[str, str]] = []

        # 1. Handle composite payload (containing search_indicators and/or pulses)
        if isinstance(data, dict):
            # Parse search_indicators if present
            if "search_indicators" in data and isinstance(data["search_indicators"], list):
                for item in data["search_indicators"]:
                    rec = self._parse_single_indicator(item, config)
                    if rec:
                        records.append(rec)

            # Parse pulses if present
            if "pulses" in data and isinstance(data["pulses"], list):
                for pulse in data["pulses"]:
                    pulse_id = pulse.get("id", "")
                    meta = {
                        "source_url": f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id else "",
                        "author": pulse.get("author_name") or (pulse.get("author") or {}).get("username") or "",
                        "context": pulse.get("name", ""),
                    }
                    for item in pulse.get("indicators", []):
                        rec = self._parse_single_indicator(item, config, pulse_meta=meta)
                        if rec:
                            records.append(rec)

            # If neither search_indicators nor pulses, check if it is a direct results list
            if not records:
                raw_results = data.get("results") or data.get("indicators")
                if isinstance(raw_results, list):
                    for item in raw_results:
                        rec = self._parse_single_indicator(item, config)
                        if rec:
                            records.append(rec)
                elif "indicator" in data:
                    rec = self._parse_single_indicator(data, config)
                    if rec:
                        records.append(rec)

        elif isinstance(data, list):
            for item in data:
                rec = self._parse_single_indicator(item, config)
                if rec:
                    records.append(rec)

        return records

    def _parse_single_indicator(
        self,
        item: dict[str, Any],
        config: dict[str, Any],
        pulse_meta: dict[str, str] | None = None,
    ) -> dict[str, str] | None:
        indicator_val = item.get("indicator") or item.get("ioc") or ""
        if not indicator_val:
            return None

        # Ignore non-actionable indicator types like CVE, CWE, YARA
        indicator_type = str(item.get("type", "")).lower()
        if indicator_type in ("cve", "cwe", "yara"):
            return None

        # Extract date from 'created' or 'modified' timestamp
        first_seen = None
        for key in ("created", "first_seen", "modified"):
            ts = item.get(key)
            if ts and isinstance(ts, str):
                first_seen = ts.split("T")[0].strip()
                break

        # Context construction
        context_parts: list[str] = []
        source_url = None
        pulse_author = None
        if pulse_meta:
            source_url = pulse_meta.get("source_url")
            pulse_author = pulse_meta.get("author")
            pulse_ctx = pulse_meta.get("context")
            if pulse_ctx:
                context_parts.append(pulse_ctx.strip())

        desc = item.get("description") or item.get("title")
        if desc and str(desc).strip() and str(desc).strip() not in context_parts:
            context_parts.append(str(desc).strip())

        row_data: dict[str, Any] = {
            "indicator": str(indicator_val).strip(),
        }
        if first_seen:
            row_data["first_seen"] = first_seen
        if source_url:
            row_data["source"] = source_url
        if pulse_author:
            row_data["reported_by"] = f"AlienVault OTX ({pulse_author})"
        if context_parts:
            row_data["context"] = " - ".join(context_parts)

        return normalize_record(row_data, config)
