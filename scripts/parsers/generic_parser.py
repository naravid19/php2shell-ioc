"""Generic Regex Parser for Unstructured Threat Advisories and Bulletins."""

from __future__ import annotations

import re
from typing import Any

from scripts.normalizer import normalize_record
from scripts.parsers.base_parser import BaseParser

# Regex to capture potential indicator tokens (defanged or plain)
CANDIDATE_REGEX = re.compile(
    r"""
    (?P<url>(?:hxxps?|https?)://[^\s"'<>]+)
    |
    (?P<sha256>\b[a-fA-F0-9]{64}\b)
    |
    (?P<ip>\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\[\.\]|\(\.\)|\.)){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{1,5})?\b)
    |
    (?P<domain>\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\(\.\)|\.))+[a-zA-Z]{2,}\b)
    """,
    re.VERBOSE | re.IGNORECASE,
)


class GenericParser(BaseParser):
    """Extracts indicators from unstructured threat text using regex heuristics."""

    def parse(self, content: str, config: dict[str, Any]) -> list[dict[str, str]]:
        if not content:
            return []

        seen_indicators: set[str] = set()
        records: list[dict[str, str]] = []

        for match in CANDIDATE_REGEX.finditer(content):
            token = match.group(0).strip().rstrip(".,;:)")
            if not token:
                continue

            rec = normalize_record({"indicator": token}, config)
            if rec and rec["indicator"] not in seen_indicators:
                seen_indicators.add(rec["indicator"])
                records.append(rec)

        return records
