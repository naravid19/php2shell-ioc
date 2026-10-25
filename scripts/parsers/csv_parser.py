"""CSV Feed Parser for Structured Telemetry (MadPot, OffSeq, etc.)."""

from __future__ import annotations

import csv
import io
from typing import Any

from scripts.normalizer import normalize_record
from scripts.parsers.base_parser import BaseParser


class CsvParser(BaseParser):
    """Parses structured CSV indicator feeds."""

    def parse(self, content: str, config: dict[str, Any]) -> list[dict[str, str]]:
        if not content:
            return []

        records: list[dict[str, str]] = []
        reader = csv.DictReader(io.StringIO(content.strip()))

        for row in reader:
            indicator_val = (
                row.get("indicator")
                or row.get("ip")
                or row.get("domain")
                or row.get("hash")
                or row.get("sha256")
                or ""
            ).strip()

            if not indicator_val:
                continue

            row_data: dict[str, Any] = {
                "indicator": indicator_val,
                "first_seen": (row.get("first_seen") or "").strip(),
                "reported_by": (row.get("reported_by") or "").strip(),
                "confidence": (row.get("confidence") or "").strip(),
            }

            contexts: list[str] = []
            if row.get("network"):
                contexts.append(str(row["network"]).strip())
            if row.get("context"):
                contexts.append(str(row["context"]).strip())

            if contexts:
                row_data["context"] = "; ".join(contexts)

            rec = normalize_record(row_data, config)
            if rec:
                records.append(rec)

        return records
