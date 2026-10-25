"""FortiGuard Outbreak Alert Parser (supports both direct API JSON and HTML table snapshots)."""

from __future__ import annotations

import json
import urllib.parse
from typing import Any
from bs4 import BeautifulSoup

from scripts.normalizer import normalize_record
from scripts.parsers.base_parser import BaseParser


class FortiGuardParser(BaseParser):
    """Parses FortiGuard live API JSON or HTML outbreak alert tables."""

    def parse(self, content: str, config: dict[str, Any]) -> list[dict[str, str]]:
        if not content:
            return []

        content_stripped = content.strip()

        # Handle direct JSON API response
        if content_stripped.startswith("{") and "indicators" in content_stripped:
            try:
                data = json.loads(content_stripped)
                raw_items = data.get("indicators", [])
                records: list[dict[str, str]] = []
                for item in raw_items:
                    ioc_val = item.get("ioc") or item.get("indicator") or ""
                    if not ioc_val:
                        continue
                    active_val = item.get("active")
                    row_data: dict[str, Any] = {"indicator": str(ioc_val).strip()}
                    if active_val is False:
                        row_data["context"] = "Status: Inactive"
                    rec = normalize_record(row_data, config)
                    if rec:
                        records.append(rec)
                return records
            except Exception:
                pass

        soup = BeautifulSoup(content, "html.parser")
        records: list[dict[str, str]] = []

        # Find all rows in all table bodies
        for row in soup.find_all("tr"):
            cells = row.find_all("td")
            if not cells:
                continue

            indicator_val = ""
            status_val = ""

            # Check for data-label attribute or column index
            for td in cells:
                label = (td.get("data-label") or "").strip().lower()
                if label == "indicator" or not indicator_val:
                    a_tag = td.find("a")
                    if a_tag and a_tag.get("href"):
                        parsed_url = urllib.parse.urlparse(a_tag["href"])
                        query_params = urllib.parse.parse_qs(parsed_url.query)
                        if "q" in query_params and query_params["q"]:
                            indicator_val = query_params["q"][0].strip()
                    if not indicator_val:
                        indicator_val = td.get_text(strip=True)
                elif label == "status":
                    status_val = td.get_text(strip=True)

            if not indicator_val:
                continue

            row_data: dict[str, Any] = {
                "indicator": indicator_val,
            }
            if status_val and status_val.lower() != "active":
                row_data["context"] = f"Status: {status_val}"

            rec = normalize_record(row_data, config)
            if rec:
                records.append(rec)

        return records
