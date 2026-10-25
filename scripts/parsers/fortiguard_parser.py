"""FortiGuard Outbreak Alert HTML Table Parser."""

from __future__ import annotations

import urllib.parse
from typing import Any
from bs4 import BeautifulSoup

from scripts.normalizer import normalize_record
from scripts.parsers.base_parser import BaseParser


class FortiGuardParser(BaseParser):
    """Parses FortiGuard HTML outbreak alert tables."""

    def parse(self, content: str, config: dict[str, Any]) -> list[dict[str, str]]:
        if not content:
            return []

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
