"""Generic Regex Parser for Unstructured Threat Advisories and Bulletins."""

from __future__ import annotations

import re
from typing import Any
from bs4 import BeautifulSoup

from scripts.normalizer import normalize_record
from scripts.parsers.base_parser import BaseParser

# Regex to capture potential indicator tokens (defanged or plain)
CANDIDATE_REGEX = re.compile(
    r"""
    (?P<url>(?:hxxps?|https?)://[^\s"'<>\)]+)
    |
    (?P<sha256>\b[a-fA-F0-9]{64}\b)
    |
    (?P<ip>\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\\?\[\\?\.\\?\]|\\?\(\\?\.\\?\)|\\.|\.)){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{1,5})?\b)
    |
    (?P<ipv6>\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b)
    |
    (?P<domain>\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\?\[\\?\.\\?\]|\\?\(\\?\.\\?\)|\\.|\.))+[a-zA-Z]{2,}\b)
    """,
    re.VERBOSE | re.IGNORECASE,
)


class GenericParser(BaseParser):
    """Extracts indicators from unstructured threat text using regex heuristics."""

    def parse(self, content: str, config: dict[str, Any]) -> list[dict[str, str]]:
        if not content:
            return []

        # Target dedicated IOC sections if present in HTML or Markdown
        is_html = any(tag in content.lower() for tag in ["<html", "<body", "<script", "<div", "<table"])
        if is_html:
            try:
                soup = BeautifulSoup(content, "html.parser")
                for tag in soup(["script", "style", "nav", "header", "footer", "svg"]):
                    tag.decompose()

                extracted_sections: list[str] = []

                # 1. Look for tables containing indicator data or headers
                for table in soup.find_all("table"):
                    table_text = table.get_text()
                    if re.search(r"ip|indicator|domain|hash|sha256|observed", table_text, re.I):
                        extracted_sections.append(table.get_text(separator="\n"))

                # 2. Look for dedicated IoC headings (h1-h6) in HTML and extract their sibling sections
                target_re = re.compile(
                    r"indicators?\s+of\s+compromise|\biocs?\b|top\s+attacking\s+ips", re.I
                )
                for heading in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
                    heading_text = heading.get_text(strip=True)
                    if target_re.search(heading_text):
                        h_level = int(heading.name[1]) if len(heading.name) == 2 and heading.name[1].isdigit() else 2
                        stop_levels = [f"h{i}" for i in range(1, h_level + 1)]

                        # Traverse upwards if heading is wrapped in a small heading container
                        start_elem = heading
                        while (
                            start_elem.parent
                            and start_elem.parent.name in ["div", "header", "section"]
                            and len(start_elem.parent.get_text(strip=True)) <= len(heading_text) + 20
                        ):
                            start_elem = start_elem.parent

                        for sibling in start_elem.find_next_siblings():
                            if sibling.name in stop_levels:
                                break
                            extracted_sections.append(sibling.get_text(separator="\n"))

                        parent_container = start_elem.parent
                        if parent_container and len(parent_container.get_text(strip=True)) > len(heading_text) + 20:
                            extracted_sections.append(parent_container.get_text(separator="\n"))

                if extracted_sections:
                    content = "\n\n".join(extracted_sections)
                else:
                    content = soup.get_text(separator="\n")
            except Exception:
                pass

        # Target dedicated IOC sections if present in threat reports
        ioc_sections: list[str] = []
        headers = list(
            re.finditer(
                r"(?im)^(?:#{2,3}|\*{0,2})\s*(?:indicators\s+of\s+compromise|ioc|top\s+attacking\s+ips).*",
                content,
            )
        )
        if headers:
            for h in headers:
                start = h.start()
                next_h = re.search(r"(?im)^#{2}\s+", content[h.end():])
                end = h.end() + next_h.start() if next_h else len(content)
                ioc_sections.append(content[start:end])
            search_text = "\n\n".join(ioc_sections)
        else:
            search_text = content

        seen_indicators: set[str] = set()
        records: list[dict[str, str]] = []

        for match in CANDIDATE_REGEX.finditer(search_text):
            token = match.group(0).strip().rstrip(".,;:)\"")
            if not token:
                continue

            # Skip software version numbers (e.g. Chrome/130.0.0.0) and CIDR subnets (e.g. /19, /24)
            leading_char = search_text[match.start() - 1] if match.start() > 0 else " "
            trailing_snippet = search_text[match.end():match.end() + 4]
            if leading_char in ["/", "\\", "@", "%"] or re.match(r"^/\d{1,2}", trailing_snippet):
                continue

            # Check surrounding context (e.g. adjacent table cells or lines) for research checker or scanner distinctions
            context_window = search_text[
                max(0, match.start() - 150) : min(len(search_text), match.end() + 150)
            ].lower()

            item_config = dict(config)
            if "research checker" in context_window or "research probe" in context_window:
                item_config["default_context"] = "Security research probe / checker"

            rec = normalize_record({"indicator": token}, item_config)
            if rec and rec["indicator"] not in seen_indicators:
                seen_indicators.add(rec["indicator"])
                records.append(rec)

        return records
