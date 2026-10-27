"""Main IoC Collection CLI and Pipeline Runner.

Reads source feeds from config/sources.json, fetches remote advisories or reads
local audit snapshots, normalizes indicators, merges them into the canonical
dataset, and generates flat blocklists for firewalls and EDRs.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

# Ensure parent directory is in path when running standalone
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import requests
except ImportError:
    requests = None  # Fallback to urllib if requests is missing

import urllib.request
import urllib.error

from scripts.normalizer import merge_indicators, BENIGN_RESEARCH_IPS
from scripts.parsers import get_parser

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)
logger = logging.getLogger("collector")

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

SCHEMA_COLUMNS = [
    "indicator",
    "type",
    "first_seen",
    "source",
    "reported_by",
    "confidence",
    "context",
]


def fetch_alienvault_live(source_cfg: dict[str, Any]) -> str | None:
    """Attempt live fetch from AlienVault OTX using Playwright browser session if available."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.info("Playwright not installed; falling back to local snapshot for AlienVault OTX.")
        return None

    try:
        logger.info("Using Playwright browser session to fetch live AlienVault OTX data...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto("https://otx.alienvault.com/browse/global/pulses?q=tag:%22php2shell%22", timeout=15000)
            page.wait_for_timeout(3000)

            # Global indicators
            ind_res = page.evaluate('''async () => {
                const r = await fetch('https://otx.alienvault.com/otxapi/indicators/?include_inactive=0&sort=-modified&q=%22php2shell%22&page=1&limit=100');
                return await r.json();
            }''')
            global_indicators = ind_res.get("results", [])

            # Pulses
            pulses_res = page.evaluate('''async () => {
                const r = await fetch('https://otx.alienvault.com/otxapi/pulses/?limit=50&page=1&sort=-modified&q=tag:%22php2shell%22');
                return await r.json();
            }''')
            pulses_raw = pulses_res.get("results", [])

            pulses = []
            for p_info in pulses_raw:
                pid = p_info.get("id")
                if not pid:
                    continue
                p_indicators_res = page.evaluate('''async (pulse_id) => {
                    try {
                        const r = await fetch('https://otx.alienvault.com/otxapi/pulses/' + pulse_id + '/indicators/?sort=-created&limit=500&page=1');
                        return await r.json();
                    } catch(e) {
                        return {results: []};
                    }
                }''', pid)
                p_indicators = p_indicators_res.get("results", [])
                pulses.append({
                    "id": pid,
                    "name": p_info.get("name"),
                    "author_name": (p_info.get("author") or {}).get("username") or p_info.get("author_name") or "AlienVault OTX",
                    "created": p_info.get("created"),
                    "modified": p_info.get("modified"),
                    "description": p_info.get("description"),
                    "tags": p_info.get("tags", []),
                    "indicators_count": len(p_indicators),
                    "indicators": p_indicators,
                })
            browser.close()
            payload = {
                "source": "AlienVault OTX",
                "query": 'tag:"php2shell"',
                "search_indicators": global_indicators,
                "pulses": pulses,
            }
            return json.dumps(payload)
    except Exception as e:
        logger.warning(f"Playwright live fetch for AlienVault OTX failed or unavailable: {e}")
        return None


def fetch_source_content(source_cfg: dict[str, Any], project_root: Path) -> str:
    """Fetch content from remote URL with fallback to local snapshot file."""
    if source_cfg.get("parser") == "alienvault_otx":
        live_content = fetch_alienvault_live(source_cfg)
        if live_content:
            return live_content

    url = source_cfg.get("url", "").strip()
    snapshot_path_str = source_cfg.get("local_snapshot", "").strip()
    snapshot_path = project_root / snapshot_path_str if snapshot_path_str else None

    # Try remote HTTP GET if URL is provided
    if url:
        logger.info(f"Fetching remote source: {url}")
        headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "application/json, text/html, application/xhtml+xml, */*",
        }
        if "fortinet.com" in url or "fortiguard" in source_cfg.get("name", "").lower():
            headers["Referer"] = "https://fortiguard.fortinet.com/outbreak-alert/php2shell"
        try:
            if requests:
                resp = requests.get(
                    url,
                    headers=headers,
                    timeout=10,
                )
                if resp.status_code == 200 and resp.text.strip():
                    return resp.text
                logger.warning(
                    f"Remote request returned status {resp.status_code} for {url}"
                )
            else:
                req = urllib.request.Request(
                    url, headers=headers
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        return response.read().decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Failed to fetch remote URL '{url}': {e}")

    # Fallback to local snapshot
    if snapshot_path and snapshot_path.is_file():
        logger.info(f"Reading local snapshot: {snapshot_path}")
        return snapshot_path.read_text(encoding="utf-8", errors="replace")

    logger.warning(f"No content available for source '{source_cfg.get('name')}'")
    return ""


def load_existing_dataset(csv_path: Path) -> list[dict[str, str]]:
    """Load existing indicators from canonical CSV if present."""
    if not csv_path.is_file():
        return []
    records: list[dict[str, str]] = []
    with open(csv_path, mode="r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append({col: row.get(col, "").strip() for col in SCHEMA_COLUMNS})
    return records


def is_blocklist_eligible(record: dict[str, Any]) -> bool:
    """Determine if an indicator is actionable threat infrastructure for automated blocklists.

    Excludes benign security research scanners and verification probes per Defenders First.
    """
    if record.get("indicator") in BENIGN_RESEARCH_IPS:
        return False
    context = str(record.get("context", "")).lower()
    if any(k in context for k in ["research probe", "research checker", "challenge"]):
        return False
    return True


def write_dataset_and_blocklists(
    records: list[dict[str, str]], output_dir: Path
) -> None:
    """Write canonical CSV, JSON, and flat blocklists."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Canonical CSV
    csv_path = output_dir / "php2shell_iocs.csv"
    with open(csv_path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA_COLUMNS)
        writer.writeheader()
        writer.writerows(records)

    # 2. Canonical JSON
    json_path = output_dir / "php2shell_iocs.json"
    json_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    # 3. Flat line-delimited blocklists (filtered for actionable threat infrastructure)
    ips = sorted(
        {
            r["indicator"]
            for r in records
            if r["type"] == "ip" and is_blocklist_eligible(r)
        }
    )
    domains = sorted(
        {
            r["indicator"]
            for r in records
            if r["type"] == "domain" and is_blocklist_eligible(r)
        }
    )
    hashes = sorted(
        {
            r["indicator"]
            for r in records
            if r["type"] == "sha256" and is_blocklist_eligible(r)
        }
    )

    (output_dir / "ips.txt").write_text("\n".join(ips) + "\n" if ips else "", encoding="utf-8")
    (output_dir / "domains.txt").write_text("\n".join(domains) + "\n" if domains else "", encoding="utf-8")
    (output_dir / "hashes.txt").write_text("\n".join(hashes) + "\n" if hashes else "", encoding="utf-8")

    logger.info(f"Wrote {len(records)} indicators to {output_dir}")
    logger.info(f"  - IPs: {len(ips)} -> {output_dir / 'ips.txt'}")
    logger.info(f"  - Domains: {len(domains)} -> {output_dir / 'domains.txt'}")
    logger.info(f"  - SHA256 Hashes: {len(hashes)} -> {output_dir / 'hashes.txt'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect, normalize, and export PHP2Shell Indicators of Compromise."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=PROJECT_ROOT / "config" / "sources.json",
        help="Path to source configuration JSON (default: config/sources.json)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "iocs",
        help="Directory to save canonical feeds and blocklists (default: iocs)",
    )
    parser.add_argument(
        "--source",
        type=str,
        default="",
        help="Filter by specific source name",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and merge without writing output files",
    )
    args = parser.parse_args()

    config_path: Path = args.config
    output_dir: Path = args.output_dir

    if not config_path.is_file():
        logger.error(f"Config file not found: {config_path}")
        return 1

    try:
        sources: list[dict[str, Any]] = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.error(f"Failed to parse config JSON: {e}")
        return 1

    existing_csv = output_dir / "php2shell_iocs.csv"
    existing_records = load_existing_dataset(existing_csv)
    initial_count = len(existing_records)
    logger.info(f"Loaded {initial_count} existing indicators from canonical dataset.")

    incoming_records: list[dict[str, str]] = []

    for src in sources:
        src_name = src.get("name", "unnamed")
        if args.source and args.source.lower() != src_name.lower():
            continue

        parser_name = src.get("parser", "generic")
        try:
            feed_parser = get_parser(parser_name)
        except ValueError as err:
            logger.error(f"Skipping source '{src_name}': {err}")
            continue

        content = fetch_source_content(src, PROJECT_ROOT)
        if not content:
            continue

        parsed = feed_parser.parse(content, src)
        if not parsed and src.get("local_snapshot"):
            snapshot_path = PROJECT_ROOT / src["local_snapshot"]
            if snapshot_path.is_file():
                logger.info(
                    f"Remote source produced 0 indicators; falling back to snapshot: {snapshot_path}"
                )
                fallback_content = snapshot_path.read_text(
                    encoding="utf-8", errors="replace"
                )
                parsed = feed_parser.parse(fallback_content, src)

        logger.info(f"Source '{src_name}' produced {len(parsed)} indicators.")
        incoming_records.extend(parsed)

    merged = merge_indicators(existing_records, incoming_records)
    total_count = len(merged)
    new_indicators = total_count - initial_count

    logger.info("=" * 50)
    logger.info(f"COLLECTION SUMMARY:")
    logger.info(f"  Existing indicators: {initial_count}")
    logger.info(f"  Incoming candidates: {len(incoming_records)}")
    logger.info(f"  Net new indicators:  {new_indicators}")
    logger.info(f"  Total unique IoCs:   {total_count}")
    logger.info("=" * 50)

    if args.dry_run:
        logger.info("[DRY RUN] Skipping file writes.")
        return 0

    write_dataset_and_blocklists(merged, output_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
