import json
from pathlib import Path
import pytest

from scripts.parsers.alienvault_otx_parser import AlienVaultOTXParser

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SAMPLE_OTX_PAYLOAD = {
    "source": "AlienVault OTX",
    "query": 'tag:"php2shell"',
    "search_indicators": [
        {
            "id": 1001,
            "indicator": "45.156.129.54",
            "type": "IPv4",
            "created": "2026-10-25T12:00:00",
            "description": "Exploit scanner observed on port 80",
        },
        {
            "id": 1002,
            "indicator": "php.net",
            "type": "domain",
            "created": "2026-10-21T00:00:00",
            "description": "Official PHP project website (benign)",
        },
        {
            "id": 1003,
            "indicator": "CVE-2026-109618",
            "type": "CVE",
            "created": "2026-10-21T00:00:00",
            "description": "PHP multipart OOM vulnerability",
        },
    ],
    "pulses": [
        {
            "id": "6adfbe6851cbd0e24cec7144",
            "name": "Hackers Weaponize Public PHP2Shell Exploit Code to Target Universities",
            "author_name": "CyberHunter_NL",
            "created": "2026-10-26T20:56:08",
            "description": "Threat report on weaponized exploitation.",
            "indicators": [
                {
                    "id": 2001,
                    "indicator": "206.188.197.105",
                    "type": "IPv4",
                    "created": "2026-10-26T20:56:09",
                    "description": "Scanning host",
                },
                {
                    "id": 2002,
                    "indicator": "40caf199ca1ebe056a74427f8e9db06c66899e33ae09c0ec2769ec70bf6dd8e7",
                    "type": "FileHash-SHA256",
                    "created": "2026-10-26T20:56:09",
                    "description": "Dropper payload",
                },
            ],
        }
    ],
}


class TestAlienVaultOTXParser:
    def test_parse_composite_payload(self):
        config = {
            "source": "https://otx.alienvault.com/browse/global/pulses?q=tag:%22php2shell%22",
            "reported_by": "AlienVault OTX",
            "default_first_seen": "2026-10-21",
            "default_confidence": "high",
            "default_context": "AlienVault OTX community & threat pulse telemetry",
        }
        parser = AlienVaultOTXParser()
        results = parser.parse(json.dumps(SAMPLE_OTX_PAYLOAD), config)

        # Expected:
        # - 45.156.129.54 (IP from search)
        # - 206.188.197.105 (IP from pulse)
        # - 40caf199ca1ebe056a74427f8e9db06c66899e33ae09c0ec2769ec70bf6dd8e7 (SHA256 from pulse)
        # Filtered out:
        # - php.net (Benign domain / False Positive)
        # - CVE-2026-109618 (Not an actionable IoC type)
        assert len(results) == 3

        indicators = {r["indicator"]: r for r in results}

        # Check search indicator
        assert "45.156.129.54" in indicators
        ind1 = indicators["45.156.129.54"]
        assert ind1["type"] == "ip"
        assert ind1["first_seen"] == "2026-10-25"
        assert ind1["reported_by"] == "AlienVault OTX"

        # Check pulse IP indicator
        assert "206.188.197.105" in indicators
        ind2 = indicators["206.188.197.105"]
        assert ind2["type"] == "ip"
        assert ind2["first_seen"] == "2026-10-26"
        assert ind2["source"] == "https://otx.alienvault.com/pulse/6adfbe6851cbd0e24cec7144"
        assert "CyberHunter_NL" in ind2["reported_by"]

        # Check pulse SHA256 indicator
        assert "40caf199ca1ebe056a74427f8e9db06c66899e33ae09c0ec2769ec70bf6dd8e7" in indicators
        ind3 = indicators["40caf199ca1ebe056a74427f8e9db06c66899e33ae09c0ec2769ec70bf6dd8e7"]
        assert ind3["type"] == "sha256"

    def test_parse_real_snapshot(self):
        snapshot_file = PROJECT_ROOT / "data" / "raw" / "alienvault_otx_snapshot.json"
        if not snapshot_file.is_file():
            pytest.skip("Snapshot file not found")

        content = snapshot_file.read_text(encoding="utf-8")
        config = {
            "source": "https://otx.alienvault.com/browse/global/pulses?q=tag:%22php2shell%22",
            "reported_by": "AlienVault OTX",
            "default_first_seen": "2026-10-21",
            "default_confidence": "high",
        }
        parser = AlienVaultOTXParser()
        results = parser.parse(content, config)

        assert len(results) > 50
        valid_types = {"ip", "domain", "sha256", "url"}
        for r in results:
            assert r["type"] in valid_types
            assert r["indicator"]
            assert r["first_seen"]
            assert r["source"]
