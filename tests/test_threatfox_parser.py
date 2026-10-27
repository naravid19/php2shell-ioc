"""Tests for ThreatFox IoC Feed Parser."""

import json
from pathlib import Path
import pytest

from scripts.parsers.threatfox_parser import ThreatFoxParser

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SAMPLE_THREATFOX_PAYLOAD = {
    "query_status": "ok",
    "data": [
        {
            "id": "142857",
            "ioc": "185.196.8.99:38124",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Indicator that identifies a botnet C&C server",
            "ioc_type": "ip:port",
            "ioc_type_desc": "ip:port",
            "malware": "elf.mirai",
            "malware_printable": "Mirai",
            "malware_alias": None,
            "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai",
            "confidence_level": 100,
            "first_seen": "2026-10-23 08:14:00 UTC",
            "last_seen": None,
            "reporter": "threatfox_abusech",
            "reference": "https://threatfox.abuse.ch/ioc/142857/",
            "tags": ["Mirai", "PHP2Shell", "CVE-2026-109618"],
        },
        {
            "id": "142858",
            "ioc": "194.38.20.10:80",
            "threat_type": "payload_delivery",
            "threat_type_desc": "Indicator that identifies payload delivery infrastructure",
            "ioc_type": "ip:port",
            "ioc_type_desc": "ip:port",
            "malware": "elf.xmrig",
            "malware_printable": "XMRig",
            "malware_alias": None,
            "confidence_level": 60,
            "first_seen": "2026-10-24 10:00:00 UTC",
            "reporter": "abuse_ch",
            "reference": None,
            "tags": ["XMRig", "PHP2Shell"],
        },
        {
            "id": "142859",
            "ioc": "9f833318d77051830252b4f3838e5b4bd81e13b6d7ec738f636198cc8ad73804",
            "threat_type": "payload",
            "threat_type_desc": "Malware payload sample hash",
            "ioc_type": "sha256_hash",
            "malware": "elf.mirai",
            "malware_printable": "Mirai",
            "confidence_level": 100,
            "first_seen": "2026-10-24 12:00:00 UTC",
            "reporter": "cert_bund",
            "reference": "https://threatfox.abuse.ch/ioc/142859/",
            "tags": ["Mirai", "Potassium"],
        },
        {
            "id": "142860",
            "ioc": "threatfox.abuse.ch",
            "threat_type": "reference",
            "ioc_type": "domain",
            "confidence_level": 100,
            "first_seen": "2026-10-21 00:00:00 UTC",
            "reporter": "researcher",
            "tags": ["benign"],
        },
        {
            "id": "142861",
            "ioc": "CVE-2026-109618",
            "threat_type": "vulnerability",
            "ioc_type": "cve",
            "confidence_level": 100,
            "first_seen": "2026-10-21 00:00:00 UTC",
            "tags": ["PHP2Shell"],
        },
        {
            "id": "142862",
            "ioc": "rule php2shell_oom { condition: true }",
            "threat_type": "detection",
            "ioc_type": "yara_rule",
            "confidence_level": 100,
            "first_seen": "2026-10-21 00:00:00 UTC",
            "tags": ["Yara"],
        },
    ],
}


class TestThreatFoxParser:
    def test_parse_standard_api_payload(self):
        config = {
            "source": "https://threatfox.abuse.ch/browse.php?search=tag%3APHP2Shell",
            "reported_by": "abuse.ch ThreatFox",
            "default_first_seen": "2026-10-21",
            "default_confidence": "high",
            "default_context": "ThreatFox PHP2Shell indicator",
        }
        parser = ThreatFoxParser()
        results = parser.parse(json.dumps(SAMPLE_THREATFOX_PAYLOAD), config)

        # Expected:
        # - 185.196.8.99 (IP extracted from 185.196.8.99:38124)
        # - 194.38.20.10 (IP extracted from 194.38.20.10:80)
        # - 9f833318d77051830252b4f3838e5b4bd81e13b6d7ec738f636198cc8ad73804 (SHA256)
        # Filtered out:
        # - threatfox.abuse.ch (Benign domain / False positive)
        # - CVE-2026-109618 (Non-actionable CVE type)
        assert len(results) == 3

        indicators = {r["indicator"]: r for r in results}

        # Check IP 1 (Mirai C2)
        assert "185.196.8.99" in indicators
        ind1 = indicators["185.196.8.99"]
        assert ind1["type"] == "ip"
        assert ind1["first_seen"] == "2026-10-23"
        assert ind1["confidence"] == "high"
        assert ind1["source"] == "https://threatfox.abuse.ch/ioc/142857/"
        assert "Mirai" in ind1["context"]
        assert "abuse.ch ThreatFox" in ind1["reported_by"]

        # Check IP 2 (XMRig delivery, 60% confidence -> medium)
        assert "194.38.20.10" in indicators
        ind2 = indicators["194.38.20.10"]
        assert ind2["type"] == "ip"
        assert ind2["first_seen"] == "2026-10-24"
        assert ind2["confidence"] == "medium"
        assert "XMRig" in ind2["context"]

        # Check SHA256
        h = "9f833318d77051830252b4f3838e5b4bd81e13b6d7ec738f636198cc8ad73804"
        assert h in indicators
        ind3 = indicators[h]
        assert ind3["type"] == "sha256"
        assert ind3["first_seen"] == "2026-10-24"
        assert ind3["confidence"] == "high"
        assert "cert_bund" in ind3["reported_by"]

    def test_parse_empty_and_invalid(self):
        parser = ThreatFoxParser()
        assert parser.parse("", {}) == []
        assert parser.parse("   ", {}) == []
        assert parser.parse("not json", {}) == []
        assert parser.parse("{}", {}) == []
        assert parser.parse('{"query_status": "no_result"}', {}) == []

    def test_parse_real_snapshot(self):
        snapshot_file = PROJECT_ROOT / "data" / "raw" / "threatfox_snapshot.json"
        assert snapshot_file.is_file()
        content = snapshot_file.read_text(encoding="utf-8")

        config = {
            "source": "https://threatfox.abuse.ch/browse.php?search=tag%3APHP2Shell",
            "reported_by": "abuse.ch ThreatFox",
            "default_first_seen": "2026-10-21",
            "default_confidence": "high",
            "default_context": "ThreatFox abuse.ch intelligence tracking",
        }
        parser = ThreatFoxParser()
        results = parser.parse(content, config)
        assert len(results) == 11

        types = {r["type"] for r in results}
        assert "ip" in types
        assert "sha256" in types
        assert "domain" in types

