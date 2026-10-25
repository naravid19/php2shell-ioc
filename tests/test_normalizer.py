import pytest
from scripts.normalizer import (
    defang,
    classify_indicator,
    normalize_record,
    merge_indicators,
    BENIGN_DOMAINS,
)


class TestDefang:
    def test_defang_url(self):
        assert defang("hxxp://example[.]com/path") == "http://example.com/path"
        assert defang("hxxps://test(.)org[:]8080") == "https://test.org:8080"

    def test_defang_ip(self):
        assert defang("103[.]216[.]220[.]92") == "103.216.220.92"
        assert defang("192(.)168(.)1(.)1") == "192.168.1.1"

    def test_whitespace_and_quotes(self):
        assert defang('  "103.216.220.92" \n') == "103.216.220.92"


class TestClassifyIndicator:
    def test_classify_clean_ipv4(self):
        ind, itype, meta = classify_indicator("103.216.220.92")
        assert ind == "103.216.220.92"
        assert itype == "ip"
        assert meta == {}

    def test_classify_ipv4_with_port(self):
        ind, itype, meta = classify_indicator("206.188.197.105:8888")
        assert ind == "206.188.197.105"
        assert itype == "ip"
        assert meta.get("port") == "8888"

    def test_classify_sha256(self):
        sha = "40caf199a099a4c84eb63df858ffbaef3ff72661730419e487fb0fc7efbd7472"
        ind, itype, meta = classify_indicator(sha.upper())
        assert ind == sha.lower()
        assert itype == "sha256"

    def test_classify_domain(self):
        ind, itype, meta = classify_indicator("THUNDER.GODOFTHUNDER.ST")
        assert ind == "thunder.godofthunder.st"
        assert itype == "domain"

    def test_reject_benign_domain_false_positives(self):
        for benign in ["php.net", "github.com", "apache.org", "wpackagist.org"]:
            ind, itype, meta = classify_indicator(benign)
            assert ind == ""
            assert itype == ""

    def test_classify_url(self):
        url = "http://attacker.com/exploit.php"
        ind, itype, meta = classify_indicator(url)
        assert ind == url
        assert itype == "url"


class TestNormalizeRecord:
    def test_normalize_valid_record_with_defaults(self):
        raw = {"indicator": "103[.]216[.]220[.]92"}
        defaults = {
            "first_seen": "2026-10-21",
            "source": "https://example.com/advisory",
            "reported_by": "TestSec",
            "confidence": "high",
            "context": "Scanning node",
        }
        res = normalize_record(raw, defaults)
        assert res is not None
        assert res["indicator"] == "103.216.220.92"
        assert res["type"] == "ip"
        assert res["first_seen"] == "2026-10-21"
        assert res["source"] == "https://example.com/advisory"
        assert res["reported_by"] == "TestSec"
        assert res["confidence"] == "high"
        assert res["context"] == "Scanning node"

    def test_normalize_ip_with_port_records_context(self):
        raw = {"indicator": "206.188.197.105:8888", "context": "OOM sweep"}
        res = normalize_record(raw, {})
        assert res is not None
        assert res["indicator"] == "206.188.197.105"
        assert "port: 8888" in res["context"]
        assert "OOM sweep" in res["context"]

    def test_normalize_rejects_benign_domains(self):
        raw = {"indicator": "php.net"}
        res = normalize_record(raw, {})
        assert res is None

    def test_normalize_without_date_defaults_to_execution_date(self):
        from datetime import datetime, timezone
        raw = {"indicator": "103.216.220.92"}
        res = normalize_record(raw, {})
        assert res is not None
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert res["first_seen"] == today


class TestMergeIndicators:
    def test_deduplicate_and_preserve_earliest_first_seen(self):
        existing = [
            {
                "indicator": "103.216.220.92",
                "type": "ip",
                "first_seen": "2026-10-21",
                "source": "https://source1.com",
                "reported_by": "ResearcherA",
                "confidence": "medium",
                "context": "Honeypot hit",
            }
        ]
        incoming = [
            {
                "indicator": "103.216.220.92",
                "type": "ip",
                "first_seen": "2026-10-17",  # earlier date
                "source": "https://source2.com",
                "reported_by": "Amazon MadPot",
                "confidence": "high",
                "context": "Exploit probe",
            }
        ]
        merged = merge_indicators(existing, incoming)
        assert len(merged) == 1
        record = merged[0]
        assert record["indicator"] == "103.216.220.92"
        assert record["first_seen"] == "2026-10-17"
        assert "source1.com" in record["source"]
        assert "source2.com" in record["source"]
        assert "ResearcherA" in record["reported_by"]
        assert "Amazon MadPot" in record["reported_by"]
        assert record["confidence"] == "high"
        assert "Honeypot hit" in record["context"]
        assert "Exploit probe" in record["context"]

    def test_merge_case_insensitive_domain(self):
        existing = [
            {
                "indicator": "thunder.godofthunder.st",
                "type": "domain",
                "first_seen": "2026-10-20",
                "source": "Feed A",
                "reported_by": "Unit A",
                "confidence": "high",
                "context": "C2 node",
            }
        ]
        incoming = [
            {
                "indicator": "THUNDER.GODOFTHUNDER.ST",
                "type": "domain",
                "first_seen": "2026-10-22",
                "source": "Feed B",
                "reported_by": "Unit B",
                "confidence": "high",
                "context": "C2 host",
            }
        ]
        merged = merge_indicators(existing, incoming)
        assert len(merged) == 1
        assert merged[0]["indicator"] == "thunder.godofthunder.st"
