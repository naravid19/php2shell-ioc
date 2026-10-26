import pytest
from scripts.parsers.fortiguard_parser import FortiGuardParser
from scripts.parsers.csv_parser import CsvParser
from scripts.parsers.generic_parser import GenericParser


FORTIGUARD_HTML_SNIPPET = """
<div class="app-data-table table-responsive">
  <table class="table">
    <thead>
      <tr><th>Indicator</th><th>Type</th><th>Status</th></tr>
    </thead>
    <tbody>
      <tr>
        <td data-label="Indicator"><a href="/search?q=thunder.godofthunder.st&amp;type=ioc">thunder.godofthunder.st</a></td>
        <td data-label="Type"><span class="badge">domain</span></td>
        <td data-label="Status"><span>Active</span></td>
      </tr>
      <tr>
        <td data-label="Indicator"><a href="/search?q=27d926a6708d6769d97d065e7a5a860ab496eab272c03d1cebc55ec71b954fa2&amp;type=ioc">27d926a6708d6769d97d065e7a5a860ab496eab272c03d1ceb</a></td>
        <td data-label="Type"><span class="badge">file</span></td>
        <td data-label="Status"><span>Active</span></td>
      </tr>
      <tr>
        <td data-label="Indicator"><a href="/search?q=206.188.197.105:8888&amp;type=ioc">206.188.197.105:8888</a></td>
        <td data-label="Type"><span class="badge">ip</span></td>
        <td data-label="Status"><span>Active</span></td>
      </tr>
    </tbody>
  </table>
</div>
"""

MADPOT_CSV_SNIPPET = """ip,first_seen,network,reported_by,context
"103.216.220.92","2026-10-17","Commercial anonymisation network","Amazon MadPot","Earliest known attempt"
"94.154.43.7","2026-10-21","AS219502 Storm Industries","OffSeq Mirage","Lead actor; OOM size sweep"
"""

UNSTRUCTURED_TEXT_SNIPPET = """
During threat analysis of PHP2Shell (CVE-2026-109618), telemetry observed active exploitation attempts from:
- 103[.]216[.]220[.]92 probing session upload endpoints.
- Malicious staging domain: hxxp://bad-php2shell[.]com/drop.php
- Attacker SHA256 payload: 40caf199ca1ebe056a74427f8e9db06c66899e33ae09c0ec2769ec70bf6dd8e7
Please note that legitimate patches are available at php.net and github.com.
"""


class TestFortiGuardParser:
    def test_parse_fortiguard_table(self):
        config = {
            "source": "https://fortiguard.fortinet.com/outbreak-alert/php2shell",
            "reported_by": "FortiGuard",
            "default_first_seen": "2026-10-21",
            "default_confidence": "high",
            "default_context": "Active PHP2Shell exploitation & scanning infrastructure",
        }
        parser = FortiGuardParser()
        results = parser.parse(FORTIGUARD_HTML_SNIPPET, config)

        assert len(results) == 3

        # Check domain
        domain_entry = next(r for r in results if r["type"] == "domain")
        assert domain_entry["indicator"] == "thunder.godofthunder.st"
        assert domain_entry["reported_by"] == "FortiGuard"
        assert domain_entry["first_seen"] == "2026-10-21"

        # Check SHA256 (extracted from href query parameter, not truncated inner text)
        hash_entry = next(r for r in results if r["type"] == "sha256")
        assert hash_entry["indicator"] == "27d926a6708d6769d97d065e7a5a860ab496eab272c03d1cebc55ec71b954fa2"
        assert len(hash_entry["indicator"]) == 64

        # Check IP with port
        ip_entry = next(r for r in results if r["type"] == "ip")
        assert ip_entry["indicator"] == "206.188.197.105"
        assert "port: 8888" in ip_entry["context"]


class TestCsvParser:
    def test_parse_madpot_csv(self):
        config = {
            "source": "data/raw/initial_madpot.csv",
            "default_confidence": "high",
        }
        parser = CsvParser()
        results = parser.parse(MADPOT_CSV_SNIPPET, config)

        assert len(results) == 2
        r1 = results[0]
        assert r1["indicator"] == "103.216.220.92"
        assert r1["type"] == "ip"
        assert r1["first_seen"] == "2026-10-17"
        assert r1["reported_by"] == "Amazon MadPot"
        assert "Commercial anonymisation network" in r1["context"]
        assert "Earliest known attempt" in r1["context"]


class TestGenericParser:
    def test_parse_unstructured_text(self):
        config = {
            "source": "https://threatintel.example.com/report",
            "reported_by": "ThreatIntel",
            "default_first_seen": "2026-10-22",
            "default_confidence": "medium",
        }
        parser = GenericParser()
        results = parser.parse(UNSTRUCTURED_TEXT_SNIPPET, config)

        indicators = {r["indicator"] for r in results}
        assert "103.216.220.92" in indicators
        assert "40caf199ca1ebe056a74427f8e9db06c66899e33ae09c0ec2769ec70bf6dd8e7" in indicators
        assert any("bad-php2shell.com" in ind for ind in indicators)

        # Benign domains must NOT be parsed as indicators
        assert "php.net" not in indicators
        assert "github.com" not in indicators

    def test_parse_html_ioc_section(self):
        html_content = """
        <html>
        <body>
            <div class="header">Visit example.org or check php.net for updates</div>
            <div class="card">
                <h2>Indicators of Compromise</h2>
                <p>The following attacking IP addresses were observed:</p>
                <ul>
                    <li>198.51.100.25</li>
                    <li>203.0.113.88</li>
                </ul>
            </div>
            <div class="footer">Contact us at support.com</div>
        </body>
        </html>
        """
        parser = GenericParser()
        results = parser.parse(html_content, {"reported_by": "Test"})
        inds = {r["indicator"] for r in results}
        assert "198.51.100.25" in inds
        assert "203.0.113.88" in inds
        assert "support.com" not in inds
        assert "example.org" not in inds

    def test_parse_html_ioc_table_and_lists(self):
        html_content = """
        <html>
        <body>
            <div class="heading-wrapper"><h3>Indicators of Compromise (IOCs)</h3></div>
            <table>
                <thead><tr><th>Attacker Host IP</th><th>Subnet / CIDR</th><th>Observed Date</th></tr></thead>
                <tbody>
                    <tr><td>198.51.100.99</td><td>198.51.100.0/24</td><td>10/21/2026</td></tr>
                </tbody>
            </table>
            <ul>
                <li>hxxp://c2-malicious.com/shell.php</li>
                <li>User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0 Safari/537.36</li>
            </ul>
        </body>
        </html>
        """
        parser = GenericParser()
        results = parser.parse(html_content, {"reported_by": "TestTable"})
        inds = {r["indicator"] for r in results}
        assert "198.51.100.99" in inds
        # Network subnet base address must NOT be ingested as an attacker host IP
        assert "198.51.100.0" not in inds
        # Browser version string must NOT be ingested as an attacker host IP
        assert "130.0.0.0" not in inds
        assert "http://c2-malicious.com/shell.php" in inds
