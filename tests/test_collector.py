import json
from pathlib import Path
from scripts.collect_iocs import (
    load_existing_dataset,
    write_dataset_and_blocklists,
    fetch_source_content,
    SCHEMA_COLUMNS,
)


def test_write_and_load_dataset(tmp_path: Path):
    sample_records = [
        {
            "indicator": "103.216.220.92",
            "type": "ip",
            "first_seen": "2026-10-17",
            "source": "https://source.example.com",
            "reported_by": "MadPot",
            "confidence": "high",
            "context": "Exploitation attempt",
        },
        {
            "indicator": "php2shell.xyz",
            "type": "domain",
            "first_seen": "2026-10-21",
            "source": "https://source.example.com",
            "reported_by": "FortiGuard",
            "confidence": "high",
            "context": "C2 node",
        },
        {
            "indicator": "40caf199ca1ebe056a74427f8e9db06c66899e33ae09c0ec2769ec70bf6dd8e7",
            "type": "sha256",
            "first_seen": "2026-10-22",
            "source": "https://source.example.com",
            "reported_by": "Arctic Wolf",
            "confidence": "high",
            "context": "Dropper script",
        },
    ]

    output_dir = tmp_path / "iocs"
    write_dataset_and_blocklists(sample_records, output_dir)

    # Check files exist
    assert (output_dir / "php2shell_iocs.csv").is_file()
    assert (output_dir / "php2shell_iocs.json").is_file()
    assert (output_dir / "ips.txt").is_file()
    assert (output_dir / "domains.txt").is_file()
    assert (output_dir / "hashes.txt").is_file()

    # Check ips.txt
    ips = (output_dir / "ips.txt").read_text(encoding="utf-8").strip().splitlines()
    assert ips == ["103.216.220.92"]

    # Check domains.txt
    domains = (output_dir / "domains.txt").read_text(encoding="utf-8").strip().splitlines()
    assert domains == ["php2shell.xyz"]

    # Check hashes.txt
    hashes = (output_dir / "hashes.txt").read_text(encoding="utf-8").strip().splitlines()
    assert hashes == ["40caf199ca1ebe056a74427f8e9db06c66899e33ae09c0ec2769ec70bf6dd8e7"]

    # Test reload
    loaded = load_existing_dataset(output_dir / "php2shell_iocs.csv")
    assert len(loaded) == 3
    assert loaded[0]["indicator"] == "103.216.220.92"


def test_fetch_source_content_snapshot_fallback(tmp_path: Path):
    snapshot = tmp_path / "sample_snapshot.txt"
    snapshot.write_text("sample content from snapshot", encoding="utf-8")

    src_cfg = {
        "name": "test_feed",
        "url": "",  # no remote url
        "local_snapshot": "sample_snapshot.txt",
    }
    content = fetch_source_content(src_cfg, tmp_path)
    assert content == "sample content from snapshot"
