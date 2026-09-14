import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris.wordlists import quick_check, deep_count, find_rockyou
from auris.wids import WIDSSensor


def test_quick_check_missing(tmp_path):
    r = quick_check(str(tmp_path / "nope.txt"))
    assert r["status"] == "missing"


def test_quick_check_incomplete(tmp_path):
    p = tmp_path / "mini.txt"
    p.write_text("a\nb\nc\n")
    assert quick_check(str(p))["status"] == "incomplete"


def test_quick_check_compressed(tmp_path):
    p = tmp_path / "r.txt.gz"
    p.write_bytes(b"x" * 100)
    assert quick_check(str(p))["status"] == "compressed"


def test_deep_count_mismatch(tmp_path):
    p = tmp_path / "mini.txt"
    p.write_text("a\nb\nc\n")
    r = deep_count(str(p))
    assert r["status"] == "mismatch" and r["lines"] == 3


def test_deep_count_compressed_refuses(tmp_path):
    p = tmp_path / "r.txt.gz"
    p.write_bytes(b"x")
    assert deep_count(str(p))["status"] == "compressed"


def test_find_rockyou_override(tmp_path):
    p = tmp_path / "custom.txt"
    p.write_text("x\n")
    assert find_rockyou("/noexiste", str(p)) == str(p)
    assert find_rockyou("/noexiste", "") is None


def test_wids_marks_simulated():
    assert WIDSSensor.SIMULATED is True
    s = WIDSSensor(interface="lo")
    s.alerts.append({"alert_type": "Deauth Flood", "severity": "High",
                     "source_mac": "00:AA:BB:CC:DD:EE",
                     "dest_mac": "FF:FF:FF:FF:FF:FF", "simulated": True})
    assert all(a.get("simulated") for a in s.get_alerts())


def test_report_footnote_simulated(tmp_path):
    from auris.report_writer import generate_markdown_report
    results = [{"ssid": "T", "bssid": "00:11:22:33:44:55", "encryption": "WPA2",
                "result": "exhausted", "path": [], "wids_alerts": 2,
                "wids_simulated": True, "recovered_key": None, "key_type": None,
                "elapsed_sec": 1}]
    out = str(tmp_path / "r.md")
    generate_markdown_report(results, {}, out)
    text = open(out).read()
    assert "simuladas" in text


def test_report_no_footnote_without_alerts(tmp_path):
    from auris.report_writer import generate_markdown_report
    results = [{"ssid": "T", "bssid": "00:11:22:33:44:55", "encryption": "WPA2",
                "result": "exhausted", "path": [], "wids_alerts": 0,
                "wids_simulated": False, "recovered_key": None, "key_type": None,
                "elapsed_sec": 1}]
    out = str(tmp_path / "r.md")
    generate_markdown_report(results, {}, out)
    assert "simuladas" not in open(out).read()
