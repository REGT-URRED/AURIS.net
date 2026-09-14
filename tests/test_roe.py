import sys
import os
import hashlib
from datetime import date

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris.roe import (
    RoEError, parse_time_window, check_time_window, enforce_scope,
    verify_mac_stable, read_iface_mac, evidence_dir, write_evidence_manifest,
    db_path_for,
)


def _scope(**kw):
    base = {
        "time_window": "2026-01-01/2026-12-31",
        "allowed_bssids": ["00:11:22:33:44:55"],
        "dry_run_default": True,
        "forbid_mac_rotation": True,
        "iface_red_team": "lo",
        "db_path": "data/auris.db",
    }
    base.update(kw)
    return base


def test_time_window_inside():
    ok, _ = check_time_window(_scope(), today=date(2026, 9, 12))
    assert ok is True


def test_time_window_outside():
    ok, msg = check_time_window(_scope(), today=date(2027, 1, 5))
    assert ok is False and "fuera de ventana" in msg


def test_time_window_missing_denies():
    ok, _ = check_time_window({}, today=date(2026, 9, 12))
    assert ok is False
    assert parse_time_window("no-es-fecha") is None


def test_enforce_blocks_real_run_by_default():
    with pytest.raises(RoEError):
        enforce_scope(_scope(), dry_run=False, force_roe=False)


def test_enforce_allows_dry_run_and_forced():
    assert enforce_scope(_scope(), dry_run=True)["window"].startswith("ventana OK")
    assert enforce_scope(_scope(), dry_run=False, force_roe=True)["window"].startswith("ventana OK")


def test_enforce_force_bypasses_dead_clock():
    ctx = enforce_scope(_scope(time_window="2020-01-01/2020-12-31"),
                        dry_run=False, force_roe=True)
    assert ctx["window_bypassed"] is True
    with pytest.raises(RoEError):
        enforce_scope(_scope(time_window="2020-01-01/2020-12-31"), dry_run=True)


def test_scope_filter_bssid_and_ssid():
    from auris.cli import _apply_scope_filter
    import typer
    targets = [{"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "CASA"},
               {"bssid": "11:22:33:44:55:66", "ssid": "VECINO"}]
    scope = {"allowed_bssids": ["AA:BB:CC:DD:EE:FF"], "allowed_ssids": ["CASA"]}
    f, dropped, lab = _apply_scope_filter(targets, scope)
    assert len(f) == 1 and dropped == 1 and lab is False
    # SSID fuera aunque BSSID dentro
    scope2 = {"allowed_bssids": ["AA:BB:CC:DD:EE:FF"], "allowed_ssids": ["OTRA"]}
    with pytest.raises(typer.Exit):
        _apply_scope_filter(targets, scope2)
    # modo lab: todo pasa
    f3, d3, lab3 = _apply_scope_filter(targets, {"allowed_bssids": ["aa:bb:cc:dd:ee:ff"]})
    assert len(f3) == 2 and lab3 is True


def test_enforce_requires_allowlist_and_window():
    with pytest.raises(RoEError):
        enforce_scope(_scope(allowed_bssids=[]), dry_run=True)
    with pytest.raises(RoEError):
        enforce_scope(_scope(time_window="2020-01-01/2020-12-31"), dry_run=True)


def test_mac_stable_loopback():
    mac = read_iface_mac("lo")
    assert mac  # sysfs legible en Linux
    ok, _ = verify_mac_stable("lo", mac)
    assert ok is True
    ok2, msg2 = verify_mac_stable("lo", "11:22:33:44:55:66")
    assert ok2 is False and "cambió" in msg2
    ok3, _ = verify_mac_stable("noexiste0", None)
    assert ok3 is True


def test_evidence_dir_absolute(tmp_path, monkeypatch):
    d = evidence_dir("test123")
    assert os.path.isabs(d) and d.endswith(os.path.join("evidence", "test123"))
    assert os.path.isdir(d)


def test_manifest_hashes_files(tmp_path):
    (tmp_path / "a.pcapng").write_bytes(b"X" * 64)
    (tmp_path / "b.txt").write_text("hola")
    m = write_evidence_manifest(str(tmp_path))
    assert m["a.pcapng"] == hashlib.sha256(b"X" * 64).hexdigest()
    assert m["b.txt"] == hashlib.sha256(b"hola").hexdigest()
    sums = (tmp_path / "SHA256SUMS").read_text()
    assert "a.pcapng" in sums and "b.txt" in sums
    # idempotente: SHA256SUMS no se auto-hashea
    m2 = write_evidence_manifest(str(tmp_path))
    assert set(m2) == {"a.pcapng", "b.txt"}


def test_record_run_persists(tmp_path):
    from auris.db import init_db, record_run, Run, PhaseResult
    db = str(tmp_path / "t.db")
    s = init_db(db)
    record_run(s, "abc123", "MOVISTAR_AB12", "00:1C:DF:AA:BB:CC",
               "exhausted", ["CAPTURE_HANDSHAKE", "WPS_CLASS", "REPORT"],
               {"CAPTURE_HANDSHAKE": "captured", "WPS_CLASS": "exhausted"})
    assert s.query(Run).filter_by(id="abc123").one().path_taken.startswith("CAPTURE")
    rows = s.query(PhaseResult).filter_by(run_id="abc123").all()
    assert {r.phase: r.result for r in rows} == {
        "CAPTURE_HANDSHAKE": "captured", "WPS_CLASS": "exhausted"}
    s.close()


def test_db_path_absolute():
    p = db_path_for({"db_path": "data/auris.db"})
    assert os.path.isabs(p) and p.endswith("data/auris.db")
