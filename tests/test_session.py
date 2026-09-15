import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris.session import (
    new_session, save_progress, load_session, latest_session,
)


def _res(bssid, ssid="T"):
    return {"bssid": bssid, "ssid": ssid, "result": "exhausted", "path": [],
            "recovered_key": None, "key_type": None, "wids_alerts": 0,
            "wids_simulated": False, "elapsed_sec": 1, "lan_surface": None,
            "vendor_intel": {"brand": "X", "profile": {}, "historic": []}}


def test_roundtrip_and_idempotent(tmp_path):
    proj = str(tmp_path)
    s = new_session(proj)
    assert os.path.isfile(s["path"])
    save_progress(s["path"], _res("AA:BB:CC:DD:EE:FF"))
    save_progress(s["path"], _res("11:22:33:44:55:66"))
    save_progress(s["path"], _res("aa:bb:cc:dd:ee:ff"))  # duplicado case-insensitive
    st = load_session(s["path"])
    assert len(st["completed"]) == 2
    # última escritura gana pero conserva la posición original
    assert st["completed_bssids"] == ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]
    assert latest_session(proj) == s["path"]
    assert load_session(str(tmp_path / "nope.json")) is None
    # el archivo es JSON válido y autocontenido (serializable al informe)
    json.dumps(st)


def test_latest_none_when_empty(tmp_path):
    assert latest_session(str(tmp_path)) is None


def test_unique_paths_no_collision(tmp_path):
    from auris.session import _unique_path, new_session
    p = tmp_path / "x.json"
    p.write_text("{}")
    q = _unique_path(str(p))
    assert q != str(p) and q.endswith("-1.json")
    assert _unique_path(str(tmp_path / "nuevo.json")) == str(tmp_path / "nuevo.json")
    a = new_session(str(tmp_path))
    b = new_session(str(tmp_path))
    assert a["path"] != b["path"] and a["id"] != b["id"]


def test_corrupt_scope_clean_exit(tmp_path):
    import subprocess, sys
    bad = tmp_path / "scope.yml"
    bad.write_text("foo: [bar\n:baz")
    r = subprocess.run(
        [sys.executable, "auris.py", "run-all", "--scope-file", str(bad), "--dry-run"],
        capture_output=True, text=True, timeout=60,
        cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    assert r.returncode == 1
    assert "Traceback" not in (r.stdout + r.stderr)
    assert "corrupto" in (r.stdout + r.stderr).lower()
