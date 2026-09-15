"""PSK_DEFAULTS Top-20 sigiloso: lista, fase y omisión."""
import sys, os, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris.models import TargetInfo

def _tgt(ssid="LAB-TEST", bssid="AA:BB:CC:DD:EE:FF", ch=6):
    return TargetInfo(bssid=bssid, ssid=ssid, channel=ch,
                      encryption="WPA2", wps_enabled=False,
                      oui=bssid.replace(":", "")[:6], signal_strength=-55)

def test_top20_list_valid():
    from auris.runner import DEFAULT_TOP20
    assert len(DEFAULT_TOP20) == 20
    assert len(set(DEFAULT_TOP20)) == 20
    assert all(len(p) >= 8 for p in DEFAULT_TOP20)
    # prevalentes humanas
    assert "12345678" in DEFAULT_TOP20
    assert "password" in DEFAULT_TOP20
    assert "admin1234" in DEFAULT_TOP20

def test_phase_skipped_without_hash_or_cap(tmp_path, monkeypatch):
    import auris.runner as r
    monkeypatch.setattr(r, "_tool_available", lambda n: False)
    assert r._phase_psk_defaults(_tgt(), str(tmp_path))[0] == "skipped"

def test_phase_cracked_second_batch_jitter(monkeypatch, tmp_path):
    import auris.runner as r
    # hash existe, hashcat disponible, cap no necesario
    monkeypatch.setattr(r, "_tool_available", lambda n: n in ("hashcat", "tcpdump"))
    monkeypatch.setattr(r, "_ensure_hc22000", lambda d, b=None: str(tmp_path / "handshake.hc22000"))
    # crear hash ficticio
    (tmp_path / "handshake.hc22000").write_text("fakehash")
    monkeypatch.setattr(r, "_aircrack_cap", lambda d: None)
    # hashcat: falla lote 1, acierta lote 2
    calls = []
    def fake_run_tool(cmd, timeout, desc=None):
        calls.append(list(cmd))
        # segundo lote = cracked
        if "batch2" in " ".join(cmd):
            return {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False}
        return {"returncode": 1, "stdout": "", "stderr": "", "timed_out": False}
    monkeypatch.setattr(r, "_run_tool", fake_run_tool)
    monkeypatch.setattr(r, "_extract_hashcat_key", lambda p: "12345678")
    sleeps = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))
    # jitter determinista
    monkeypatch.setattr(r.random, "uniform", lambda a, b: 0.3)
    status, key, typ = r._phase_psk_defaults(_tgt(), str(tmp_path))
    assert status == "cracked" and key == "12345678"
    assert "Top-20" in typ
    assert len(calls) == 2
    assert len(sleeps) == 1 and 2.0 <= sleeps[0] <= 6.0

def test_phase_exhausted_silent(monkeypatch, tmp_path):
    import auris.runner as r
    monkeypatch.setattr(r, "_tool_available", lambda n: n == "hashcat")
    monkeypatch.setattr(r, "_ensure_hc22000", lambda d, b=None: str(tmp_path / "handshake.hc22000"))
    (tmp_path / "handshake.hc22000").write_text("fake")
    monkeypatch.setattr(r, "_aircrack_cap", lambda d: None)
    monkeypatch.setattr(r, "_run_tool", lambda cmd, timeout, desc=None: {"returncode": 1, "stdout": "", "stderr": "", "timed_out": False})
    monkeypatch.setattr(r, "_extract_hashcat_key", lambda p: None)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    monkeypatch.setattr(r.random, "uniform", lambda a, b: 0.1)
    status, _, _ = r._phase_psk_defaults(_tgt(), str(tmp_path))
    assert status == "exhausted"

def test_decide_path_injects_defaults():
    from auris.decision_engine import decide_path
    from auris.models import Profile
    # WPS_CLASS
    t = _tgt()
    t.wps_enabled = True; t.wps_version = "2.0"
    p = Profile(brand="Askey", pin_class="generic_pin_family", isp_locked_fw=False)
    path = decide_path(t, p)
    assert path.index("PSK_DEFAULTS") == path.index("CAPTURE_HANDSHAKE") + 1
    assert path.index("WPS_CLASS") > path.index("PSK_DEFAULTS")
    # WPS_PIXIE
    t2 = _tgt(); t2.wps_enabled = True; t2.wps_version = "1.0"
    p2 = Profile(brand="?", pin_class="unknown", isp_locked_fw=False)
    path2 = decide_path(t2, p2)
    assert path2.index("PSK_DEFAULTS") == path2.index("CAPTURE_HANDSHAKE") + 1
    # PMKID
    t3 = _tgt(); t3.wps_enabled = False; t3.wpa3_supported = False
    path3 = decide_path(t3, p2)
    assert path3.index("PSK_DEFAULTS") == path3.index("CAPTURE_PMKID") + 1
    # WPA3 no lleva PSK_DEFAULTS
    t4 = _tgt(); t4.wps_enabled = False; t4.wpa3_supported = True
    path4 = decide_path(t4, p2)
    assert "PSK_DEFAULTS" not in path4
    assert "DETECT_WPA3_SAE" in path4

def test_offensive_sets_include_defaults():
    from auris.runner import ATTACK_PHASES
    from auris.pipeline import _OFFENSIVE_PHASES
    assert "PSK_DEFAULTS" in ATTACK_PHASES
    assert "PSK_DEFAULTS" in _OFFENSIVE_PHASES
