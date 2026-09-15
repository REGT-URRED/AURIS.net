import sys
import os

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris.models import TargetInfo, Profile


@pytest.fixture
def no_tools(monkeypatch):
    """Simula Kali vacía: ningún binario de radio/Python externo disponible."""
    import auris.runner as r
    monkeypatch.setattr(r, "_tool_available", lambda name: False)
    return r


@pytest.fixture
def tgt():
    return TargetInfo(bssid="00:1C:DF:AA:BB:CC", ssid="MOVISTAR_AB12", channel=6,
                      encryption="WPA2", wps_enabled=True, wps_version="1.0",
                      oui="001CDF", signal_strength=-55)


def test_capture_phases_degrade(no_tools, tgt, tmp_path):
    assert no_tools._phase_capture_pmkid(tgt, "wlan0", str(tmp_path)) == "skipped"
    assert no_tools._phase_capture_handshake(tgt, "wlan0", str(tmp_path)) == "skipped"


def test_wps_phases_degrade(no_tools, tgt):
    assert no_tools._phase_wps_class(tgt, "wlan0")[0] == "skipped"
    assert no_tools._phase_wps_pixie(tgt, "wlan0")[0] == "skipped"


def test_psk_phases_degrade_without_hash_or_hashcat(no_tools, tgt, tmp_path):
    # Sin hash capturado ni hashcat: skipped limpio, sin excepciones
    assert no_tools._phase_psk_ssid_logic(tgt, str(tmp_path))[0] == "skipped"
    assert no_tools._phase_psk_rockyou(tgt, str(tmp_path))[0] == "skipped"


def test_resilience_degrades(no_tools, tgt, tmp_path):
    assert no_tools._phase_resilience_test(tgt, "wlan0", str(tmp_path)) == "skipped"


def test_full_run_without_tools(no_tools, tgt, tmp_path, monkeypatch):
    """run_single_target completa en Kali vacía: informe honesto, cero crash."""
    import auris.roe as roe
    monkeypatch.setattr(roe, "evidence_dir", lambda rid: str(tmp_path / rid) or str(tmp_path))
    import os as _os
    _os.makedirs(str(tmp_path), exist_ok=True)
    r = no_tools.run_single_target(
        tgt, Profile(brand="Askey", pin_class="generic_pin_family", isp_locked_fw=True),
        iface="lo", scope={"db_path": str(tmp_path / "t.db")})
    assert r["result"] in ("exhausted", "eol_confirmed", "locked", "not_found", "done")
    assert r["recovered_key"] is None
    assert set(r["phase_results"]) >= {"CAPTURE_HANDSHAKE", "WPS_CLASS"}
    assert all(v in ("skipped", "not_found", "done", "locked", "timeout", "error",
                     "exhausted", "eol_confirmed", "cracked", "class_confirmed",
                     "captured") for v in r["phase_results"].values())


def test_scanner_degrades_without_tools(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: None)
    from auris.scanner import _scan_airodump, _scan_wash
    assert _scan_airodump("wlan0", 1) == []
    assert _scan_wash("wlan0", 1) == []
