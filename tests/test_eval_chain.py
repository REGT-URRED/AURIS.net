"""Cadena de evaluación secuencial: BROADCOM_EVAL, omisión WPS parcheado y salidas.

Estos tests NO requieren hardware, radio ni conexión: solo stubs y monkeypatch.
"""

import os
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from types import SimpleNamespace

from auris.models import Profile, TargetInfo

import pytest


def _tgt(wps_version=None, wps_enabled=False):
    return TargetInfo(
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="LAB-TEST",
        channel=6,
        encryption="WPA2",
        wps_enabled=wps_enabled,
        wps_version=wps_version,
        oui="AABBCC",
        signal_strength=-55,
    )


# ── decision_engine ──────────────────────────────────────────────────────────


def test_wps_branches_lead_with_broadcom_eval():
    from auris.decision_engine import decide_path

    p = Profile(brand="Askey", pin_class="generic_pin_family", isp_locked_fw=False)
    t = _tgt(wps_version="2.0", wps_enabled=True)
    path = decide_path(t, p)
    assert path[0] == "BROADCOM_EVAL"
    assert path.index("CAPTURE_HANDSHAKE") == 1

    t2 = _tgt(wps_version="1.0", wps_enabled=True)
    p2 = Profile(brand="?", pin_class="unknown", isp_locked_fw=False)
    assert decide_path(t2, p2)[0] == "BROADCOM_EVAL"

    # Ruta no-WPS sin cambio
    t3 = _tgt(wps_enabled=False)
    assert "BROADCOM_EVAL" not in decide_path(t3, p2)


# ── runner: fase de evaluación ───────────────────────────────────────────────


@pytest.fixture
def eval_state(monkeypatch):
    """Estado por-target limpio antes de cada test de evaluación."""
    import auris.runner as R

    monkeypatch.setattr(R, "_broadcom_patched", False)
    monkeypatch.setattr(R, "_broadcom_eval", None)
    return R


def test_eval_without_uv_continues_chain(eval_state, monkeypatch):
    R = eval_state
    monkeypatch.setattr(R, "_tool_available", lambda name: False)
    status, key, ktype = R._phase_broadcom_eval(_tgt(wps_enabled=True), "wlan0mon")
    assert status == "evaluated"
    assert ktype == "broadcom_unavailable"
    assert R._broadcom_eval is None


def test_eval_patched_hostapd_sets_flag(eval_state, monkeypatch):
    R = eval_state
    monkeypatch.setattr(R, "_tool_available", lambda name: name == "uv")
    monkeypatch.setattr(
        R.broadcom,
        "fingerprint",
        lambda iface, ssid, timeout=240.0: SimpleNamespace(
            assessment="PATCHED_HOSTAPD",
            model="CG3100",
            warning=None,
            evidence=("a", "b", "c", "d"),
        ),
    )
    status, key, ktype = R._phase_broadcom_eval(_tgt(wps_enabled=True), "wlan0mon")
    assert status == "determined"
    assert ktype == "patched_hostapd"
    assert R._broadcom_patched is True
    assert R._broadcom_eval["evidence"] == ("a", "b", "c")
    assert R._broadcom_eval["model"] == "CG3100"


def test_eval_vulnerable_marks_zero_day(eval_state, monkeypatch):
    R = eval_state
    monkeypatch.setattr(R, "_tool_available", lambda name: name == "uv")
    monkeypatch.setattr(
        R.broadcom,
        "fingerprint",
        lambda iface, ssid, timeout=240.0: SimpleNamespace(
            assessment="LIKELY_VULNERABLE", model="CG3100", warning=None, evidence=()
        ),
    )
    status, key, ktype = R._phase_broadcom_eval(_tgt(wps_enabled=True), "wlan0mon")
    assert status == "determined"
    assert ktype == "zero_day_wps_broadcom"
    assert R._broadcom_patched is False
    assert R._broadcom_eval["assessment"] == "LIKELY_VULNERABLE"


def test_eval_broadcom_error_continues(eval_state, monkeypatch):
    from auris.broadcom import BroadcomError

    R = eval_state
    monkeypatch.setattr(R, "_tool_available", lambda name: name == "uv")

    def boom(*args, **kwargs):
        raise BroadcomError("fingerprinter falló (rc=2)")

    monkeypatch.setattr(R.broadcom, "fingerprint", boom)
    status, key, ktype = R._phase_broadcom_eval(_tgt(wps_enabled=True), "wlan0mon")
    assert status == "evaluated"
    assert ktype == "broadcom_unavailable"
    assert R._broadcom_eval is None


# ── runner: omisión WPS con hostapd parcheado + reseteo por target ──────────


def test_patched_verdict_gates_wps_phases_and_resets(tmp_path, monkeypatch):
    import auris.roe as roe
    import auris.runner as R

    t = _tgt(wps_version="2.0", wps_enabled=True)
    profile = Profile(
        brand="Askey", pin_class="generic_pin_family", isp_locked_fw=False
    )
    monkeypatch.setattr(roe, "evidence_dir", lambda rid: str(tmp_path / rid))
    called = []

    def fake_eval(tgt, iface, timeout=240.0):
        R._broadcom_patched = True
        R._broadcom_eval = {
            "assessment": "PATCHED_HOSTAPD",
            "model": "CG3100",
            "warning": None,
            "evidence": (),
        }
        return "determined", "", "patched_hostapd"

    monkeypatch.setattr(R, "_phase_broadcom_eval", fake_eval)
    monkeypatch.setattr(
        R, "_phase_capture_handshake", lambda tgt, iface, run_dir: "captured"
    )
    _psk_runs = []

    def _fake_psk(tgt, run_dir):
        _psk_runs.append(1)
        if len(_psk_runs) == 1:
            return ("cracked", "claveLab2024", "WPA2-PSK (Top-20 defaults)")
        # 2.ª corrida sin cracked: permite verificar que el reseteo del estado
        # Broadcom llega hasta dejar correr la fase WPS de la ruta.
        return ("skipped", None, None)

    monkeypatch.setattr(
        R,
        "_phase_psk_defaults",
        _fake_psk,
    )

    def boom(name):
        def inner(*args, **kwargs):
            called.append(name)
            return "skipped", None, None

        return inner

    monkeypatch.setattr(R, "_phase_wps_class", boom("WPS_CLASS"))
    monkeypatch.setattr(R, "_phase_wps_pixie", boom("WPS_PIXIE"))

    res = R.run_single_target(
        t, profile, iface="lo", scope={"db_path": str(tmp_path / "t.db")}
    )
    assert called == []
    # La ruta v2.0 con familia de PIN solo planifica WPS_CLASS (sin WPS_PIXIE):
    # el gating del veredicto parcheado se observa en esa fase.
    assert res["phase_results"]["WPS_CLASS"] == "skipped"
    assert res["phase_results"]["PSK_DEFAULTS"] == "cracked"
    assert res["phase_results"]["BROADCOM_EVAL"] == "determined"
    assert res["recovered_key"] == "claveLab2024"
    assert res["broadcom_eval"]["assessment"] == "PATCHED_HOSTAPD"
    assert R._broadcom_patched is True

    # Segundo target: estado por-target se resetea al inicio de la run
    monkeypatch.setattr(
        R,
        "_phase_broadcom_eval",
        lambda tgt, iface, timeout=240.0: ("evaluated", "", "broadcom_unavailable"),
    )
    res2 = R.run_single_target(
        t, profile, iface="lo", scope={"db_path": str(tmp_path / "t.db")}
    )
    assert R._broadcom_patched is False
    assert R._broadcom_eval is None
    assert "broadcom_eval" not in res2
    # Sin crack en la 2.ª corrida, la fase WPS de la ruta sí se ejecuta
    # (no queda bloqueada por el veredicto parcheado de la corrida anterior).
    assert called == ["WPS_CLASS"]
    assert res2["phase_results"]["WPS_CLASS"] == "skipped"


# ── broadcom: timeouts ───────────────────────────────────────────────────────


def test_run_timeout_raises_broadcom_error(tmp_path, monkeypatch):
    from auris import broadcom

    def raises_timeout(command, cwd, timeout=180.0, **kwargs):
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(broadcom.subprocess, "run", raises_timeout)
    with pytest.raises(broadcom.BroadcomError) as excinfo:
        broadcom._run(["fake"], str(tmp_path), timeout=1.0)
    assert "supero el tiempo" in str(excinfo.value)


def test_fingerprint_forwards_default_timeout(tmp_path, monkeypatch):
    from auris import broadcom

    captured = {}
    monkeypatch.setattr(broadcom, "_interpreter_command", lambda args: ["fake", *args])

    def fake_run(command, cwd, timeout=180.0):
        captured["timeout"] = timeout
        return SimpleNamespace(returncode=2, stdout="", stderr="fallo")

    monkeypatch.setattr(broadcom, "_run", fake_run)
    with pytest.raises(broadcom.BroadcomError):
        broadcom.fingerprint("wlan0mon", "TEST", cwd=str(tmp_path))
    assert captured["timeout"] == 240.0


# ── report_writer: credenciales + vulnerabilidades ──────────────────────────


def _report_results():
    return [
        {
            "bssid": "11:22:33:44:55:66",
            "ssid": "FIBRA_VULNERABLE",
            "encryption": "WPA2",
            "result": "cracked",
            "path": ["BROADCOM_EVAL", "CAPTURE_HANDSHAKE", "PSK_DEFAULTS", "REPORT"],
            "recovered_key": "clave12345",
            "key_type": "WPA2-PSK (Top-20 defaults, aircrack-ng)",
            "wids_alerts": 0,
            "broadcom_eval": {
                "assessment": "LIKELY_VULNERABLE",
                "model": "CG3100",
                "warning": None,
                "evidence": (),
            },
        },
        {
            "bssid": "22:22:22:22:22:22",
            "ssid": "RED_BLINDADA",
            "result": "exhausted",
            "recovered_key": None,
            "key_type": None,
            "wids_alerts": 0,
            "wps_locked": True,
            "wpa3_supported": True,
        },
    ]


def test_collect_credentials_maps_methods():
    from auris.report_writer import _collect_credentials

    creds = _collect_credentials(_report_results())
    assert len(creds) == 1
    assert creds[0]["metodo"] == "Contraseñas por defecto"
    assert creds[0]["tipo"] == "WPA2-PSK (Top-20 defaults, aircrack-ng)"

    extras = _collect_credentials(
        [
            {
                "ssid": "A",
                "bssid": "AA",
                "recovered_key": "k",
                "key_type": "WPS Pixie Dust",
            },
            {
                "ssid": "B",
                "bssid": "BB",
                "recovered_key": "k",
                "key_type": "WPS PIN (Clase conocida)",
            },
            {
                "ssid": "C",
                "bssid": "CC",
                "recovered_key": "k",
                "key_type": "WPA2-PSK (Lógica SSID familia)",
            },
            {
                "ssid": "D",
                "bssid": "DD",
                "recovered_key": "k",
                "key_type": "WPA2-PSK (Diccionario)",
            },
        ]
    )
    metodos = [c["metodo"] for c in extras]
    assert metodos == [
        "WPS Pixie Dust",
        "PIN por clase",
        "Análisis lógica SSID",
        "Diccionario",
    ]


def test_markdown_has_credentials_and_vulnerabilities(tmp_path):
    from auris.report_writer import generate_markdown_report

    md_path = str(tmp_path / "informe.md")
    generate_markdown_report(_report_results(), {"institution": "UNLP"}, md_path)
    content = open(md_path, encoding="utf-8").read()
    assert "## Contraseñas recuperadas" in content
    assert "## Vulnerabilidades verificadas" in content
    assert "Zero-day BRCM EAP fragment reassembly (wps_monitor)" in content
    assert "Clave recuperada via Contraseñas por defecto" in content
    assert "WPS bloqueado" in content
    assert "Ninguna clave recuperada en esta sesion" in content


def test_write_passwords_file(tmp_path):
    from auris.report_writer import write_passwords_file

    out = tmp_path / "claves.txt"
    n = write_passwords_file(_report_results(), str(out))
    assert n == 1
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "SSID;BSSID;tipo;clave"
    assert "FIBRA_VULNERABLE;11:22:33:44:55:66;" in lines[1]

    zero = tmp_path / "nada.txt"
    assert (
        write_passwords_file(
            [{"ssid": "X", "bssid": "BB", "recovered_key": None, "key_type": None}],
            str(zero),
        )
        == 0
    )
    assert not zero.exists()


# ── targeting ────────────────────────────────────────────────────────────────


def test_targeting_missing_signal_reason():
    from auris.targeting import score_target

    rt = score_target(
        {
            "bssid": "AA:BB:CC:DD:EE:01",
            "ssid": "S",
            "encryption": "WPA2",
            "signal_strength": None,
        }
    )
    assert "señal desconocida" in rt.reasons
    rt2 = score_target(
        {"bssid": "AA:BB:CC:DD:EE:02", "ssid": "S", "encryption": "WPA2"}
    )
    assert "señal desconocida" in rt2.reasons


def test_brand_of_prefers_explicit():
    from auris.targeting import brand_of

    assert (
        brand_of({"oui": "001CDF", "ssid": "MOVISTAR_X", "brand": "Cisco"}) == "Cisco"
    )
    assert (
        brand_of({"oui": "001CDF", "ssid": "MOVISTAR_X", "brand": "Unknown"}) == "Askey"
    )


# ── vendor_profiles: aviso de mapa OUI ──────────────────────────────────────


def test_oui_map_warning_once(tmp_path, capsys, monkeypatch):
    import auris.vendor_profiles as vp

    monkeypatch.setattr(vp, "_OUI_WARNED", False)

    # Archivo ausente: normal, sin aviso
    assert vp._lab_overrides(str(tmp_path / "nope.json")) == {}
    assert "mapa OUI no disponible" not in capsys.readouterr().out

    # Archivo ilegible: aviso una sola vez
    bad = tmp_path / "vendor_map.json"
    bad.write_text("{no-json")
    assert vp._lab_overrides(str(bad)) == {}
    assert vp._lab_overrides(str(bad)) == {}
    out = capsys.readouterr().out
    assert out.count("mapa OUI no disponible") == 1
