import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris.models import TargetInfo, Profile, ThreatModelSTRIDE
from auris.decision_engine import decide_path, calculate_stride_threat
from auris.db import init_db, Vendor

def test_stride_calculation():
    target = TargetInfo(
        bssid="00:11:22:33:44:55",
        ssid="TEST_WIFI",
        channel=6,
        encryption="WPA2",
        wps_enabled=True,
        wps_version="1.0",
        oui="001122",
        signal_strength=-60
    )
    profile = Profile(brand="Askey", pin_class="generic_pin_family", isp_locked_fw=True)
    
    stride = calculate_stride_threat(target, profile)
    
    assert stride.tampering > 0
    assert stride.elevation_of_privilege > 0
    assert stride.total_risk > 10

def test_decision_engine_wps_path():
    target = TargetInfo(
        bssid="00:11:22:33:44:55",
        ssid="TEST_WIFI",
        channel=6,
        encryption="WPA2",
        wps_enabled=True,
        wps_version="2.0",
        oui="001122",
        signal_strength=-60
    )
    profile = Profile(brand="Askey", pin_class="generic_pin_family")
    
    path = decide_path(target, profile, wids_enabled=True)
    
    assert "START_WIDS_MONITORING" in path
    assert "WPS_CLASS" in path
    assert "VALIDATE_COUNTERMEASURE" in path
    assert "REPORT" in path

def test_decision_engine_wep():
    target = TargetInfo(
        bssid="00:11:22:33:44:55",
        ssid="OLD_WIFI",
        channel=1,
        encryption="WEP",
        wps_enabled=False,
        oui="001122",
        signal_strength=-70
    )
    profile = Profile(brand="Unknown")
    
    path = decide_path(target, profile)
    
    assert "CLASSIFY_WEAK_CRYPTO" in path
    assert "REPORT" in path

def test_db_init(tmp_path):
    db_file = tmp_path / "test.db"
    session = init_db(str(db_file))
    
    v = Vendor(oui="00:11:22", brand="Test Brand", oem_group="CPE")
    session.add(v)
    session.commit()
    
    retrieved = session.query(Vendor).filter_by(oui="00:11:22").first()
    assert retrieved.brand == "Test Brand"


def test_reaver_credential_extraction():
    from auris.runner import _extract_reaver_credentials
    sample_stdout = """
    [+] Waiting for beacon from 00:11:22:33:44:55
    [+] Associated with 00:11:22:33:44:55 (ESSID: TEST_AP)
    [+] WPS PIN: '12345670'
    [+] WPA PSK: 'ClaveSecreta2026'
    [+] AP SSID: 'TEST_AP'
    """
    creds = _extract_reaver_credentials(sample_stdout)
    assert creds.get("pin") == "12345670"
    assert creds.get("psk") == "ClaveSecreta2026"


def test_report_writer_with_recovered_password(tmp_path):
    import json
    from auris.report_writer import generate_markdown_report, generate_json_report

    scope = {
        "institution": "Laboratorio de Ciberseguridad",
        "student": "Investigador Demo",
        "supervisor": "Profesor Evaluador",
        "authorization": "DOC-AUTH-2026",
        "time_window": "09:00 - 12:00",
    }

    session_results = [
        {
            "bssid": "AA:BB:CC:11:22:33",
            "ssid": "FIBRA_VULNERABLE",
            "encryption": "WPA2",
            "wps_enabled": True,
            "wps_version": "1.0",
            "wps_locked": False,
            "wpa3_supported": False,
            "brand": "Askey",
            "result": "cracked",
            "path": ["WPS_PIXIE", "REPORT"],
            "recovered_key": "PIN: 12345670 | PSK: wifi12345",
            "key_type": "WPS Pixie Dust",
            "wids_alerts": 1,
            "elapsed_sec": 12.5,
        },
        {
            "bssid": "11:22:33:44:55:66",
            "ssid": "RED_ROBUSTA",
            "encryption": "WPA3",
            "wps_enabled": False,
            "wps_version": None,
            "wps_locked": False,
            "wpa3_supported": True,
            "brand": "Cisco",
            "result": "done",
            "path": ["DETECT_WPA3_SAE", "REPORT"],
            "recovered_key": None,
            "key_type": None,
            "wids_alerts": 0,
            "elapsed_sec": 4.1,
        }
    ]

    md_path = str(tmp_path / "informe.md")
    json_path = str(tmp_path / "informe.json")

    generate_markdown_report(session_results, scope, md_path)
    generate_json_report(session_results, scope, json_path)

    # Verificar Markdown
    with open(md_path, "r", encoding="utf-8") as f:
        md_content = f.read()

    assert "FIBRA_VULNERABLE" in md_content
    assert "wifi12345" in md_content
    assert "Registro de Credenciales y Contraseñas Obtenidas" in md_content
    assert "Evidencia Primordial" in md_content
    assert "Contraseñas Obtenidas" in md_content

    # Verificar JSON
    with open(json_path, "r", encoding="utf-8") as f:
        json_data = json.load(f)

    assert json_data["summary"]["compromised_keys_count"] == 1
    assert json_data["summary"]["recovered_credentials"][0]["recovered_key"] == "PIN: 12345670 | PSK: wifi12345"


def test_ssid_family_base():
    from auris.runner import ssid_family_base
    assert ssid_family_base("FAMILIA_WIFI_2") == "FAMILIA_WIFI"
    assert ssid_family_base("FAMILIA_WIFI-3") == "FAMILIA_WIFI"
    assert ssid_family_base("CASA_5G") == "CASA"
    assert ssid_family_base("RED") == "RED"
    assert ssid_family_base("LAB_AURIS") == "LAB_AURIS"


def test_ssid_candidates_base_patterns():
    from auris.runner import generate_ssid_candidates
    lote1, lote2 = generate_ssid_candidates("TestNet", "AA:BB:CC:11:22:33")
    assert "TestNet2026" in lote1
    assert "TestNet@2026@" in lote1
    assert "testnet123" in lote1
    assert all(len(c) >= 8 for c in lote1)
    assert len(lote1) == len(set(lote1))
    assert lote2 == []


def test_family_key_reuse_and_mutation():
    from auris.runner import generate_ssid_candidates, extract_reusable_psk
    assert extract_reusable_psk("PIN: 12345670 | PSK: wifi@2026@") == "wifi@2026@"
    assert extract_reusable_psk("PIN: 12345670") is None
    lote1, lote2 = generate_ssid_candidates(
        "WIFI_X2", "AA:BB:CC:11:22:33",
        family_keys={"WIFI_X": "wifi@2026@"},
    )
    assert "wifi@2026@" in lote1  # reutilización exacta primero
    assert "wifi@2026@1" in lote2  # mutación para el hermano
    assert "wifi@2026@2" in lote2
    # clave de SSID no emparentado no contamina
    l1b, l2b = generate_ssid_candidates(
        "WIFI_X2", "AA:BB:CC:11:22:33",
        family_keys={"OTRA_RED": "secreto999"},
    )
    assert "secreto999" not in l1b and all("secreto" not in c for c in l2b)



def test_safe_int_never_crashes():
    from auris.scanner import _safe_int
    assert _safe_int("6") == 6
    assert _safe_int("-1") == -1
    assert _safe_int("  -70 ") == -70
    assert _safe_int("e") == 0
    assert _safe_int("") == 0
    assert _safe_int(None) == 0
    assert _safe_int("abc", default=-70) == -70


def test_target_contract_for_cli():
    """Todo dict que sale del scanner debe traer las claves que consume run_all."""
    from auris.scanner import _empty_target, _demo_targets
    need = {"ssid", "bssid", "channel", "encryption", "oui", "signal_strength",
            "wps_enabled", "wps_version", "wps_locked", "wpa3_supported", "dpp_supported"}
    assert need <= set(_empty_target())
    for t in _demo_targets():
        assert need <= set(t), f"demo sin claves: {t.get('ssid')}"


def test_parse_aircrack_key():
    from auris.runner import _parse_aircrack_key
    # salida real de aircrack-ng
    salida = ("                               Aircrack-ng 1.7\n\n"
              "      [00:00:12] 1234/14344391 keys tested (1024.00 k/s)\n\n"
              "                     KEY FOUND! [ claveDePrueba2024 ]\n")
    assert _parse_aircrack_key(salida) == "claveDePrueba2024"
    assert _parse_aircrack_key("KEY FOUND! [ 12345678 ]") == "12345678"
    assert _parse_aircrack_key("no pasó nada") is None
    assert _parse_aircrack_key("") is None
    assert _parse_aircrack_key(None) is None


def test_aircrack_cap_detecta_capture(tmp_path):
    from auris.runner import _aircrack_cap
    # pcap mínimo plausible (cabecera de 24 bytes + relleno)
    cap = tmp_path / "handshake-01.cap"
    cap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    assert _aircrack_cap(str(tmp_path)) == str(cap)
    # archivo demasiado pequeño no sirve
    vacio = tmp_path / "vacio.cap"
    vacio.write_bytes(b"\xd4\xc3\xb2\xa1")
    tmp2 = tmp_path / "otro"
    tmp2.mkdir()
    (tmp2 / "vacio.cap").write_bytes(b"\xd4\xc3\xb2\xa1")
    assert _aircrack_cap(str(tmp2)) is None


def test_psk_fases_sin_herramientas_no_crashean(tmp_path):
    """Sin hashcat ni aircrack-ng las fases PSK degradan, nunca revientan."""
    from auris.runner import _phase_psk_rockyou, _phase_psk_ssid_logic
    from auris.models import TargetInfo
    import auris.runner as R
    orig = R._tool_available
    R._tool_available = lambda name: False
    try:
        t = TargetInfo(ssid="WIFI_TEST", bssid="AA:BB:CC:DD:EE:FF", channel=6,
                       encryption="WPA2", wps_enabled=False, oui="AABBCC",
                       signal_strength=-50)
        assert _phase_psk_ssid_logic(t, str(tmp_path))[0] == "skipped"
        assert _phase_psk_rockyou(t, str(tmp_path))[0] == "skipped"
    finally:
        R._tool_available = orig


def test_fallback_aircrack_ng_crackea_psk(tmp_path, monkeypatch):
    """Sin hashcat, el fallback aircrack-ng debe devolver la clave ya parseada."""
    import os as _os
    import auris.runner as R
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "handshake-01.cap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    shim = tmp_path / "bin"
    shim.mkdir()
    fake = shim / "aircrack-ng"
    fake.write_text("#!/bin/sh\necho 'KEY FOUND! [ claveDePrueba2024 ]'\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim}:{_os.environ['PATH']}")
    monkeypatch.setenv("AURIS_NO_PROGRESS", "1")
    monkeypatch.setattr(R, "_tool_available", lambda name: name == "aircrack-ng")
    t = TargetInfo(ssid="WIFI_TEST", bssid="AA:BB:CC:DD:EE:FF", channel=6,
                   encryption="WPA2", wps_enabled=False, oui="AABBCC",
                   signal_strength=-50)
    status, key, ktype = R._phase_psk_ssid_logic(t, str(run_dir))
    assert status == "cracked", status
    assert key == "claveDePrueba2024"
    assert "aircrack-ng" in (ktype or "")


def test_fallback_aircrack_ng_sin_clave_devuelve_exhausted(tmp_path, monkeypatch):
    import os as _os
    import auris.runner as R
    run_dir = tmp_path / "run2"
    run_dir.mkdir()
    (run_dir / "handshake-01.cap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    shim = tmp_path / "bin2"
    shim.mkdir()
    fake = shim / "aircrack-ng"
    fake.write_text("#!/bin/sh\necho 'Passphrase not in dictionary'\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim}:{_os.environ['PATH']}")
    monkeypatch.setenv("AURIS_NO_PROGRESS", "1")
    monkeypatch.setattr(R, "_tool_available", lambda name: name == "aircrack-ng")
    t = TargetInfo(ssid="WIFI_TEST", bssid="AA:BB:CC:DD:EE:FF", channel=6,
                   encryption="WPA2", wps_enabled=False, oui="AABBCC",
                   signal_strength=-50)
    status, key, _ = R._phase_psk_ssid_logic(t, str(run_dir))
    assert status == "exhausted"
    assert key is None


def test_pixie_cae_a_bully_si_no_hay_reaver(tmp_path, monkeypatch):
    """Sin reaver, el Pixie Dust debe intentarse con bully -d, no rendirse."""
    import os as _os
    import auris.runner as R
    shim = tmp_path / "binp"
    shim.mkdir()
    usado = shim / "argdump"
    fake = shim / "bully"
    fake.write_text("#!/bin/sh\necho \"$@\" > " + str(usado) + "\n"
                    "echo 'WPS pin: 12345670'\necho 'WPA PSK: claveViaBully'\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim}:{_os.environ['PATH']}")
    monkeypatch.setenv("AURIS_NO_PROGRESS", "1")
    monkeypatch.setattr(R, "_tool_available",
                        lambda name: name in ("bully", "pixiewps"))
    t = TargetInfo(ssid="WIFI_TEST", bssid="AA:BB:CC:DD:EE:FF", channel=6,
                   encryption="WPA2", wps_enabled=True, oui="AABBCC",
                   signal_strength=-50)
    status, key, ktype = R._phase_wps_pixie(t, "wlan0mon")
    assert status == "cracked", status
    assert "12345670" in (key or "")
    assert ktype == "WPS Pixie Dust"
    args = usado.read_text()
    assert "-d" in args and "AA:BB:CC:DD:EE:FF" in args.upper()


def test_pixie_sin_motor_no_crashea(tmp_path, monkeypatch):
    import auris.runner as R
    monkeypatch.setattr(R, "_tool_available", lambda name: False)
    monkeypatch.setenv("AURIS_NO_PROGRESS", "1")
    t = TargetInfo(ssid="WIFI_TEST", bssid="AA:BB:CC:DD:EE:FF", channel=6,
                   encryption="WPA2", wps_enabled=True, oui="AABBCC",
                   signal_strength=-50)
    assert R._phase_wps_pixie(t, "wlan0mon")[0] == "skipped"
