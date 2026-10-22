"""
Catálogo Broadcom, parser YARA y orquestación del fingerprint.

Todo offline: el runner del fingerprinter se inyecta, no se toca radio.
"""

import json
import os
import sys
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from auris import broadcom
from auris.broadcom import BroadcomError, fingerprint, lookup, parse_yara_output
from auris.cli import app

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_catalogo_afectados():
    matches = lookup("Askey")
    assert any(
        match.product == "TCG3000" and match.status == "affected" for match in matches
    )
    assert any(match.product == "RTF3505VW" for match in matches)


def test_catalogo_parcheados():
    matches = lookup("Sagemcom", "F5598T")
    assert matches and matches[0].status == "patched"


def test_catalogo_sin_coincidencias():
    assert lookup("NoExisteEstaMarca") == []


def test_catalogo_requiere_fabricante():
    with pytest.raises(BroadcomError):
        lookup("")


def test_catalogo_completo():
    rows = broadcom._catalog_rows()
    afectados = [row for row in rows if row["status"] == "affected"]
    parcheados = [row for row in rows if row["status"] == "patched"]
    assert len(afectados) >= 50
    assert len(parcheados) >= 4
    assert os.path.isfile(broadcom.YARA_RULES)


def test_parse_yara_output():
    salida = (
        "BRCM_WPS_Monitor_Generic_ELF /tmp/fw/usr/bin/wps_monitor\n"
        "VULN_BRCM_WPS_EAP_Fragment_Reassembly_ELF /tmp/fw/usr/bin/wpsmon\n"
        "basura sin ruta\n"
    )
    matches = parse_yara_output(salida)
    assert [match.rule for match in matches] == [
        "BRCM_WPS_Monitor_Generic_ELF",
        "VULN_BRCM_WPS_EAP_Fragment_Reassembly_ELF",
    ]


def _fake_runner(tmp_path, payload, returncode=0):
    result = tmp_path / "evidence" / "broadcom-fingerprint-test" / "result.json"
    result.parent.mkdir(parents=True)
    result.write_text(json.dumps(payload), encoding="utf-8")

    def runner(command, cwd):
        return SimpleNamespace(
            returncode=returncode,
            stdout=f"SSID: TEST\nJSON: {result}\nPCAP: {result.parent / 'traffic.pcap'}\n",
            stderr="",
        )

    return runner


def test_fingerprint_parsea_resultado(tmp_path, monkeypatch):
    monkeypatch.setattr(broadcom, "_interpreter_command", lambda args: ["fake", *args])
    payload = {
        "target": {
            "bssid": "20:0c:c8:16:76:dc",
            "channel": 1,
            "wps_identity": {"vendor": "Netgear", "model": "CG3100"},
        },
        "assessment": "LIKELY_VULNERABLE",
        "implementation": "BROADCOM_WPS_MONITOR",
        "target_health": "HEALTHY",
        "broadcom_sdk": {"evidence": ["broadcom_proprietary_ie"]},
        "warning": None,
    }
    run = fingerprint(
        "wlan0mon",
        "VOO-111317",
        cwd=str(tmp_path),
        runner=_fake_runner(tmp_path, payload),
    )
    assert run.assessment == "LIKELY_VULNERABLE"
    assert run.implementation == "BROADCOM_WPS_MONITOR"
    assert run.bssid == "20:0c:c8:16:76:dc"
    assert run.vendor == "Netgear"
    assert run.json_path and os.path.isfile(run.json_path)


def test_fingerprint_ssid_invalido(tmp_path):
    with pytest.raises(BroadcomError):
        fingerprint("wlan0mon", "x" * 33, cwd=str(tmp_path))


def test_fingerprint_falla_sin_json(tmp_path, monkeypatch):
    monkeypatch.setattr(broadcom, "_interpreter_command", lambda args: ["fake", *args])

    def runner(command, cwd):
        return SimpleNamespace(returncode=2, stdout="", stderr="no interface")

    with pytest.raises(BroadcomError):
        fingerprint("wlan0mon", "TEST", cwd=str(tmp_path), runner=runner)


def test_doctor_broadcom_assets():
    from auris.doctor import check_broadcom

    results = {result.name: result for result in check_broadcom(ROOT)}
    assert results["Broadcom intel"].status == "ok"
    assert results["yara"].status in {"ok", "warn"}
    assert results["uv"].status in {"ok", "warn"}


def test_cli_lookup_offline():
    result = CliRunner().invoke(app, ["broadcom", "--lookup", "Askey"])
    assert result.exit_code == 0, result.output
    assert "TCG3000" in result.output


def test_cli_sin_modo():
    result = CliRunner().invoke(app, ["broadcom"])
    assert result.exit_code == 1
    assert "Elegí un modo" in result.output


def test_cli_modos_excluyentes():
    result = CliRunner().invoke(
        app, ["broadcom", "--lookup", "Askey", "--firmware", "/tmp"]
    )
    assert result.exit_code == 1
    assert "mutuamente" in result.output
    assert "excluyentes" in result.output
