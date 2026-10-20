"""
Inteligencia Broadcom vendorizada en research/broadcom-wps.

Verifica procedencia/licencia, que el script compile y que el subcomando
`auris broadcom` exista y valide argumentos. No toca radio ni red.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from typer.testing import CliRunner

from auris.cli import app

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENDOR = os.path.join(ROOT, "research", "broadcom-wps")
SCRIPT = os.path.join(VENDOR, "broadcom_fingerprint.py")
YARA = os.path.join(VENDOR, "broadcom_wps_monitor.yar")


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def test_archivos_vendorizados():
    for name in (
        "broadcom_fingerprint.py",
        "broadcom_wps_monitor.yar",
        "README.md",
        "LICENSE.md",
        "VENDOR.md",
    ):
        assert os.path.isfile(os.path.join(VENDOR, name)), f"falta {name}"


def test_licencia_y_procedencia():
    assert "MIT License" in _read(os.path.join(VENDOR, "LICENSE.md"))
    vendor = _read(os.path.join(VENDOR, "VENDOR.md"))
    assert "qkaiser/broadcom-wps" in vendor
    assert "0727296" in vendor


def test_reglas_yara_completas():
    rules = _read(YARA)
    for name in (
        "BRCM_WPS_Monitor_Generic_ELF",
        "BRCM_WPS_Monitor_HAL_Config_ELF",
        "VULN_BRCM_WPS_EAP_Fragment_Reassembly_ELF",
    ):
        assert f"rule {name}" in rules


def test_script_sintacticamente_valido():
    # compile() no importa scapy ni ejecuta nada.
    compile(_read(SCRIPT), SCRIPT, "exec")


def test_subcomando_registrado():
    names = {command.name for command in app.registered_commands}
    assert "broadcom" in names


def test_subcomando_exige_interface_y_ssid():
    result = CliRunner().invoke(app, ["broadcom"])
    assert result.exit_code == 2
    assert "Missing option" in result.output
