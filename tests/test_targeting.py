"""
Selección automática de objetivos (`run-all --auto`).

Heurística pura, sin radio: ranking, top-N y enriquecimiento Broadcom.
"""

import os
import sys

from typer.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from auris.targeting import affected_models, rank_targets, score_target, select_targets
from auris.cli import app


def _target(**overrides):
    base = {
        "bssid": "AA:BB:CC:DD:EE:01",
        "ssid": "TEST",
        "channel": 6,
        "encryption": "WPA2",
        "wps_enabled": False,
        "wps_locked": False,
        "oui": "000000",
        "signal_strength": -60,
        "brand": "Unknown",
        "clients": 0,
    }
    base.update(overrides)
    return base


def test_senal_fuerte_gana():
    fuerte = score_target(_target(signal_strength=-40))
    debil = score_target(_target(signal_strength=-85))
    assert fuerte.score > debil.score


def test_wps_abierto_gana_a_lockout_y_apagado():
    abierto = score_target(_target(wps_enabled=True, wps_locked=False))
    locked = score_target(_target(wps_enabled=True, wps_locked=True))
    apagado = score_target(_target(wps_enabled=False))
    assert abierto.score > locked.score > apagado.score
    assert any("WPS abierto" in reason for reason in abierto.reasons)


def test_wpa3_penaliza():
    wpa3 = score_target(_target(encryption="WPA3-SAE"))
    wpa2 = score_target(_target(encryption="WPA2"))
    assert wpa3.score < wpa2.score


def test_broadcom_suma_y_explica():
    askey = score_target(_target(brand="Askey"))
    generico = score_target(_target(brand="Unknown"))
    assert askey.score > generico.score
    assert any("Broadcom SDK" in reason for reason in askey.reasons)


def test_ranking_ordena_por_puntaje_y_bssid():
    targets = [
        _target(bssid="AA:BB:CC:DD:EE:03", signal_strength=-80),
        _target(bssid="AA:BB:CC:DD:EE:02", signal_strength=-40),
        _target(bssid="AA:BB:CC:DD:EE:01", signal_strength=-40),
    ]
    ranked = rank_targets(targets)
    assert [item.bssid for item in ranked] == [
        "AA:BB:CC:DD:EE:01",
        "AA:BB:CC:DD:EE:02",
        "AA:BB:CC:DD:EE:03",
    ]


def test_top_limita_el_ranking():
    targets = [
        _target(bssid="AA:BB:CC:DD:EE:01", signal_strength=-85),
        _target(bssid="AA:BB:CC:DD:EE:02", signal_strength=-40),
        _target(bssid="AA:BB:CC:DD:EE:03", signal_strength=-60),
    ]
    top1 = select_targets(targets, top=1)
    assert len(top1) == 1
    assert top1[0].bssid == "AA:BB:CC:DD:EE:02"
    assert len(select_targets(targets, top=0)) == 3


def test_affected_models_offline():
    assert any("TCG3000" in model for model in affected_models("Askey"))
    assert affected_models("NoExisteEstaMarca") == []


def test_cli_expone_auto_y_top():
    result = CliRunner().invoke(app, ["run-all", "--help"])
    assert result.exit_code == 0
    assert "--auto" in result.output
    assert "--top" in result.output
