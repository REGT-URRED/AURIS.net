import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris.report_writer import MITRE_ATTACK, TERMINAL_PHASES, FINDINGS_TEMPLATES
from auris.decision_engine import decide_path
from auris.models import TargetInfo, Profile


def _all_paths():
    combos = [
        dict(encryption='WPA2', wps_enabled=True, wps_version='1.0', wps_locked=False,
             wpa3_supported=False, dpp_supported=False),
        dict(encryption='WPA2', wps_enabled=True, wps_version='2.0', wps_locked=True,
             wpa3_supported=False, dpp_supported=False),
        dict(encryption='WPA2', wps_enabled=True, wps_version='2.0', wps_locked=False,
             wpa3_supported=False, dpp_supported=False),
        dict(encryption='WPA2', wps_enabled=False, wps_version=None, wps_locked=False,
             wpa3_supported=False, dpp_supported=False),
        dict(encryption='WPA2', wps_enabled=False, wps_version=None, wps_locked=False,
             wpa3_supported=True, dpp_supported=True),
        dict(encryption='WPA3', wps_enabled=False, wps_version=None, wps_locked=False,
             wpa3_supported=True, dpp_supported=True),
        dict(encryption='WEP', wps_enabled=False, wps_version=None, wps_locked=False,
             wpa3_supported=False, dpp_supported=False),
        dict(encryption='Open', wps_enabled=False, wps_version=None, wps_locked=False,
             wpa3_supported=False, dpp_supported=False),
        dict(encryption='WPA', wps_enabled=True, wps_version='1.0', wps_locked=False,
             wpa3_supported=False, dpp_supported=False),
    ]
    for c in combos:
        for brand, pin, lock in [('Askey', 'generic_pin_family', True),
                                 ('Unknown', 'unknown', False),
                                 ('Huawei', 'unknown', False)]:
            t = TargetInfo(bssid='00:11:22:33:44:55', ssid='T', channel=1,
                           oui='000000', signal_strength=-60, **c)
            yield decide_path(t, Profile(brand=brand, pin_class=pin, isp_locked_fw=lock))


def test_mitre_covers_every_phase():
    """Toda fase ejecutable tiene mapeo MITRE (candado anti-regresión)."""
    for path in _all_paths():
        for phase in path:
            if phase in TERMINAL_PHASES:
                continue
            assert phase in MITRE_ATTACK, f"fase sin mapeo MITRE: {phase}"


def test_mitre_ids_wellformed():
    for phase, m in MITRE_ATTACK.items():
        assert m["id"] and m["name"] and m["tactic"], phase
        assert " " not in m["id"], phase


def test_every_result_has_finding_template():
    results = ["cracked", "class_confirmed", "locked", "exhausted",
               "not_found", "eol_confirmed", "dry_run", "done",
               "skipped", "timeout", "error"]
    for r in results:
        f = FINDINGS_TEMPLATES.get(r, FINDINGS_TEMPLATES.get("done"))
        assert f and f.get("headline"), r


def test_json_report_schema(tmp_path):
    from auris.report_writer import generate_json_report
    import json
    results = [{
        "ssid": "T", "bssid": "00:11:22:33:44:55", "brand": "Askey",
        "encryption": "WPA2", "result": "exhausted", "path": ["CAPTURE_HANDSHAKE", "REPORT"],
        "phase_results": {}, "recovered_key": None, "key_type": None,
        "wids_alerts": 0, "wids_simulated": False, "elapsed_sec": 1,
        "run_id": "abc", "evidence_dir": "/x", "evidence_manifest": {},
        "lan_surface": None, "eol_assessment": None, "vendor_intel": None,
    }]
    out = str(tmp_path / "r.json")
    generate_json_report(results, {"institution": "Lab"}, out)
    d = json.load(open(out))
    for key in ("auris_version", "generated_at", "scope", "results", "summary"):
        assert key in d, f"JSON sin {key}"
    assert d["results"][0]["bssid"] == "00:11:22:33:44:55"
