import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris.vendor_profiles import (
    resolve_brand, get_profile, intel_for, historic_coverage,
    render_vendor_section_md, HISTORIC_VULNS, ISP_TOKENS, VENDOR_PROFILES,
)


def test_offline_module_no_sockets():
    """El módulo de inteligencia debe ser 100% offline: sin sockets ni HTTP."""
    import auris.vendor_profiles as vp
    src = open(vp.__file__).read()
    for banned in ("import socket", "import requests", "urllib", "http.client"):
        assert banned not in src, f"módulo no-offline: usa {banned}"


def test_resolve_brand_oui_verified():
    assert resolve_brand("00:1C:DF", "X", "") == "Askey"
    assert resolve_brand("ac:cc:8a", "X", "") == "Askey"  # case-insensitive


def test_resolve_brand_ssid_fleet():
    assert resolve_brand("", "HUAWEI-5GHT", "") == "Huawei"
    assert resolve_brand("", "MOVISTAR_AB12", "") == "ISP Fleet (HGU)"
    assert resolve_brand("", "WLAN_9XQ2", "") == "ISP Fleet (Legacy)"
    assert resolve_brand("", "TP-Link_F845", "") == "TP-Link"
    assert resolve_brand("", "ZXC-random-99", "") == "Unknown"


def test_resolve_brand_prefers_scan():
    assert resolve_brand("", "WLAN_9XQ2", "Huawei") == "Huawei"


def test_historic_db_schema_complete():
    """Cada bug histórico debe traer causa, prueba AURIS y defensa."""
    assert len(HISTORIC_VULNS) >= 10
    for v in HISTORIC_VULNS:
        for field in ("id", "title", "year", "severity", "affected",
                      "cause", "auris", "fix", "detection"):
            assert v.get(field), f"{v.get('id')} sin campo {field}"
        assert v["detection"] in ("fingerprint", "active", "candidates")


def test_historic_db_has_lab_relevant_ids():
    ids = " ".join(v["id"] for v in HISTORIC_VULNS)
    for must in ("CVE-2017-17215", "CVE-2023-1389", "CVE-2014-8361",
                 "KRACK", "Pixie", "FragAttacks", "Kr00k", "Mirai", "dnsmasq"):
        assert must in ids, f"falta entrada histórica: {must}"


def test_intel_for_lab_fleet():
    intel = intel_for(ssid="MOVISTAR_AB12", bssid="00:1C:DF:AA:BB:CC", brand="Askey")
    assert intel["brand"] == "Askey"
    assert intel["is_hgu"] is True
    assert len(intel["historic"]) >= 5
    intel2 = intel_for(ssid="WLAN_9XQ2", bssid="02:0F:B5:77:88:99", brand="Unknown")
    assert intel2["is_legacy_fleet"] is True


def test_isp_tokens_feed_candidates():
    from auris.runner import generate_ssid_candidates
    lote1, _ = generate_ssid_candidates("MOVISTAR_AB12", "00:1C:DF:AA:BB:CC")
    joined = "\n".join(lote1).lower()
    assert "movistar" in joined  # tokens ISP presentes en el lote


def test_historic_coverage_mapping():
    cov = historic_coverage("cracked", "WPA2-PSK (Lógica SSID familia)")
    assert any("2010" in c for c in cov)
    cov2 = historic_coverage("class_confirmed", "WPS")
    assert any("OEM" in c for c in cov2)
    cov3 = historic_coverage("exhausted", None)
    assert any("KRACK" in c or "FragAttacks" in c for c in cov3)


def test_render_vendor_section_md():
    intel = intel_for(ssid="HUAWEI-5GHT", bssid="9C:C7:A6:44:55:66", brand="Huawei")
    result = {"ssid": "HUAWEI-5GHT", "bssid": "9C:C7:A6:44:55:66",
              "brand": "Huawei", "result": "exhausted", "key_type": None,
              "vendor_intel": intel}
    lines = render_vendor_section_md(result)
    text = "\n".join(lines)
    assert "Huawei" in text
    assert "CVE-2017-17215" in text  # deuda Huawei presente
    assert "cómo defenderse" in text.lower() or "Defensa exigida" in text


def test_lab_override_file(tmp_path):
    import json
    import auris.vendor_profiles as vp
    m = tmp_path / "vendor_map.json"
    m.write_text(json.dumps({"AA:BB:CC": "Huawei", "notabrand": "", "00:11:22": "  "}))
    loaded = vp._lab_overrides(str(m))
    assert loaded == {"AABBCC": "Huawei"}  # normaliza y descarta vacíos
    assert vp._lab_overrides(str(tmp_path / "nope.json")) == {}
    m.write_text("{no json")
    assert vp._lab_overrides(str(m)) == {}


def test_lab_override_priority(monkeypatch):
    import auris.vendor_profiles as vp
    monkeypatch.setattr(vp, "_VENDOR_MAP_CACHE", {"AABBCC": "Huawei"})
    assert vp.resolve_brand("AA:BB:CC", "", "") == "Huawei"  # gana al vacío/Unknown
    monkeypatch.setattr(vp, "_VENDOR_MAP_CACHE", {})
    assert vp.resolve_brand("00:1C:DF", "X", "") == "Askey"  # fallback intacto


def test_eol_kb_schema():
    from auris.vendor_profiles import EOL_KB
    assert set(EOL_KB) >= {"Askey", "MitraStar", "Huawei", "TP-Link",
                           "ISP Fleet (Legacy)", "Unknown"}
    for brand, kb in EOL_KB.items():
        assert kb["verdict"] in ("eol_confirmed", "needs_evidence"), brand
        assert kb["reasons"] and kb["required_evidence"] and kb["action"], brand


def test_eol_assessment_fleet():
    from auris.vendor_profiles import eol_assessment
    a = eol_assessment("Askey", "MOVISTAR_AB12")
    assert a["verdict"] == "eol_confirmed" and len(a["reasons"]) >= 2
    leg = eol_assessment("Unknown", "WLAN_9XQ2")
    assert leg["verdict"] == "eol_confirmed"  # flota legacy por SSID
    h = eol_assessment("Huawei", "HUAWEI-5GHT")
    assert h["verdict"] == "needs_evidence"  # honesto: sin versión no se afirma EOL
    assert any("37215" in e for e in h["required_evidence"])


def test_eol_phase_writes_evidence(tmp_path):
    from auris.models import TargetInfo, Profile
    from auris.runner import _phase_eol_governance
    t = TargetInfo(bssid="00:1C:DF:AA:BB:CC", ssid="MOVISTAR_AB12", channel=6,
                   encryption="WPA2", wps_enabled=True, oui="001CDF", signal_strength=-55)
    r = _phase_eol_governance(t, Profile(brand="Askey", pin_class="generic_pin_family",
                                         isp_locked_fw=True), str(tmp_path))
    assert r == "eol_confirmed"
    import json
    data = json.loads((tmp_path / "eol_assessment.json").read_text())
    assert data["brand"] == "Askey" and "action" in data


def test_render_eol_section():
    from auris.vendor_profiles import eol_assessment, render_eol_section_md
    res = {"eol_assessment": eol_assessment("MitraStar", "MOVISTAR_PLUS_2")}
    text = "\n".join(render_eol_section_md(res))
    assert "1234/1234" in text and "Evidencia requerida" in text
    assert render_eol_section_md({}) == []


def test_dpp_assessment_signals():
    from auris.vendor_profiles import dpp_assessment, render_dpp_section_md
    # TP-Link demo: WPA2 + SAE + DPP = transición
    a = dpp_assessment("TP-Link", "TP-Link_F845", wpa3_supported=True,
                       dpp_supported=True, wps_enabled=False, encryption="WPA2")
    assert a["verdict"] == "needs_evidence"
    assert any("transición" in s["signal"] for s in a["signals"])
    # WPS + DPP = concern
    b = dpp_assessment("Askey", "MOVISTAR_AB12", wpa3_supported=True,
                       dpp_supported=True, wps_enabled=True, encryption="WPA2")
    assert b["verdict"] == "concern"
    # WPA3 puro sin WPS ni DPP legacy = clear-ish (sin señales => clear solo si dpp)
    c = dpp_assessment("Unknown", "X", wpa3_supported=True,
                       dpp_supported=True, wps_enabled=False, encryption="WPA3")
    assert c["verdict"] == "clear"
    text = "\n".join(render_dpp_section_md({"dpp_assessment": a}))
    assert "transición" in text and "Defensa exigida" in text
    assert render_dpp_section_md({}) == []
    assert render_dpp_section_md({"dpp_assessment": None}) == []


def test_dpp_phase_writes_evidence(tmp_path):
    from auris.models import TargetInfo, Profile
    from auris.runner import _phase_audit_dpp
    t = TargetInfo(bssid="D4:CA:6D:DE:AD:BE", ssid="TP-Link_F845", channel=3,
                   encryption="WPA2", wps_enabled=False, oui="D4CA6D",
                   signal_strength=-48, wpa3_supported=True, dpp_supported=True)
    r = _phase_audit_dpp(t, Profile(brand="TP-Link"), str(tmp_path))
    assert r == "not_found"
    import json
    data = json.loads((tmp_path / "dpp_assessment.json").read_text())
    assert data["verdict"] == "needs_evidence"
