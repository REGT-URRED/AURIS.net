import sys
import os
import socket
import threading

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris import lan_audit
from auris.lan_audit import (
    assert_lab_ip, audit_lan_surface, _rompager_verdict, render_lan_section_md,
)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _serve_banner(port, banner, ready):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(5)
    ready.set()
    try:
        conn, _ = srv.accept()
        conn.sendall(banner)
        conn.close()
    except socket.timeout:
        pass
    finally:
        srv.close()


def test_only_lab_ips():
    assert_lab_ip("192.168.1.1")
    assert_lab_ip("10.0.0.5")
    assert_lab_ip("127.0.0.1")
    with pytest.raises(ValueError):
        assert_lab_ip("8.8.8.8")
    with pytest.raises(ValueError):
        assert_lab_ip("1.1.1.1")
    with pytest.raises(Exception):
        assert_lab_ip("")


def test_tr064_surface_detected(monkeypatch):
    port = _free_port()
    ready = threading.Event()
    t = threading.Thread(target=_serve_banner, args=(port, b"TR-064 alive\r\n", ready), daemon=True)
    t.start()
    assert ready.wait(3)
    monkeypatch.setattr(lan_audit, "LAN_PROBES", [
        {"port": port, "service": "TR-064/UPnP", "finding": "CVE-2017-17215",
         "why": "test", "fix": "test-fix"},
    ])
    data = audit_lan_surface("127.0.0.1", timeout=3)
    assert data["checks"][0]["open"] is True
    assert "TR-064" in data["checks"][0]["banner"]
    assert data["checks"][0]["finding"] == "CVE-2017-17215"


def test_closed_port_fast():
    port = _free_port()  # libre = cerrado
    import time
    t0 = time.time()
    data = audit_lan_surface("127.0.0.1", timeout=1, ports=[port])
    assert time.time() - t0 < 5
    assert data["checks"] == [] or all(not c["open"] for c in data["checks"])


def test_rompager_verdicts():
    assert "VULNERABLE" in _rompager_verdict("Allegro-Software-RomPager/4.07")
    assert "presente" in _rompager_verdict("RomPager/4.34")
    assert _rompager_verdict("Apache/2.4") is None
    assert _rompager_verdict("") is None


def test_http_fingerprint_rompager(monkeypatch):
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        server_version = "RomPager/4.07"
        sys_version = ""

        def do_GET(self):
            body = b"<html><head><title>HUAWEI HG532e</title></head></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(lan_audit, "LAN_PROBES", [
        {"port": port, "service": "HTTP admin", "http": True,
         "finding": "Misfortune Cookie / fingerprint", "why": "t", "fix": "f"},
    ])
    data = audit_lan_surface("127.0.0.1", timeout=3)
    c = data["checks"][0]
    assert c["open"] is True
    assert "RomPager/4.07" in c["server"]
    assert "HUAWEI" in c["title"]
    assert c["verdict"] and "VULNERABLE" in c["verdict"]
    srv.server_close()


def test_render_section():
    result = {"lan_surface": {"host": "192.168.1.1", "summary": "1/2 test",
              "checks": [{"port": 37215, "service": "TR-064/UPnP", "open": True,
                           "banner": "", "finding": "CVE-2017-17215",
                           "verdict": "expuesto", "fix": "cerrar"}]}}
    lines = render_lan_section_md(result)
    text = "\n".join(lines)
    assert "37215" in text and "CVE-2017-17215" in text
    assert render_lan_section_md({}) == []
    assert render_lan_section_md({"lan_surface": None}) == []


def test_decision_path_has_lan_phase():
    from auris.models import TargetInfo, Profile
    from auris.decision_engine import decide_path
    t = TargetInfo(bssid="00:11:22:33:44:55", ssid="T", channel=1,
                   encryption="WPA2", wps_enabled=False, oui="000000",
                   signal_strength=-60)
    p = Profile(brand="Unknown")
    path = decide_path(t, p)
    assert "AUDIT_LAN_SURFACE" in path
    assert path.index("AUDIT_LAN_SURFACE") < path.index("RESILIENCE_TEST")


def test_module_offline_stdlib_only():
    import auris.lan_audit as m
    assert not hasattr(m, "requests")
    src = open(m.__file__).read()
    assert "import requests" not in src and "urllib.request" not in src
