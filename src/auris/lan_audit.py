"""
AURIS v2 — Auditoría de superficie LAN (solo lectura, solo laboratorio).

Qué hace: conecta por TCP a los puertos de gestión del gateway del laboratorio
y lee banners/versiones para detectar la SUPERFICIE de zerodays históricos
(TR-064 Huawei, telnet Mirai, RomPager/Misfortune Cookie, TR-069 expuesto).

Qué NO hace (por diseño, ni siquiera en laboratorio):
  - No envía payloads ni intenta explotar nada.
  - No prueba credenciales (sin logins, sin fuerza bruta web/telnet).
  - Se niega a operar contra IPs públicas (solo RFC1918 + loopback para tests).

Requiere: --allow-lan explícito + lab_lan_gateway en el scope.
100% OFFLINE: stdlib únicamente (socket, ipaddress, ssl deshabilitado a propósito).
"""

import re
import socket
import ipaddress
from typing import Dict, List, Optional

CONNECT_TIMEOUT = 2.0
BANNER_BYTES = 1024

# Puerto, servicio, bug histórico que evidencia, cómo defenderse (resumen).
LAN_PROBES = [
    {"port": 37215, "service": "TR-064/UPnP",
     "finding": "CVE-2017-17215",
     "why": "Puerto del servicio TR-064 explotado por Mirai Okiru/Satori en Huawei HG532. "
            "Abierto = superficie del RCE presente; el parche se verifica por firmware, no por banner.",
     "fix": "Firmware post dic-2017; cerrar 37215 hacia WAN; gestión solo-LAN."},
    {"port": 23, "service": "Telnet",
     "finding": "Mirai (2016)",
     "why": "Telnet abierto con credenciales de fábrica = vector de reclutamiento Mirai. "
            "El banner por sí solo ya confirma exposición del servicio.",
     "fix": "Cerrar telnet; SSH con clave única por unidad; jamás gestión en WAN."},
    {"port": 7547, "service": "TR-069 CWMP",
     "finding": "Gestión remota ISP",
     "why": "Puerto de aprovisionamiento del operador. Debe existir hacia el ACS del ISP, "
            "nunca accesible para edición desde LAN salvo diseño documentado.",
     "fix": "ACL hacia el ACS; credenciales CWMP únicas por unidad; auditar firmware que lo sirve."},
    {"port": 80, "service": "HTTP admin", "http": True,
     "finding": "Misfortune Cookie / fingerprint",
     "why": "Cabecera Server y título revelan RomPager/modelo/firmware. RomPager < 4.34 = "
            "CVE-2014-9222/9223 (bypass + RCE).",
     "fix": "RomPager >= 4.34 vía firmware; HTTPS de gestión; cambio forzado de credencial."},
    {"port": 8080, "service": "HTTP admin alt", "http": True,
     "finding": "Misfortune Cookie / fingerprint",
     "why": "Puerto alternativo de administración con la misma superficie que el 80.",
     "fix": "Igual que puerto 80; no duplicar superficies de gestión."},
    {"port": 443, "service": "HTTPS admin", "http": True, "tls": True,
     "finding": "Fingerprint TLS/gestión",
     "why": "Versión TLS y certificado (autofirmado = gestión sin identidad verificable).",
     "fix": "TLS >= 1.2; HSTS en LAN; certificado válido o pinning documentado."},
]


def assert_lab_ip(gw_ip: str) -> ipaddress.IPv4Address:
    """Solo RFC1918/loopback. Todo lo demás = RoEError conceptual (ValueError)."""
    ip = ipaddress.ip_address((gw_ip or "").strip())
    if not (ip.is_private or ip.is_loopback):
        raise ValueError(f"IP fuera del laboratorio: {gw_ip} (solo RFC1918/loopback)")
    return ip


def _grab_banner(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> tuple:
    """(abierto, banner). Solo connect + recv pasivo, sin payload."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(BANNER_BYTES)
            except socket.timeout:
                data = b""
            return True, data.decode("utf-8", "replace").strip()[:300]
    except (OSError, socket.timeout):
        return False, ""


def _http_fingerprint(host: str, port: int, timeout: float = CONNECT_TIMEOUT) -> Dict[str, str]:
    """Un solo GET / por HTTP plano. Sin TLS (veredicto aparte)."""
    out = {"server": "", "title": "", "model_hint": ""}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            raw = b""
            while len(raw) < 8192:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                raw += chunk
        text = raw.decode("utf-8", "replace")
        head, _, body = text.partition("\r\n\r\n")
        m = re.search(r"(?im)^Server:\s*(.+)$", head)
        if m:
            out["server"] = m.group(1).strip()[:120]
        m = re.search(r"(?is)<title>\s*(.+?)\s*</title>", body)
        if m:
            out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        m = re.search(r"(?i)(HG\d{3,4}\w*|Archer\s+\w+|GPT-\d+\w*|RTF\d+\w*|TL-WR\w+|firmware[^<]{0,40}|RomPager/[\d.]+)",
                      head + " " + body)
        if m:
            out["model_hint"] = m.group(0).strip()[:120]
    except (OSError, socket.timeout):
        pass
    return out


def _rompager_verdict(server: str) -> Optional[str]:
    m = re.search(r"RomPager/(\d+)\.(\d+)", server or "")
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    if (major, minor) < (4, 34):
        return "VULNERABLE: RomPager < 4.34 → CVE-2014-9222/9223 (Misfortune Cookie)"
    return "RomPager >= 4.34 (parche Misfortune Cookie presente)"


def audit_lan_surface(gw_ip: str, timeout: float = CONNECT_TIMEOUT,
                      ports: Optional[List[int]] = None) -> Dict:
    """Barrido de superficie LAN. Retorna dict serializable a JSON."""
    assert_lab_ip(gw_ip)
    wanted = set(ports) if ports else None
    checks: List[Dict] = []
    for probe in LAN_PROBES:
        if wanted is not None and probe["port"] not in wanted:
            continue
        open_, banner = _grab_banner(gw_ip, probe["port"], timeout)
        entry = {"port": probe["port"], "service": probe["service"],
                 "open": open_, "banner": banner,
                 "finding": probe["finding"] if open_ else None,
                 "verdict": None, "fix": probe["fix"] if open_ else None}
        if open_ and probe.get("http") and not probe.get("tls"):
            fp = _http_fingerprint(gw_ip, probe["port"], timeout)
            entry.update(fp)
            rv = _rompager_verdict(fp["server"])
            if rv:
                entry["verdict"] = rv
            elif fp["server"] or fp["title"]:
                entry["verdict"] = "Superficie de gestión confirmada (revisar versión contra EOL)"
        elif open_ and probe.get("tls"):
            entry["verdict"] = "Puerto TLS abierto (verificar versión TLS y certificado en informe extendido)"
        elif open_:
            entry["verdict"] = f"Servicio expuesto: {probe['why'][:160]}"
        checks.append(entry)
    n_open = sum(1 for c in checks if c["open"])
    return {"host": gw_ip, "checks": checks,
            "summary": f"{n_open}/{len(checks)} servicios de gestión expuestos en LAN"}


def render_lan_section_md(result: Dict) -> List[str]:
    """Sección Markdown por dispositivo: superficie LAN + mapeo a zerodays."""
    lan = result.get("lan_surface")
    if not lan:
        return []
    lines = [
        "#### Superficie LAN del gateway (solo lectura, con consentimiento)",
        "",
        f"| Puerto | Servicio | Estado | Evidencia | Bug histórico / causa | Defensa exigida |",
        f"|---|---|---|---|---|---|",
    ]
    for c in lan.get("checks", []):
        state = "🟢 ABIERTO" if c["open"] else "⚪ cerrado"
        ev = " ".join(x for x in (c.get("banner"), c.get("server"), c.get("title"),
                                  c.get("model_hint"), c.get("verdict")) if x)[:180] or "—"
        lines.append(
            f"| {c['port']} | {c['service']} | {state} | {ev} | "
            f"{c.get('finding') or '—'} | {c.get('fix') or '—'} |"
        )
    lines += ["", f"**Resumen:** {lan.get('summary', '')}", ""]
    return lines
