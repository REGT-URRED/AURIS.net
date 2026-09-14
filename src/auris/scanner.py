"""
AURIS v2 — scanner.py
Escaneo real de redes WiFi en el aire usando las herramientas disponibles.

Orden de preferencia:
  1. hcxdumptool   (Kali/Parrot — el más preciso para PMKID/WPS)
  2. wash          (detección específica de WPS)
  3. airodump-ng   (universal, parte de aircrack-ng)

Todos retornan la misma estructura normalizada de targets.
"""

import os
import csv
import time
import shutil
import subprocess
import tempfile
import threading
from typing import List, Dict, Any, Optional, Callable
from .terminal import console, spinner


# ── Estructura de target normalizada ─────────────────────────────────────────
def _empty_target() -> Dict[str, Any]:
    return {
        "bssid": "",
        "ssid": "",
        "channel": 0,
        "encryption": "WPA2",
        "wps_enabled": False,
        "wps_version": None,
        "wps_locked": False,
        "wpa3_supported": False,
        "dpp_supported": False,
        "oui": "",
        "signal_strength": 0,
        "brand": "?",
        "clients": 0,
        "beacons": 0,
        "data_frames": 0,
    }


def _extract_oui(bssid: str) -> str:
    return bssid.replace(":", "")[:6].upper()


def _safe_int(value: str, default: int = 0) -> int:
    """int() que nunca crashea ante CSV corrupto (canal/señal basura)."""
    try:
        return int(str(value).strip() or default)
    except (ValueError, TypeError):
        return default


def _detect_brand_from_oui(oui: str) -> str:
    """Mapa básico OUI → marca. Se expande con la BD de vendors."""
    OUI_MAP = {
        "001CDF": "Askey", "001F9F": "Askey", "ACCC8A": "Askey",
        "74DA88": "Edimax", "D4CA6D": "TP-Link", "50C7BF": "TP-Link",
        "4846FB": "Huawei", "00E0FC": "Huawei", "C83A35": "Tenda",
        "00265A": "Gemtek", "001174": "Gemtek", "001E10": "Arcadyan",
        "2CB05D": "Sagemcom", "00237D": "Sagemcom", "001F1F": "Zyxel",
    }
    return OUI_MAP.get(oui[:6].upper(), "?")


def _detect_encryption(cipher_str: str) -> str:
    """Normaliza la cadena de cifrado de airodump a un valor limpio."""
    c = cipher_str.upper().strip()
    if "WPA3" in c or "SAE" in c:
        return "WPA3"
    if "WPA2" in c:
        return "WPA2"
    if "WPA" in c:
        return "WPA"
    if "WEP" in c:
        return "WEP"
    if "OPN" in c or "OPEN" in c or c == "":
        return "Open"
    return c


# ── Método 1: airodump-ng ─────────────────────────────────────────────────────

def _scan_airodump(iface: str, duration: int,
                   on_progress: Optional[Callable] = None) -> List[Dict[str, Any]]:
    """
    Escanea con airodump-ng y parsea el CSV de salida.
    """
    if not shutil.which("airodump-ng"):
        return []

    targets = []
    with tempfile.TemporaryDirectory() as tmpdir:
        output_prefix = os.path.join(tmpdir, "airodump")
        cmd = [
            "airodump-ng",
            "--output-format", "csv",
            "--write", output_prefix,
            "--write-interval", "5",
            iface,
        ]

        console.print(f"  [dim]airodump-ng en {iface} ({duration}s)...[/dim]")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        from .terminal import live_task

        # Barra de carga minimalista mientras airodump corre
        with live_task(f"Escaneando redes · {iface}", duration) as tick:
            elapsed = 0
            while elapsed < duration and proc.poll() is None:
                time.sleep(1)
                elapsed += 1
                tick(1)
                if on_progress:
                    on_progress(elapsed, duration)

        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

        # Parsear el CSV generado por airodump
        csv_file = f"{output_prefix}-01.csv"
        if not os.path.isfile(csv_file):
            return []

        with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # El CSV de airodump tiene dos secciones separadas por línea en blanco
        sections = content.split("\n\n")
        if not sections:
            return []

        ap_section = sections[0]
        lines = ap_section.splitlines()

        for line in lines[2:]:  # Skip header
            if not line.strip():
                continue
            try:
                parts = [p.strip() for p in next(csv.reader([line]))]
            except Exception:
                continue
            if len(parts) < 13:
                continue
            bssid = parts[0]
            if not bssid or len(bssid) < 17:
                continue

            oui = _extract_oui(bssid)
            cipher = parts[5] + " " + parts[7]  # Privacy + Cipher
            ssid = parts[13] if len(parts) > 13 else ""

            t = _empty_target()
            t.update({
                "bssid":           bssid,
                "ssid":            ssid or f"[Hidden-{bssid[-5:]}]",
                "channel":         _safe_int(parts[3]),
                "encryption":      _detect_encryption(cipher),
                "oui":             oui,
                "signal_strength": _safe_int(parts[8]),
                "beacons":         _safe_int(parts[9]),
                "data_frames":     _safe_int(parts[10]),
                "brand":           _detect_brand_from_oui(oui),
                "wpa3_supported":  "WPA3" in cipher.upper() or "SAE" in cipher.upper(),
            })
            targets.append(t)

    return targets


# ── Método 2: wash (detección WPS) ────────────────────────────────────────────

def _scan_wash(iface: str, duration: int) -> List[Dict[str, Any]]:
    """
    Escanea con wash para detectar APs con WPS habilitado.
    Retorna solo APs con WPS.
    """
    if not shutil.which("wash"):
        return []

    targets = []
    console.print(f"  [dim]wash -i {iface} --scan ({duration}s)...[/dim]")

    try:
        proc = subprocess.Popen(
            ["wash", "-i", iface, "--scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        try:
            stdout, _ = proc.communicate(timeout=duration)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                stdout, _ = proc.communicate(timeout=3)
            except Exception:
                stdout = ""
        lines_collected = [l for l in (stdout or "").splitlines() if l.strip()]

        # Parsear salida de wash:
        # BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
        for line in lines_collected:
            parts = line.split()
            if len(parts) < 7 or ":" not in parts[0]:
                continue
            bssid = parts[0]
            oui = _extract_oui(bssid)
            locked_str = parts[4].lower() if len(parts) > 4 else "no"

            t = _empty_target()
            t.update({
                "bssid":       bssid,
                "ssid":        " ".join(parts[6:]) if len(parts) > 6 else f"[Hidden-{bssid[-5:]}]",
                "channel":     int(parts[1]) if parts[1].isdigit() else 6,
                "signal_strength": int(parts[2]) if parts[2].lstrip("-").isdigit() else -70,
                "wps_enabled": True,
                "wps_version": parts[3] if len(parts) > 3 else "?",
                "wps_locked":  locked_str in ("yes", "true", "locked", "1"),
                "oui":         oui,
                "brand":       _detect_brand_from_oui(oui),
                "encryption":  "WPA2",
            })
            targets.append(t)

    except Exception as e:
        console.print(f"  [yellow][WARN] wash: {e}[/yellow]")

    return targets


# ── Función pública principal ─────────────────────────────────────────────────

def scan_networks(iface: str, duration: int = 60,
                  on_progress: Optional[Callable] = None) -> List[Dict[str, Any]]:
    """
    Escanea el aire y retorna una lista de redes detectadas.

    Estrategia:
      - Corre airodump-ng (visión general de todas las redes)
      - Corre wash en paralelo (enriquece con datos WPS exactos)
      - Fusiona ambos resultados en una sola lista dedupada por BSSID

    Si ninguna herramienta está disponible, retorna datos de laboratorio demo.
    """
    results: Dict[str, Dict[str, Any]] = {}  # bssid → target

    airodump_available = shutil.which("airodump-ng") is not None
    wash_available     = shutil.which("wash") is not None

    if not airodump_available and not wash_available:
        console.print("  [yellow]airodump-ng y wash no disponibles — modo demo[/yellow]")
        return _demo_targets()

    # Correr airodump-ng como scan principal
    if airodump_available:
        airs = _scan_airodump(iface, duration, on_progress)
        for t in airs:
            results[t["bssid"]] = t

    # Correr wash para enriquecer con datos WPS precisos
    if wash_available:
        wash_duration = min(duration, 30)
        wash_targets = _scan_wash(iface, wash_duration)
        for wt in wash_targets:
            bssid = wt["bssid"]
            if bssid in results:
                # Enriquecer: wash sabe mejor sobre WPS
                results[bssid]["wps_enabled"] = True
                results[bssid]["wps_version"] = wt["wps_version"]
                results[bssid]["wps_locked"]  = wt["wps_locked"]
                if not results[bssid]["ssid"]:
                    results[bssid]["ssid"] = wt["ssid"]
            else:
                results[bssid] = wt

    targets = list(results.values())

    if not targets:
        console.print("  [yellow]No se detectaron redes. Verifica que la interfaz está en modo monitor.[/yellow]")

    return targets


def _demo_targets() -> List[Dict[str, Any]]:
    """Datos de laboratorio para pruebas sin hardware real (flota de 5 routers)."""
    return [
        {
            "bssid": "00:1C:DF:AA:BB:CC", "ssid": "MOVISTAR_AB12",
            "channel": 6, "encryption": "WPA2",
            "wps_enabled": True, "wps_version": "1.0", "wps_locked": False,
            "wpa3_supported": False, "dpp_supported": False,
            "oui": "001CDF", "signal_strength": -55, "brand": "Askey",
            "clients": 2, "beacons": 120, "data_frames": 450,
        },
        {
            "bssid": "28:6C:07:11:22:33", "ssid": "MOVISTAR_PLUS_2",
            "channel": 1, "encryption": "WPA2",
            "wps_enabled": True, "wps_version": "2.0", "wps_locked": True,
            "wpa3_supported": False, "dpp_supported": False,
            "oui": "286C07", "signal_strength": -62, "brand": "MitraStar",
            "clients": 1, "beacons": 60, "data_frames": 80,
        },
        {
            "bssid": "9C:C7:A6:44:55:66", "ssid": "HUAWEI-5GHT",
            "channel": 11, "encryption": "WPA2",
            "wps_enabled": True, "wps_version": "2.0", "wps_locked": False,
            "wpa3_supported": False, "dpp_supported": False,
            "oui": "9CC7A6", "signal_strength": -58, "brand": "Huawei",
            "clients": 3, "beacons": 200, "data_frames": 900,
        },
        {
            "bssid": "D4:CA:6D:DE:AD:BE", "ssid": "TP-Link_F845",
            "channel": 3, "encryption": "WPA2",
            "wps_enabled": False, "wps_version": None, "wps_locked": False,
            "wpa3_supported": True, "dpp_supported": True,
            "oui": "D4CA6D", "signal_strength": -48, "brand": "TP-Link",
            "clients": 3, "beacons": 240, "data_frames": 1200,
        },
        {
            "bssid": "02:0F:B5:77:88:99", "ssid": "WLAN_9XQ2",
            "channel": 9, "encryption": "WPA",
            "wps_enabled": True, "wps_version": "1.0", "wps_locked": False,
            "wpa3_supported": False, "dpp_supported": False,
            "oui": "020FB5", "signal_strength": -71, "brand": "Unknown",
            "clients": 0, "beacons": 40, "data_frames": 10,
        },
    ]
