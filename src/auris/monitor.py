"""
AURIS v2 — monitor.py
Gestión del modo monitor de la interfaz WiFi.

Maneja automáticamente la transición:
  wlan0 → wlan0mon  (activar)
  wlan0mon → wlan0  (restaurar)

Soporta dos métodos según lo que esté disponible:
  1. airmon-ng  (preferido, disponible en Kali/Parrot)
  2. iw + ip    (fallback manual, funciona en cualquier Linux)
"""

import subprocess
import shutil
import time
import re
from typing import Optional, Tuple
from .terminal import console


def _run(cmd: list, timeout: int = 10) -> Tuple[int, str, str]:
    """Ejecuta un comando y retorna (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", f"command not found: {cmd[0]}"


def get_active_interface_name(iface: str) -> str:
    """
    Retorna el nombre real de la interfaz después de poner en modo monitor.
    airmon-ng puede renombrarla a wlan0mon, phy0mon, etc.
    """
    # Buscar en iw dev si ya existe una interfaz mon derivada
    _, out, _ = _run(["iw", "dev"])
    for line in out.splitlines():
        line = line.strip()
        if "Interface" in line:
            name = line.split()[-1]
            # Buscar si ya está en modo monitor
            _, info, _ = _run(["iw", name, "info"])
            if "monitor" in info.lower():
                return name
    return iface


def kill_interfering_processes() -> int:
    """
    Mata procesos que pueden interferir con el modo monitor
    (NetworkManager, wpa_supplicant, dhclient).
    Equivalente a: airmon-ng check kill
    Retorna el número de procesos terminados.
    """
    interfering = ["NetworkManager", "wpa_supplicant", "dhclient", "dhcpcd"]
    killed = 0
    for proc in interfering:
        rc, _, _ = _run(["pkill", "-f", proc])
        if rc == 0:
            console.print(f"  [dim]Proceso detenido: {proc}[/dim]")
            killed += 1
    if killed > 0:
        time.sleep(1)  # Esperar que los procesos terminen
    return killed


def enable_monitor_mode(iface: str, kill_procs: bool = True) -> Optional[str]:
    """
    Pone la interfaz WiFi en modo monitor.
    Retorna el nombre de la interfaz en modo monitor (ej. 'wlan0mon'),
    o None si falla.

    Método 1: airmon-ng start <iface>
    Método 2: ip + iw (fallback)
    """
    console.print(f"  [cyan]Activando modo monitor en [bold]{iface}[/bold]...[/cyan]")

    # Verificar que la interfaz existe
    _, out, _ = _run(["iw", "dev"])
    if iface not in out:
        console.print(f"  [yellow][WARN] Interfaz {iface} no encontrada. Interfaces disponibles:[/yellow]")
        for line in out.splitlines():
            if "Interface" in line:
                console.print(f"    [dim]{line.strip()}[/dim]")
        return None

    # Matar procesos interferentes
    if kill_procs:
        killed = kill_interfering_processes()
        if killed:
            console.print(f"  [dim]Detenidos {killed} procesos interferentes.[/dim]")

    # ── Método 1: airmon-ng ────────────────────────────────────────────────────
    if shutil.which("airmon-ng"):
        console.print(f"  [dim]Usando airmon-ng...[/dim]")
        rc, out, err = _run(["airmon-ng", "start", iface], timeout=15)

        if rc == 0 or "monitor mode" in out.lower() or "monitor mode" in err.lower():
            # Buscar el nombre de la interfaz mon en la salida
            mon_match = re.search(r"(wlan\d+mon|phy\d+mon|mon\d+)", out + err)
            mon_iface = mon_match.group(1) if mon_match else f"{iface}mon"

            # Verificar con iw dev que existe y está en modo monitor
            _, iw_out, _ = _run(["iw", "dev"])
            if mon_iface in iw_out:
                console.print(f"  [green][OK] Modo monitor activo: [bold]{mon_iface}[/bold][/green]")
                return mon_iface
            else:
                # airmon-ng puede no renombrar en kernels modernos
                _, info, _ = _run(["iw", iface, "info"])
                if "monitor" in info.lower():
                    console.print(f"  [green][OK] Modo monitor activo: [bold]{iface}[/bold] (sin renombrado)[/green]")
                    return iface
        console.print(f"  [yellow]airmon-ng falló (rc={rc}). Intentando método manual...[/yellow]")

    # ── Método 2: ip + iw (fallback) ──────────────────────────────────────────
    console.print(f"  [dim]Usando ip + iw (método manual)...[/dim]")

    steps = [
        (["ip", "link", "set", iface, "down"],           "Bajar interfaz"),
        (["iw", iface, "set", "monitor", "control"],     "Configurar modo monitor"),
        (["ip", "link", "set", iface, "up"],             "Subir interfaz"),
    ]

    for cmd, desc in steps:
        rc, _, err = _run(cmd, timeout=8)
        if rc != 0:
            console.print(f"  [red][ERR] {desc}: {err.strip()}[/red]")
            return None
        console.print(f"  [dim]{desc}: OK[/dim]")

    # Verificar que el modo monitor está activo
    _, info, _ = _run(["iw", iface, "info"])
    if "monitor" in info.lower():
        console.print(f"  [green][OK] Modo monitor activo: [bold]{iface}[/bold][/green]")
        return iface
    else:
        console.print(f"  [red][ERR] No se pudo confirmar modo monitor en {iface}[/red]")
        return None


def disable_monitor_mode(mon_iface: str, original_iface: Optional[str] = None) -> bool:
    """
    Restaura la interfaz al modo managed (normal).
    Retorna True si fue exitoso.
    """
    console.print(f"  [dim]Restaurando {mon_iface} a modo managed...[/dim]")

    # ── Método 1: airmon-ng ────────────────────────────────────────────────────
    if shutil.which("airmon-ng"):
        rc, out, _ = _run(["airmon-ng", "stop", mon_iface], timeout=15)
        if rc == 0 or "managed mode" in out.lower():
            console.print(f"  [green][OK] Interfaz restaurada a modo managed.[/green]")
            # Reiniciar NetworkManager si existe
            if shutil.which("systemctl"):
                _run(["systemctl", "restart", "NetworkManager"], timeout=10)
            return True

    # ── Método 2: ip + iw (fallback) ──────────────────────────────────────────
    iface = original_iface or mon_iface.replace("mon", "")
    steps = [
        (["ip", "link", "set", mon_iface, "down"],
         f"Bajar {mon_iface}"),
        (["iw", mon_iface, "set", "type", "managed"],
         "Configurar modo managed"),
        (["ip", "link", "set", mon_iface, "up"],
         f"Subir {mon_iface}"),
    ]
    for cmd, desc in steps:
        rc, _, err = _run(cmd, timeout=8)
        if rc != 0:
            console.print(f"  [yellow][WARN] {desc}: {err.strip()}[/yellow]")

    # Reiniciar NetworkManager
    if shutil.which("systemctl"):
        _run(["systemctl", "restart", "NetworkManager"], timeout=10)

    console.print(f"  [green][OK] Interfaz restaurada.[/green]")
    return True


def set_channel(iface: str, channel: int) -> bool:
    """Fija el canal de la interfaz en modo monitor."""
    rc, _, err = _run(["iw", "dev", iface, "set", "channel", str(channel)])
    if rc == 0:
        return True
    # Fallback: iwconfig
    if shutil.which("iwconfig"):
        rc, _, _ = _run(["iwconfig", iface, "channel", str(channel)])
        return rc == 0
    return False
