"""
AURIS v2 — monitor.py
Gestión del modo monitor de la interfaz WiFi.

Lecciones aprendidas en campo (Kali 2024.2, ath9k):
  - airmon-ng puede RENOMBRAR wlan0 → wlan0mon y aun así salir con rc!=0.
    El éxito NO se decide por el rc: se re-escanea `iw dev` y se adopta
    cualquier interfaz en modo monitor (find_monitor_iface).
  - hcxdumptool 6.3.1 prohíbe interfaces lógicas de airmon-ng y prefiere
    monitor creado por él (-m) o por iw/ip. Por eso el método manual
    (ip + iw, conserva el nombre) va PRIMERO y airmon-ng es el fallback.
  - Matar NetworkManager sin red de seguridad deja la máquina sin red:
    todo camino que toque NM termina con restart + verificación.

Transiciones:
  wlan0 → wlan0 (monitor, mismo nombre, método manual preferido)
  wlan0 → wlan0mon (airmon-ng, se adopta el renombre)
"""

import subprocess
import shutil
import time
import re
from typing import Optional, Tuple, List
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


def list_wireless_ifaces() -> List[str]:
    """Nombres de interfaces wireless vistas por `iw dev` (vacío = sin radio)."""
    _, out, _ = _run(["iw", "dev"])
    return [line.split()[-1] for line in out.splitlines()
            if line.strip().startswith("Interface")]


def is_monitor_mode(iface: str) -> bool:
    """True si `iw <iface> info` reporta tipo monitor."""
    _, info, _ = _run(["iw", iface, "info"])
    low = info.lower()
    return "type monitor" in low or "monitor" in low


def find_monitor_iface(prefer: Optional[str] = None) -> Optional[str]:
    """
    Re-escanea `iw dev` y adopta una interfaz ya en modo monitor.
    Orden de preferencia: el propio `prefer` si está en monitor,
    `<prefer>mon`, y luego cualquier otra en monitor.
    """
    monitors = [i for i in list_wireless_ifaces() if is_monitor_mode(i)]
    if not monitors:
        return None
    if prefer and prefer in monitors:
        return prefer
    if prefer and f"{prefer}mon" in monitors:
        return f"{prefer}mon"
    for m in monitors:
        if prefer and prefer.replace("wlan", "") in m:
            return m
    return monitors[0]


def get_active_interface_name(iface: str) -> str:
    """Compat: nombre real del monitor derivado de `iface`, o `iface`."""
    return find_monitor_iface(prefer=iface) or iface


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


def nm_is_running() -> bool:
    """True si NetworkManager está activo (systemctl o pgrep)."""
    if shutil.which("systemctl"):
        rc, out, _ = _run(["systemctl", "is-active", "NetworkManager"], timeout=8)
        if out.strip() == "active":
            return True
        if rc == 0:
            return True
    rc, _, _ = _run(["pgrep", "-x", "NetworkManager"])
    return rc == 0


def restart_network_manager(wait_sec: int = 20) -> bool:
    """
    Reinicia NetworkManager y VERIFICA que volvió (poll de `nmcli`).
    Retorna True solo si la red está gestionada de nuevo.
    """
    restarted = False
    if shutil.which("systemctl"):
        rc, _, _ = _run(["systemctl", "restart", "NetworkManager"], timeout=15)
        restarted = restarted or rc == 0
    elif shutil.which("service"):
        rc, _, _ = _run(["service", "NetworkManager", "restart"], timeout=15)
        restarted = restarted or rc == 0
    if shutil.which("nmcli"):
        _run(["nmcli", "radio", "wifi", "on"], timeout=8)
    for _ in range(max(wait_sec // 2, 1)):
        time.sleep(2)
        if nm_is_running():
            console.print("  [green][OK] NetworkManager restaurado y verificado.[/green]")
            return True
    console.print("  [red][ERR] NetworkManager NO volvió. Recuperación manual:[/red]")
    console.print("    [cyan]sudo systemctl restart NetworkManager && nmcli radio wifi on[/cyan]")
    console.print("    [cyan]sudo rfkill unblock wifi && ip link set wlan0 up[/cyan]")
    return restarted and False


def _enable_manual(iface: str) -> Optional[str]:
    """Método ip + iw: conserva el nombre (compatible hcxdumptool)."""
    if iface not in list_wireless_ifaces():
        return None
    steps = [
        (["ip", "link", "set", iface, "down"],           "Bajar interfaz"),
        (["iw", iface, "set", "monitor", "control"],     "Configurar modo monitor"),
        (["ip", "link", "set", iface, "up"],             "Subir interfaz"),
    ]
    for cmd, desc in steps:
        rc, _, err = _run(cmd, timeout=8)
        if rc != 0:
            console.print(f"  [yellow][WARN] {desc}: {err.strip()}[/yellow]")
            return None
        console.print(f"  [dim]{desc}: OK[/dim]")
    if is_monitor_mode(iface):
        return iface
    return None


def _enable_airmon(iface: str) -> Optional[str]:
    """
    airmon-ng como fallback. El rc NO decide el éxito (puede renombrar y
    salir rc!=0 igual): siempre se re-escanea y se adopta el monitor real.
    """
    if not shutil.which("airmon-ng"):
        return None
    rc, out, err = _run(["airmon-ng", "start", iface], timeout=20)
    # Pista del nuevo nombre en la salida (no vinculante)
    mon_match = re.search(r"(wlan\d+mon|phy\d+mon|mon\d+)", (out or "") + (err or ""))
    hint = mon_match.group(1) if mon_match else None
    found = find_monitor_iface(prefer=iface)
    if found:
        if rc != 0:
            console.print(f"  [dim]airmon-ng salió rc={rc} pero el monitor existe: {found} (renombre adoptado)[/dim]")
        return found
    if hint:
        console.print(f"  [yellow]airmon-ng mencionó {hint} pero no aparece en `iw dev`[/yellow]")
    else:
        console.print(f"  [yellow]airmon-ng no dejó monitor (rc={rc}).[/yellow]")
    return None


def enable_monitor_mode(iface: str, kill_procs: bool = True) -> Tuple[Optional[str], bool]:
    """
    Pone la interfaz WiFi en modo monitor.
    Retorna (mon_iface, nm_tocado):
      mon_iface  = nombre a usar (mismo nombre o renombre adoptado), None si falla.
      nm_tocado  = True si se detuvo NetworkManager (el llamador DEBE restaurar
                   con disable_monitor_mode aunque mon_iface sea None).

    Orden: manual ip+iw primero (compatible hcxdumptool), airmon-ng después.
    Si `iface` ya no existe pero hay un monitor previo (resto de otra sesión),
    se adopta directamente (auto-recuperación).
    """
    console.print(f"  [cyan]Activando modo monitor en [bold]{iface}[/bold]...[/cyan]")

    ifaces = list_wireless_ifaces()
    if iface not in ifaces:
        adopted = find_monitor_iface(prefer=iface)
        if adopted:
            console.print(f"  [yellow][WARN] {iface} no existe; adoptando monitor previo: {adopted}[/yellow]")
            return adopted, False
        console.print(f"  [yellow][WARN] Interfaz {iface} no encontrada. Interfaces:[/yellow]")
        for i in ifaces:
            console.print(f"    [dim]{i}[/dim]")
        if not ifaces:
            console.print("  [dim]Sin hardware wireless visible (¿VM sin USB passthrough?).[/dim]")
        return None, False

    # Matar procesos interferentes (con red de seguridad en disable)
    nm_touched = False
    if kill_procs:
        killed = kill_interfering_processes()
        nm_touched = killed > 0
        if killed:
            console.print(f"  [dim]Detenidos {killed} procesos interferentes (se restaurarán al final).[/dim]")

    # ── Método 1: ip + iw (preferido) ─────────────────────────────────────────
    console.print("  [dim]Método 1/2: ip + iw (conserva nombre, compatible hcxdumptool)...[/dim]")
    mon = _enable_manual(iface)
    if mon:
        console.print(f"  [green][OK] Modo monitor activo: [bold]{mon}[/bold][/green]")
        return mon, nm_touched

    # ── Método 2: airmon-ng (fallback, adopta renombre) ───────────────────────
    console.print("  [dim]Método 2/2: airmon-ng (adoptará renombre tipo wlan0mon)...[/dim]")
    mon = _enable_airmon(iface)
    if mon:
        console.print(f"  [green][OK] Modo monitor activo: [bold]{mon}[/bold][/green]")
        return mon, nm_touched

    # ── Fallo total: restaurar red AHORA (no esperar al finally) ─────────────
    console.print("  [red][ERR] No se pudo activar modo monitor. Restaurando red...[/red]")
    if nm_touched:
        restart_network_manager()
    _print_monitor_diagnostic(iface)
    return None, nm_touched


def _print_monitor_diagnostic(iface: str) -> None:
    """Guía de diagnóstico cuando el monitor falla con hardware presente."""
    console.print("  [bold yellow]Diagnóstico de radio:[/bold yellow]")
    console.print("    [dim]1.[/dim] [cyan]rfkill list[/cyan] → si bloqueado: [cyan]sudo rfkill unblock wifi[/cyan]")
    console.print("    [dim]2.[/dim] [cyan]iw dev[/cyan] → ¿aparece wlan0mon de otra sesión? [cyan]sudo airmon-ng stop wlan0mon[/cyan]")
    console.print("    [dim]3.[/dim] [cyan]iw list | grep -A8 monitor[/cyan] → el driver debe listar 'monitor'")
    console.print(f"    [dim]4.[/dim] Probar manual: [cyan]sudo ip link set {iface} down && sudo iw {iface} set monitor control && sudo ip link set {iface} up[/cyan]")


def disable_monitor_mode(mon_iface: str, original_iface: Optional[str] = None,
                         ensure_nm: bool = True) -> bool:
    """
    Restaura la interfaz a modo managed y NetworkManager (verificado).
    Idempotente: si nada cambió, no toca nada. Retorna True si la red quedó sana.
    """
    orig = original_iface or mon_iface.replace("mon", "")
    mon_exists = mon_iface in list_wireless_ifaces()
    orig_exists = orig in list_wireless_ifaces()
    mon_is_mon = mon_exists and is_monitor_mode(mon_iface)

    if not mon_exists and not orig_exists and not ensure_nm:
        console.print("  [dim]Nada que restaurar (sin interfaces wireless).[/dim]")
        return True

    if mon_is_mon or (mon_exists and mon_iface != orig):
        console.print(f"  [dim]Restaurando {mon_iface} a modo managed...[/dim]")
        # airmon-ng stop resucita el nombre original cuando hubo renombre
        if shutil.which("airmon-ng"):
            rc, out, _ = _run(["airmon-ng", "stop", mon_iface], timeout=15)
            if rc == 0 or "managed mode" in (out or "").lower():
                console.print("  [green][OK] Interfaz restaurada vía airmon-ng.[/green]")
            else:
                # Fallback manual sobre el mon
                for cmd, desc in (
                    (["ip", "link", "set", mon_iface, "down"], f"Bajar {mon_iface}"),
                    (["iw", mon_iface, "set", "type", "managed"], "Modo managed"),
                    (["ip", "link", "set", mon_iface, "up"], f"Subir {mon_iface}"),
                ):
                    rc2, _, err2 = _run(cmd, timeout=8)
                    if rc2 != 0:
                        console.print(f"  [yellow][WARN] {desc}: {(err2 or '').strip()}[/yellow]")
        elif mon_exists:
            for cmd, desc in (
                (["ip", "link", "set", mon_iface, "down"], f"Bajar {mon_iface}"),
                (["iw", mon_iface, "set", "type", "managed"], "Modo managed"),
                (["ip", "link", "set", mon_iface, "up"], f"Subir {mon_iface}"),
            ):
                rc2, _, err2 = _run(cmd, timeout=8)
                if rc2 != 0:
                    console.print(f"  [yellow][WARN] {desc}: {(err2 or '').strip()}[/yellow]")
    elif mon_exists and not mon_is_mon:
        console.print(f"  [dim]{mon_iface} ya está en modo managed — sin cambios de interfaz.[/dim]")

    nm_ok = True
    if ensure_nm:
        nm_ok = restart_network_manager()

    final = list_wireless_ifaces()
    ok = nm_ok and (not final or orig in final or mon_iface in final)
    if ok:
        console.print("  [green][OK] Red restaurada y verificada.[/green]")
    else:
        console.print("  [red][ERR] La red podría seguir caída — aplica recuperación manual (ver arriba).[/red]")
    return ok


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
