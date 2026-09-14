"""
AURIS v2 — Reglas de enfrentamiento (RoE), persistencia de runs y cadena de custodia.

100% OFFLINE. Sin esta capa, el scope.yml era decorativo: time_window,
dry_run_default y forbid_mac_rotation existían pero nada los leía.
"""

import os
import hashlib
from datetime import date
from typing import Dict, List, Optional, Tuple


class RoEError(Exception):
    """Violación de reglas de enfrentamiento: la sesión NO debe continuar."""
    pass


PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))


# ─── Ventana temporal ─────────────────────────────────────────────────────────

def parse_time_window(tw: str) -> Optional[Tuple[date, date]]:
    """'2026-09-12/2026-12-15' → (date, date). None si ausente o malformado."""
    try:
        start_s, end_s = (tw or "").split("/")
        return (date.fromisoformat(start_s.strip()), date.fromisoformat(end_s.strip()))
    except (ValueError, AttributeError):
        return None


def check_time_window(scope: Dict, today: Optional[date] = None) -> Tuple[bool, str]:
    """¿Hoy está dentro de la ventana autorizada? Sin ventana = denegar."""
    tw = parse_time_window(scope.get("time_window", ""))
    if tw is None:
        return False, "scope sin time_window válida (formato 'AAAA-MM-DD/AAAA-MM-DD')"
    today = today or date.today()
    if not (tw[0] <= today <= tw[1]):
        return False, f"fuera de ventana autorizada {tw[0]}..{tw[1]} (hoy {today})"
    return True, f"ventana OK {tw[0]}..{tw[1]}"


# ─── Enforcement ─────────────────────────────────────────────────────────────

def read_iface_mac(iface: str) -> Optional[str]:
    """MAC actual de la interfaz (None si no existe). Solo lectura sysfs."""
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().lower()
    except OSError:
        return None


def enforce_scope(scope: Dict, dry_run: bool, force_roe: bool = False) -> Dict[str, Optional[str]]:
    """
    Puerta obligatoria antes de tocar el aire. Retorna contexto verificado
    {"iface_mac": ..., "window": ..., "window_bypassed": bool}.
    Lanza RoEError si la sesión no puede continuar.
    """
    ok, msg = check_time_window(scope)
    bypassed = False
    if not ok:
        if force_roe:
            # Reloj muerto en campo (CMOS) o ventana desfasada: solo con flag
            # explícito, aviso fuerte y registro en consola para auditoría.
            bypassed = True
            msg = f"VENTANA OMITIDA CON --force-roe ({msg}) — registrar justificación en el acta"
        else:
            raise RoEError(f"RoE: {msg}")

    if scope.get("dry_run_default", False) and not dry_run and not force_roe:
        raise RoEError("RoE: scope exige dry_run_default — usa --dry-run o --force-roe explícito")

    if not scope.get("allowed_bssids"):
        raise RoEError("RoE: scope sin allowed_bssids (lista blanca vacía)")

    iface = scope.get("iface_red_team", "wlan0")
    return {"iface_mac": read_iface_mac(iface), "window": msg, "window_bypassed": bypassed}


def verify_mac_stable(iface: str, mac_start: Optional[str]) -> Tuple[bool, str]:
    """forbid_mac_rotation: AURIS nunca rota MAC; verifica que nada externo lo hizo."""
    if mac_start is None:
        return True, "MAC inicial no legible (entorno sin interfaz) — sin verificación"
    now = read_iface_mac(iface)
    if now is None:
        return True, "interfaz ya no visible al cierre — sin verificación"
    if now != mac_start:
        return False, f"MAC cambió durante la sesión ({mac_start} → {now})"
    return True, f"MAC estable ({mac_start})"


# ─── Evidencia: paths absolutos + manifiesto SHA256 ───────────────────────────

def evidence_dir(run_id: str) -> str:
    """Directorio de evidencia siempre bajo el proyecto (nunca CWD-dependiente)."""
    d = os.path.join(PROJECT_DIR, "evidence", run_id)
    os.makedirs(d, exist_ok=True)
    return d


def write_evidence_manifest(run_dir: str) -> Dict[str, str]:
    """SHA256 de cada archivo de evidence/<id>/ → SHA256SUMS (+ dict)."""
    manifest: Dict[str, str] = {}
    try:
        entries = sorted(os.listdir(run_dir))
    except OSError:
        return manifest
    for name in entries:
        if name == "SHA256SUMS":
            continue
        path = os.path.join(run_dir, name)
        if not os.path.isfile(path):
            continue
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            manifest[name] = h.hexdigest()
        except OSError:
            continue
    try:
        with open(os.path.join(run_dir, "SHA256SUMS"), "w") as f:
            for name, digest in manifest.items():
                f.write(f"{digest}  {name}\n")
    except OSError:
        pass
    return manifest


def db_path_for(scope: Dict) -> str:
    """Ruta absoluta de la BD (db_path del scope es relativo al proyecto)."""
    p = scope.get("db_path", "data/auris.db") or "data/auris.db"
    if not os.path.isabs(p):
        p = os.path.join(PROJECT_DIR, p)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p
