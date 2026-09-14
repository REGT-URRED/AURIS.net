"""
AURIS v2 — Persistencia de sesión y reanudación (--resume).

Un corte de luz a mitad de la flota ya no pierde el progreso: tras cada AP
completado se guarda el estado (atómico: tmp + rename) en data/sessions/.
Con --resume-last (o --resume-file) los BSSID completados se reincorporan
al informe final sin re-auditarse.
"""

import os
import json
import time
import glob
from typing import Dict, List, Optional

SESSIONS_SUBDIR = os.path.join("data", "sessions")


def sessions_dir(project_dir: str) -> str:
    d = os.path.join(project_dir, SESSIONS_SUBDIR)
    os.makedirs(d, exist_ok=True)
    return d


def _unique_path(base: str) -> str:
    """Si base existe (dos runs en el mismo segundo), sufija -1, -2..."""
    if not os.path.exists(base):
        return base
    root, ext = os.path.splitext(base)
    n = 1
    while os.path.exists(f"{root}-{n}{ext}"):
        n += 1
    return f"{root}-{n}{ext}"


def new_session(project_dir: str) -> Dict:
    """Crea data/sessions/sesion_<ts>.json y retorna {'id','path','completed'...}."""
    ts = int(time.time())
    path = _unique_path(os.path.join(sessions_dir(project_dir), f"sesion_{ts}.json"))
    state = {"session_id": os.path.splitext(os.path.basename(path))[0], "started_ts": ts,
             "completed": [], "completed_bssids": []}
    _atomic_write(path, state)
    return {"id": state["session_id"], "path": path, "state": state}


_WRITE_WARNED = False


def _atomic_write(path: str, state: Dict) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, path)
    except OSError as e:
        # FS read-only o disco lleno: la sesión en memoria sigue; se avisa una vez
        global _WRITE_WARNED
        try:
            if not _WRITE_WARNED:
                print(f"[WARN] No se pudo guardar sesión en {path} ({e}) — continúa solo en memoria")
                _WRITE_WARNED = True
        except Exception:
            pass
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except OSError:
            pass


def save_progress(session_path: str, result: Dict) -> None:
    """Añade el resultado de un AP (idempotente por BSSID)."""
    try:
        with open(session_path) as f:
            state = json.load(f)
    except (OSError, ValueError):
        return
    bssid = (result.get("bssid") or "").upper()
    replaced = False
    for i, r in enumerate(state.get("completed", [])):
        if (r.get("bssid") or "").upper() == bssid:
            state["completed"][i] = result
            replaced = True
            break
    if not replaced:
        state.setdefault("completed", []).append(result)
    state["completed_bssids"] = [r.get("bssid") for r in state["completed"]]
    try:
        _atomic_write(session_path, state)
    except OSError:
        pass


def load_session(path: str) -> Optional[Dict]:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def latest_session(project_dir: str) -> Optional[str]:
    cands = sorted(glob.glob(os.path.join(sessions_dir(project_dir), "sesion_*.json")))
    return cands[-1] if cands else None
