"""
AURIS v2 — Verificación de wordlists offline.

Huella esperada de rockyou.txt (colección SecLists / weakpass):
  ~14.34M líneas · ~133 MB descomprimido · ~50.9 MB comprimido.
El chequeo rápido (tamaño) corre en `doctor`; el conteo profundo de líneas
vive en `auris verify-rockyou` porque 14M de líneas tardan ~20 s.
"""

import os
from typing import Dict, Optional

ROCKYOU_LINES_MIN = 14_000_000
ROCKYOU_LINES_MAX = 14_500_000
ROCKYOU_SIZE_MB_MIN = 100.0
ROCKYOU_SIZE_MB_MAX = 170.0

CANDIDATE_PATHS = [
    "/usr/share/wordlists/rockyou.txt",
    "offline_bundle/wordlists/rockyou.txt",
    "data/rockyou.txt",
]


def find_rockyou(project_dir: str, override: str = "") -> Optional[str]:
    """Primera ruta existente (override > estándar Kali > bundle > data)."""
    cands = ([override] if override else []) + [
        p if os.path.isabs(p) else os.path.join(project_dir, p)
        for p in ["/usr/share/wordlists/rockyou.txt",
                  "offline_bundle/wordlists/rockyou.txt",
                  "data/rockyou.txt"]
    ]
    for p in cands:
        if p and os.path.isfile(p):
            return p
    return None


def quick_check(path: str) -> Dict[str, str]:
    """Chequeo rápido por tamaño. Nunca cuenta líneas."""
    try:
        size_mb = os.path.getsize(path) / (1024 * 1024)
    except OSError:
        return {"status": "missing", "msg": f"no existe: {path}"}
    if path.endswith(".gz"):
        return {"status": "compressed",
                "msg": f"comprimida ({size_mb:.1f} MB) — descomprimir: gunzip -k {path}"}
    if ROCKYOU_SIZE_MB_MIN <= size_mb <= ROCKYOU_SIZE_MB_MAX:
        return {"status": "ok",
                "msg": f"{path} ({size_mb:.1f} MB, dentro de huella 100–170 MB) — confirma con `auris verify-rockyou`"}
    if size_mb < ROCKYOU_SIZE_MB_MIN:
        return {"status": "incomplete",
                "msg": f"{path} ({size_mb:.1f} MB) bajo huella mínima 100 MB — probablemente truncada"}
    return {"status": "suspicious",
            "msg": f"{path} ({size_mb:.1f} MB) sobre huella máxima 170 MB — verificar origen"}


def deep_count(path: str) -> Dict[str, str]:
    """Conteo real de líneas (lento, ~20 s). Solo .txt descomprimido."""
    if path.endswith(".gz"):
        return {"status": "compressed", "lines": 0,
                "msg": "descomprime primero: gunzip -k rockyou.txt.gz"}
    n = 0
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                n += chunk.count(b"\n")
    except OSError as e:
        return {"status": "error", "lines": 0, "msg": str(e)}
    if ROCKYOU_LINES_MIN <= n <= ROCKYOU_LINES_MAX:
        return {"status": "ok", "lines": n,
                "msg": f"{n:,} líneas — huella válida (≈14.34M weakpass/SecLists)"}
    return {"status": "mismatch", "lines": n,
            "msg": f"{n:,} líneas fuera de rango 14.0–14.5M — no es la rockyou canónica"}
