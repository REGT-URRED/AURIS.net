"""
AURIS — adapters/tool_runner.py
Único punto de ejecución de subprocesos externos.

Por qué existe este módulo
──────────────────────────
En runner.py original, _run_tool() y _run_tool_plain() estaban definidos
en el mismo archivo que las fases, el orquestador y la lógica de generación
de candidatos. Eso significa que un cambio en el manejo de timeouts afectaba
a todo. Ahora existe UN SOLO lugar donde se ejecutan subprocesos externos.

Todas las fases (phases/*.py) y adaptadores (adapters/*.py) importan de aquí.
Nadie más llama a subprocess directamente.

Contrato
────────
ToolResult.returncode  : código de salida del proceso (-1 si timeout/error)
ToolResult.stdout      : salida estándar decodificada
ToolResult.stderr      : salida de error decodificada
ToolResult.timed_out   : True si el proceso fue terminado por timeout
ToolResult.elapsed_sec : tiempo real de ejecución
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ToolResult:
    """Resultado normalizado de la ejecución de una herramienta externa."""
    returncode:  int
    stdout:      str
    stderr:      str
    timed_out:   bool
    elapsed_sec: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def combined_output(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()


def tool_available(name: str) -> bool:
    """Verifica si una herramienta está en el PATH del sistema."""
    return shutil.which(name) is not None


def run_tool(
    cmd: List[str],
    timeout: int,
    desc: Optional[str] = None,
    progress_callback=None,
) -> ToolResult:
    """
    Ejecuta un subproceso con timeout estricto.

    Parámetros
    ──────────
    cmd              : Lista de argumentos (sin shell=True).
    timeout          : Segundos máximos. Al expirar, el proceso se termina.
    desc             : Descripción para barra de progreso (None = sin barra).
    progress_callback: Función opcional (elapsed, total) para actualización de UI.

    Garantías
    ─────────
    - NUNCA lanza excepciones al llamante: los errores van en ToolResult.
    - SIEMPRE termina al expirar el timeout.
    - El returncode es -1 en cualquier condición de error/timeout.
    """
    t0 = time.time()

    if not cmd:
        return ToolResult(returncode=-1, stdout="", stderr="empty command",
                          timed_out=False, elapsed_sec=0.0)

    # Si hay barra de progreso, correr el proceso en hilo separado
    if desc and not os.environ.get("AURIS_NO_PROGRESS"):
        return _run_with_progress(cmd, timeout, desc, progress_callback)

    return _run_plain(cmd, timeout, t0)


def _run_plain(cmd: List[str], timeout: int, t0: float) -> ToolResult:
    """Ejecución directa sin UI de progreso."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return ToolResult(
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            timed_out=False,
            elapsed_sec=round(time.time() - t0, 2),
        )
    except subprocess.TimeoutExpired:
        return ToolResult(returncode=-1, stdout="", stderr="timeout",
                          timed_out=True, elapsed_sec=timeout)
    except FileNotFoundError:
        return ToolResult(returncode=-1, stdout="", stderr=f"not found: {cmd[0]}",
                          timed_out=False, elapsed_sec=round(time.time() - t0, 2))
    except Exception as exc:
        return ToolResult(returncode=-1, stdout="", stderr=str(exc),
                          timed_out=False, elapsed_sec=round(time.time() - t0, 2))


def _run_with_progress(
    cmd: List[str], timeout: int,
    desc: str, progress_callback=None,
) -> ToolResult:
    """Ejecución con progreso en hilo secundario."""
    box: dict = {}
    t0 = time.time()

    def _worker():
        box["result"] = _run_plain(cmd, timeout, t0)

    worker = threading.Thread(target=_worker, daemon=True)
    worker.start()

    elapsed = 0.0
    interval = 0.5
    while worker.is_alive() and elapsed < timeout:
        time.sleep(interval)
        elapsed += interval
        if progress_callback:
            progress_callback(elapsed, timeout)

    worker.join(timeout=3)
    result = box.get("result", ToolResult(
        returncode=-1, stdout="", stderr="thread_timeout",
        timed_out=True, elapsed_sec=timeout,
    ))
    return result
