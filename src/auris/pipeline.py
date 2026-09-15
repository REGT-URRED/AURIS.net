"""
AURIS — pipeline.py
Orquestador limpio de fases. Reemplaza la "god function" run_single_target.

Por qué este módulo existe
──────────────────────────
El runner.py original tenía una función de 300 líneas (run_single_target) que:
  - Iniciaba el WIDS
  - Calculaba STRIDE
  - Decidía el path
  - Ejecutaba cada fase con un if/elif de 80 líneas
  - Sellaba la evidencia
  - Persistía en BD
  - Generaba el reporte

Eso es una "god function": hace todo, no puede testearse en partes, y cualquier
cambio tiene efectos laterales en todo lo demás.

El Pipeline resuelve esto con responsabilidad única:
  ÚNICA RESPONSABILIDAD: ejecutar una secuencia de fases en orden y retornar
  un PipelineResult. Nada más.

Separación de responsabilidades:
  - Qué fases ejecutar    → decision_engine.decide_path()
  - Cómo ejecutar c/fase  → phases/*.py (cada clase)
  - Cuándo parar          → StopCondition (dentro del pipeline)
  - Persistencia y reporte → runner.py (thin wrapper)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .phases.base import (
    PhaseResult, PhaseProtocol,
    STATUS_CRACKED, STATUS_CLASS_CONFIRMED, STATUS_EOL_CONFIRMED,
    STATUS_LOCKED, STATUS_SKIPPED, STATUS_DONE,
)


# ─── Resultado global del pipeline ────────────────────────────────────────────

@dataclass
class PipelineResult:
    """
    Resultado completo de la ejecución del pipeline para un target.

    No mezcla resultado con lógica — sólo datos.
    El thin runner.py consume esto para persistir y reportar.
    """
    target_ssid:    str
    target_bssid:   str
    path_planned:   List[str]
    phase_results:  Dict[str, PhaseResult] = field(default_factory=dict)
    final_status:   str = "pending"
    credential:     Optional[str] = None
    cred_type:      Optional[str] = None
    lockout_detected: bool = False
    elapsed_sec:    float = 0.0

    @property
    def phases_executed(self) -> int:
        return sum(1 for r in self.phase_results.values()
                   if r.status != STATUS_SKIPPED)

    @property
    def all_evidence(self) -> List[str]:
        paths = []
        for r in self.phase_results.values():
            paths.extend(r.evidence)
        return paths

    def summary_line(self) -> str:
        executed = self.phases_executed
        total    = len(self.path_planned)
        cred     = f" | credential: {self.cred_type}" if self.cred_type else ""
        return (
            f"{self.target_ssid} ({self.target_bssid}) "
            f"→ {self.final_status} | {executed}/{total} phases | "
            f"{self.elapsed_sec:.1f}s{cred}"
        )


# ─── Condición de parada ───────────────────────────────────────────────────────

# Fases ofensivas: una vez que se obtiene una credencial se omiten las restantes.
_OFFENSIVE_PHASES = frozenset({
    "CAPTURE_PMKID", "CAPTURE_HANDSHAKE",
    "WPS_CLASS", "WPS_PIXIE",
    "PSK_DEFAULTS", "PSK_SSID_LOGIC", "PSK_ROCKYOU",
    "CLASSIFY_WEAK_CRYPTO",
})

def _should_stop_early(result: PhaseResult, pipeline_status: str) -> bool:
    """True si el pipeline debe detener las fases ofensivas restantes."""
    # Un lockout siempre para la batería aérea
    if result.is_lockout:
        return True
    # Una credencial obtenida para las fases ofensivas (no informativas)
    if pipeline_status in (STATUS_CRACKED, STATUS_CLASS_CONFIRMED):
        return True
    return False


# ─── El pipeline ──────────────────────────────────────────────────────────────

class Pipeline:
    """
    Ejecuta una secuencia de fases en orden, con control de flujo limpio.

    Uso
    ───
        pipeline = Pipeline(phase_registry, planned_path)
        result = pipeline.run(target.ssid, target.bssid)

    El pipeline no sabe cómo funciona cada fase internamente.
    Sólo sabe del contrato PhaseProtocol y PhaseResult.
    """

    def __init__(
        self,
        phase_registry: Dict[str, PhaseProtocol],
        planned_path: List[str],
        on_phase_start=None,
        on_phase_done=None,
    ) -> None:
        """
        Parámetros
        ──────────
        phase_registry : Mapa nombre → objeto de fase (de phases.build_phase_registry()).
        planned_path   : Secuencia de nombres de fase devuelta por decide_path().
        on_phase_start : Callback opcional (phase_name: str) → None.
        on_phase_done  : Callback opcional (result: PhaseResult) → None.
        """
        self._registry      = phase_registry
        self._planned_path  = [p for p in planned_path if p != "REPORT"]
        self._on_start      = on_phase_start
        self._on_done       = on_phase_done

    def run(self, target_ssid: str = "", target_bssid: str = "") -> PipelineResult:
        """
        Ejecuta todas las fases en orden y retorna un PipelineResult.

        Reglas de ejecución
        ───────────────────
        1. Si la fase no está en el registry → se registra como SKIPPED.
        2. Si can_run() retorna False       → se registra como SKIPPED.
        3. Si la fase levanta una excepción → se registra como ERROR.
        4. Si status=LOCKED                → se detiene la batería aérea.
        5. Si status=CRACKED               → se omiten fases ofensivas restantes.
        6. Fases informativas (EOL, LAN, governance) siempre se ejecutan.
        """
        pr = PipelineResult(
            target_ssid=target_ssid,
            target_bssid=target_bssid,
            path_planned=list(self._planned_path),
        )
        t0 = time.time()
        pipeline_status = "pending"

        for phase_name in self._planned_path:

            # ── Comprobar condición de parada ANTES de cargar la fase ─────────
            if pr.lockout_detected:
                pr.phase_results[phase_name] = PhaseResult(
                    phase_name=phase_name, status=STATUS_SKIPPED,
                    detail="pipeline stopped: WPS lockout detected",
                )
                continue

            if pipeline_status in (STATUS_CRACKED, STATUS_CLASS_CONFIRMED):
                if phase_name in _OFFENSIVE_PHASES:
                    pr.phase_results[phase_name] = PhaseResult(
                        phase_name=phase_name, status=STATUS_SKIPPED,
                        detail="pipeline stopped: credential already obtained",
                    )
                    continue

            # ── Obtener la fase del registry ──────────────────────────────────
            phase = self._registry.get(phase_name)
            if phase is None:
                pr.phase_results[phase_name] = PhaseResult(
                    phase_name=phase_name, status=STATUS_SKIPPED,
                    detail="phase not in registry",
                )
                continue

            # ── can_run() check ───────────────────────────────────────────────
            if not phase.can_run():
                pr.phase_results[phase_name] = PhaseResult(
                    phase_name=phase_name, status=STATUS_SKIPPED,
                    detail="can_run() = False (tool or condition not met)",
                )
                if self._on_done:
                    self._on_done(pr.phase_results[phase_name])
                continue

            # ── Ejecutar la fase ──────────────────────────────────────────────
            if self._on_start:
                self._on_start(phase_name)

            try:
                result = phase.run()
            except Exception as exc:
                from .phases.base import STATUS_ERROR
                result = PhaseResult(
                    phase_name=phase_name, status=STATUS_ERROR,
                    detail=f"unhandled exception: {exc}",
                )

            pr.phase_results[phase_name] = result

            if self._on_done:
                self._on_done(result)

            # ── Actualizar estado global del pipeline ─────────────────────────
            if result.status == STATUS_CRACKED and pipeline_status == "pending":
                pipeline_status = STATUS_CRACKED
                pr.credential = result.credential
                pr.cred_type  = result.cred_type

            elif result.status == STATUS_CLASS_CONFIRMED and pipeline_status == "pending":
                pipeline_status = STATUS_CLASS_CONFIRMED
                pr.credential = result.credential
                pr.cred_type  = result.cred_type

            elif result.status == STATUS_EOL_CONFIRMED and pipeline_status == "pending":
                pipeline_status = STATUS_EOL_CONFIRMED

            if result.is_lockout:
                pr.lockout_detected = True
                pipeline_status = STATUS_LOCKED

        # ── Resultado final ───────────────────────────────────────────────────
        if pipeline_status == "pending":
            # Ninguna fase dio un resultado positivo
            non_skip = [
                r.status for r in pr.phase_results.values()
                if r.status not in (STATUS_SKIPPED, STATUS_DONE, "captured")
            ]
            pipeline_status = non_skip[-1] if non_skip else "exhausted"

        pr.final_status = pipeline_status
        pr.elapsed_sec  = round(time.time() - t0, 2)
        return pr
