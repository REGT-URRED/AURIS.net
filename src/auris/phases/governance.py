"""
AURIS — phases/governance.py
Fases de gobernanza y análisis de riesgo sistémico:
  EOL_GOVERNANCE, AUDIT_DPP_VULNERABILITIES, VALIDATE_COUNTERMEASURE.
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional

from ..models import TargetInfo, Profile
from .base import (
    PhaseResult,
    STATUS_EOL_CONFIRMED, STATUS_NOT_FOUND, STATUS_DONE, STATUS_ERROR, STATUS_SKIPPED,
)


class EOLGovernancePhase:
    """
    Evalúa si el CPE tiene firmware desactualizado sin canal de distribución del ISP.
    Produce hallazgo de gobernanza (CWE-1104) cuando se confirma la brecha.
    """
    name = "EOL_GOVERNANCE"

    def __init__(self, target: TargetInfo, profile: Profile, run_dir: str) -> None:
        self._target  = target
        self._profile = profile
        self._run_dir = run_dir

    def can_run(self) -> bool:
        # Siempre ejecutable: es una evaluación de conocimiento, no de radio
        return True

    def run(self) -> PhaseResult:
        t0 = time.time()
        try:
            from ..vendor_profiles import eol_assessment
            assessment = eol_assessment(self._profile.brand, self._target.ssid)
        except Exception as exc:
            return PhaseResult(phase_name=self.name, status=STATUS_ERROR,
                               detail=f"eol_assessment failed: {exc}",
                               elapsed_sec=round(time.time()-t0, 2))

        # Persistir el assessment para el informe
        out_path = os.path.join(self._run_dir, "eol_assessment.json")
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(assessment, f, indent=2)
        except OSError:
            pass

        elapsed = round(time.time()-t0, 2)
        if assessment.get("verdict") == "eol_confirmed":
            reasons = assessment.get("reasons", ["Firmware sin parche distribuido"])
            return PhaseResult(
                phase_name=self.name, status=STATUS_EOL_CONFIRMED,
                cred_type="CWE-1104: Use of Unmaintained Third Party Component",
                detail=f"EOL confirmed: {reasons[0]}",
                elapsed_sec=elapsed, evidence=[out_path],
            )

        required = assessment.get("required_evidence", ["Version comparison needed"])
        return PhaseResult(
            phase_name=self.name, status=STATUS_NOT_FOUND,
            detail=f"EOL not confirmed — requires: {required[0]}",
            elapsed_sec=elapsed,
        )


class AuditDPPPhase:
    """
    Evalúa riesgos de onboarding DPP / Easy Connect por señales observables
    (no envía frames DPP — evaluación pasiva de la configuración detectada).
    """
    name = "AUDIT_DPP_VULNERABILITIES"

    def __init__(self, target: TargetInfo, profile: Profile, run_dir: str) -> None:
        self._target  = target
        self._profile = profile
        self._run_dir = run_dir

    def can_run(self) -> bool:
        return self._target.dpp_supported or self._target.wpa3_supported

    def run(self) -> PhaseResult:
        t0 = time.time()
        if not self.can_run():
            return PhaseResult(phase_name=self.name, status=STATUS_SKIPPED,
                               detail="DPP/WPA3 not detected on this AP")
        try:
            from ..vendor_profiles import dpp_assessment
            assessment = dpp_assessment(
                brand=self._profile.brand,
                ssid=self._target.ssid,
                wpa3_supported=self._target.wpa3_supported,
                dpp_supported=self._target.dpp_supported,
                wps_enabled=self._target.wps_enabled,
                encryption=self._target.encryption,
            )
        except Exception as exc:
            return PhaseResult(phase_name=self.name, status=STATUS_ERROR,
                               detail=str(exc), elapsed_sec=round(time.time()-t0, 2))

        out_path = os.path.join(self._run_dir, "dpp_assessment.json")
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(assessment, f, indent=2)
        except OSError:
            pass

        verdict = assessment.get("verdict", "needs_evidence")
        elapsed = round(time.time()-t0, 2)
        status = STATUS_NOT_FOUND if verdict != "clear" else STATUS_DONE
        return PhaseResult(
            phase_name=self.name, status=status,
            detail=f"DPP verdict: {verdict}",
            elapsed_sec=elapsed, evidence=[out_path],
        )


class ValidateCountermeasurePhase:
    """
    Documenta si los controles L2 del AP (filtrado MAC, lockout WPS)
    son mitigaciones reales o controles cosméticos. No emite frames.
    """
    name = "VALIDATE_COUNTERMEASURE"

    def __init__(self, target: TargetInfo) -> None:
        self._target = target

    def can_run(self) -> bool:
        return True

    def run(self) -> PhaseResult:
        notes = []
        if self._target.wps_locked:
            notes.append("WPS lockout: MAC-spoofable L2 control (CWE-656)")
        if not self._target.wps_enabled:
            notes.append("WPS disabled: correct hardening")
        if self._target.wpa3_supported:
            notes.append("WPA3-SAE: resistant to offline dictionary attacks")

        detail = "; ".join(notes) if notes else "No countermeasures to validate"
        return PhaseResult(
            phase_name=self.name, status=STATUS_DONE,
            detail=detail,
        )
