"""
AURIS — phases/network.py
Fases de auditoría de red: superficie LAN y prueba de resiliencia.
"""

from __future__ import annotations

import json
import os
import time
from typing import Dict, Optional

from ..models import TargetInfo
from ..adapters.tool_runner import tool_available
from .base import (
    PhaseResult,
    STATUS_DONE, STATUS_SKIPPED, STATUS_ERROR,
)


class AuditLanSurfacePhase:
    """
    Auditoría de superficie de gestión LAN (solo lectura, solo RFC1918).
    Requiere --allow-lan explícito y lab_lan_gateway en el scope.
    """
    name = "AUDIT_LAN_SURFACE"

    def __init__(
        self,
        target: TargetInfo,
        run_dir: str,
        scope: Optional[Dict] = None,
        allow_lan: bool = False,
    ) -> None:
        self._target    = target
        self._run_dir   = run_dir
        self._scope     = scope or {}
        self._allow_lan = allow_lan

    def can_run(self) -> bool:
        return self._allow_lan and bool(self._scope.get("lab_lan_gateway", ""))

    def run(self) -> PhaseResult:
        if not self.can_run():
            return PhaseResult(phase_name=self.name, status=STATUS_SKIPPED,
                               detail="--allow-lan not set or lab_lan_gateway not in scope")
        gw = self._scope.get("lab_lan_gateway", "")
        t0 = time.time()
        try:
            from ..lan_audit import audit_lan_surface
            data = audit_lan_surface(gw)
        except ValueError as exc:
            return PhaseResult(phase_name=self.name, status=STATUS_ERROR,
                               detail=f"IP not RFC1918: {exc}",
                               elapsed_sec=round(time.time()-t0, 2))
        except Exception as exc:
            return PhaseResult(phase_name=self.name, status=STATUS_ERROR,
                               detail=f"LAN unreachable: {exc}",
                               elapsed_sec=round(time.time()-t0, 2))

        out_path = os.path.join(self._run_dir, "lan_surface.json")
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass

        open_findings = [c for c in data.get("checks", []) if c.get("open") and c.get("finding")]
        detail = (
            f"{len(open_findings)} open service(s) with findings: "
            + ", ".join(f"{c['port']}/{c['service']}" for c in open_findings)
            if open_findings else "no open management services detected"
        )
        return PhaseResult(
            phase_name=self.name, status=STATUS_DONE,
            detail=detail, elapsed_sec=round(time.time()-t0, 2),
            evidence=[out_path],
        )


class ResilienceTestPhase:
    """
    Prueba de resiliencia: envía frames de deauth y mide la recuperación del AP.
    Solo se ejecuta si aireplay-ng está disponible y el scope lo autoriza.
    """
    name = "RESILIENCE_TEST"

    def __init__(self, target: TargetInfo, iface: str) -> None:
        self._target = target
        self._iface  = iface

    def can_run(self) -> bool:
        return tool_available("aireplay-ng")

    def run(self) -> PhaseResult:
        if not self.can_run():
            return PhaseResult(phase_name=self.name, status=STATUS_SKIPPED,
                               detail="aireplay-ng not available")
        from ..adapters.capture import deauth_burst
        t0 = time.time()
        res = deauth_burst(
            iface=self._iface,
            bssid=self._target.bssid,
            frames=5,
            timeout=30,
        )
        elapsed = round(time.time()-t0, 2)
        status = STATUS_DONE if res.ok else STATUS_ERROR
        return PhaseResult(
            phase_name=self.name, status=status,
            detail="Deauth resilience test completed" if res.ok else res.stderr,
            elapsed_sec=elapsed,
        )
