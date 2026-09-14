"""
AURIS — phases/capture.py
Fase de captura de material crackeable (PMKID / Handshake 4-way).
"""

from __future__ import annotations

import time
from typing import Optional

from ..models import TargetInfo
from ..adapters.capture import capture_pmkid, capture_handshake, find_crackable_material
from .base import (
    PhaseResult, PhaseProtocol,
    STATUS_CAPTURED, STATUS_NOT_FOUND, STATUS_SKIPPED,
    STATUS_TIMEOUT, STATUS_ERROR,
)

TIMEOUTS = {"pmkid": 60, "handshake": 120}
MAX_ROUNDS = {"pmkid": 2, "handshake": 3}


class CapturePhase:
    """
    Captura de material WPA crackeable.

    Modos
    ─────
    "pmkid"     : PMKID via hcxdumptool (sin clientes conectados).
    "handshake" : Handshake 4-way via hcxdumptool + airodump-ng + deauth.
    """
    name: str

    def __init__(self, target: TargetInfo, iface: str, run_dir: str, mode: str = "pmkid") -> None:
        self._target  = target
        self._iface   = iface
        self._run_dir = run_dir
        self._mode    = mode
        self.name     = f"CAPTURE_{mode.upper()}"

    def can_run(self) -> bool:
        from ..adapters.tool_runner import tool_available
        if self._mode == "pmkid":
            return tool_available("hcxdumptool")
        return tool_available("hcxdumptool") or tool_available("airodump-ng")

    def run(self) -> PhaseResult:
        if not self.can_run():
            return PhaseResult(
                phase_name=self.name, status=STATUS_SKIPPED,
                detail=f"capture tools not available for mode={self._mode}",
            )

        t0 = time.time()
        try:
            if self._mode == "pmkid":
                result = capture_pmkid(
                    iface=self._iface,
                    bssid=self._target.bssid,
                    out_dir=self._run_dir,
                    timeout=TIMEOUTS["pmkid"],
                    max_rounds=MAX_ROUNDS["pmkid"],
                )
            else:
                result = capture_handshake(
                    iface=self._iface,
                    bssid=self._target.bssid,
                    channel=self._target.channel,
                    out_dir=self._run_dir,
                    timeout=TIMEOUTS["handshake"],
                    max_rounds=MAX_ROUNDS["handshake"],
                )
        except Exception as exc:
            return PhaseResult(
                phase_name=self.name, status=STATUS_ERROR,
                detail=str(exc), elapsed_sec=round(time.time() - t0, 2),
            )

        if result.timed_out:
            return PhaseResult(
                phase_name=self.name, status=STATUS_TIMEOUT,
                elapsed_sec=round(time.time() - t0, 2),
            )

        if result.captured:
            evidence = [p for p in (result.pcap_path, result.hc22000_path) if p]
            detail = f"hc22000: {result.hc22000_path}" if result.hc22000_path else f"pcap: {result.pcap_path}"
            return PhaseResult(
                phase_name=self.name, status=STATUS_CAPTURED,
                detail=detail, elapsed_sec=round(time.time() - t0, 2),
                evidence=evidence,
            )

        return PhaseResult(
            phase_name=self.name, status=STATUS_NOT_FOUND,
            detail=result.error, elapsed_sec=round(time.time() - t0, 2),
        )
