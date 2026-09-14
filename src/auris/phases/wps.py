"""
AURIS — phases/wps.py
Fases de análisis WPS: PixieDust, PIN class, lockout, WPA3 detection.
"""

from __future__ import annotations

import time
from ..models import TargetInfo
from ..adapters.cracker import attack_wps_pixiedust, attack_wps_pin_class
from ..adapters.tool_runner import tool_available
from .base import (
    PhaseResult,
    STATUS_CRACKED, STATUS_CLASS_CONFIRMED, STATUS_LOCKED,
    STATUS_NOT_FOUND, STATUS_SKIPPED, STATUS_TIMEOUT, STATUS_DONE, STATUS_ERROR,
)

TIMEOUTS = {"WPS_PIXIE": 120, "WPS_CLASS": 180}


class WPSPixiePhase:
    """WPS PixieDust: explota debilidad del PRNG del registrar WPS v1.0."""
    name = "WPS_PIXIE"

    def __init__(self, target: TargetInfo, iface: str) -> None:
        self._target = target
        self._iface  = iface

    def can_run(self) -> bool:
        return (
            self._target.wps_enabled
            and self._target.wps_version == "1.0"
            and not self._target.wps_locked
            and (tool_available("reaver") or tool_available("bully"))
            and tool_available("pixiewps")
        )

    def run(self) -> PhaseResult:
        if not self.can_run():
            return PhaseResult(phase_name=self.name, status=STATUS_SKIPPED,
                               detail="WPS PixieDust prerequisites not met")
        t0 = time.time()
        try:
            result = attack_wps_pixiedust(
                iface=self._iface,
                bssid=self._target.bssid,
                channel=self._target.channel,
                timeout=TIMEOUTS["WPS_PIXIE"],
            )
        except Exception as exc:
            return PhaseResult(phase_name=self.name, status=STATUS_ERROR,
                               detail=str(exc), elapsed_sec=round(time.time()-t0, 2))

        if result.status == "locked":
            return PhaseResult(phase_name=self.name, status=STATUS_LOCKED,
                               detail="AP activated WPS lockout",
                               elapsed_sec=result.elapsed_sec)
        if result.cracked:
            return PhaseResult(
                phase_name=self.name, status=STATUS_CRACKED,
                credential=result.password, cred_type=result.method,
                elapsed_sec=result.elapsed_sec,
            )
        if result.status == "timeout":
            return PhaseResult(phase_name=self.name, status=STATUS_TIMEOUT,
                               elapsed_sec=result.elapsed_sec)
        return PhaseResult(phase_name=self.name, status=STATUS_NOT_FOUND,
                           elapsed_sec=result.elapsed_sec)


class WPSPinClassPhase:
    """WPS PIN class: valida si la familia usa PIN de fábrica predecible."""
    name = "WPS_CLASS"

    def __init__(self, target: TargetInfo, iface: str) -> None:
        self._target = target
        self._iface  = iface

    def can_run(self) -> bool:
        return (
            self._target.wps_enabled
            and not self._target.wps_locked
            and (tool_available("reaver") or tool_available("bully"))
        )

    def run(self) -> PhaseResult:
        if not self.can_run():
            return PhaseResult(phase_name=self.name, status=STATUS_SKIPPED,
                               detail="WPS PIN class prerequisites not met")
        t0 = time.time()
        try:
            result = attack_wps_pin_class(
                iface=self._iface,
                bssid=self._target.bssid,
                timeout=TIMEOUTS["WPS_CLASS"],
            )
        except Exception as exc:
            return PhaseResult(phase_name=self.name, status=STATUS_ERROR,
                               detail=str(exc), elapsed_sec=round(time.time()-t0, 2))

        if result.status == "locked":
            return PhaseResult(phase_name=self.name, status=STATUS_LOCKED,
                               detail="AP WPS lockout — L2 control documented",
                               elapsed_sec=result.elapsed_sec)
        if result.cracked:
            return PhaseResult(
                phase_name=self.name, status=STATUS_CLASS_CONFIRMED,
                credential=result.password, cred_type=result.method,
                detail="WPS PIN class confirmed for this device family",
                elapsed_sec=result.elapsed_sec,
            )
        if result.status == "timeout":
            return PhaseResult(phase_name=self.name, status=STATUS_TIMEOUT,
                               elapsed_sec=result.elapsed_sec)
        return PhaseResult(phase_name=self.name, status=STATUS_NOT_FOUND,
                           elapsed_sec=result.elapsed_sec)


class DetectWPSLockoutPhase:
    """Documenta el lockout WPS como hallazgo (control cosmético si es por MAC)."""
    name = "DETECT_WPS_LOCKOUT"

    def __init__(self, target: TargetInfo) -> None:
        self._target = target

    def can_run(self) -> bool:
        return self._target.wps_enabled and self._target.wps_locked

    def run(self) -> PhaseResult:
        return PhaseResult(
            phase_name=self.name, status=STATUS_DONE,
            detail="WPS lockout detected — documented as L2 cosmetic control (MAC-spoofable)",
            cred_type="CWE-656: Reliance on Security Through Obscurity",
        )


class DetectWPA3Phase:
    """Documenta WPA3-SAE: resistente a diccionario offline, omite PSK_ROCKYOU."""
    name = "DETECT_WPA3_SAE"

    def __init__(self, target: TargetInfo) -> None:
        self._target = target

    def can_run(self) -> bool:
        return self._target.wpa3_supported

    def run(self) -> PhaseResult:
        return PhaseResult(
            phase_name=self.name, status=STATUS_DONE,
            detail="WPA3-SAE detected — offline dictionary attacks not viable by design",
            cred_type="WPA3-SAE (802.11-2020)",
        )
