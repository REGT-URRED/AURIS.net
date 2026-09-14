"""
AURIS — phases/__init__.py
Registro de todas las fases disponibles.

Uso desde el pipeline
─────────────────────
    from auris.phases import build_phase_registry
    registry = build_phase_registry(target, profile, iface, run_dir, scope)
    phase = registry["CAPTURE_PMKID"]
    result = phase.run()
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Optional

if TYPE_CHECKING:
    from ..models import Profile, TargetInfo

from .base import PhaseProtocol


def build_phase_registry(
    target,
    profile,
    iface: str,
    run_dir: str,
    scope: Optional[Dict] = None,
    known_keys: Optional[Dict[str, str]] = None,
    allow_lan: bool = False,
    wordlist_rockyou: Optional[str] = None,
) -> Dict[str, "PhaseProtocol"]:
    """
    Construye el diccionario name → fase instanciada para un target dado.

    El pipeline sólo interactúa con este diccionario.
    Añadir una nueva fase = añadir una entrada aquí y crear la clase.
    """
    from .capture import CapturePhase
    from .wps import WPSPixiePhase, WPSPinClassPhase, DetectWPSLockoutPhase, DetectWPA3Phase
    from .psk import PSKSsidLogicPhase, PSKRockyouPhase, ClassifyWeakCryptoPhase
    from .governance import EOLGovernancePhase, AuditDPPPhase, ValidateCountermeasurePhase
    from .network import AuditLanSurfacePhase, ResilienceTestPhase

    return {
        # Captura
        "CAPTURE_PMKID":            CapturePhase(target, iface, run_dir, mode="pmkid"),
        "CAPTURE_HANDSHAKE":        CapturePhase(target, iface, run_dir, mode="handshake"),
        # WPS
        "WPS_PIXIE":                WPSPixiePhase(target, iface),
        "WPS_CLASS":                WPSPinClassPhase(target, iface),
        "DETECT_WPS_LOCKOUT":       DetectWPSLockoutPhase(target),
        "DETECT_WPA3_SAE":          DetectWPA3Phase(target),
        # PSK
        "CLASSIFY_WEAK_CRYPTO":     ClassifyWeakCryptoPhase(target),
        "PSK_SSID_LOGIC":           PSKSsidLogicPhase(target, run_dir, known_keys or {}),
        "PSK_ROCKYOU":              PSKRockyouPhase(target, run_dir, wordlist_rockyou),
        # Gobernanza
        "EOL_GOVERNANCE":           EOLGovernancePhase(target, profile, run_dir),
        "AUDIT_DPP_VULNERABILITIES": AuditDPPPhase(target, profile, run_dir),
        "VALIDATE_COUNTERMEASURE":  ValidateCountermeasurePhase(target),
        # Red / LAN
        "AUDIT_LAN_SURFACE":        AuditLanSurfacePhase(target, run_dir, scope, allow_lan),
        "RESILIENCE_TEST":          ResilienceTestPhase(target, iface),
    }


__all__ = ["PhaseProtocol", "build_phase_registry"]
