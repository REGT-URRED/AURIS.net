"""
AURIS — phases/psk.py
Fases de crackeo de PSK: lógica SSID, rockyou y clasificación de cifrado débil.
"""

from __future__ import annotations

import os
import time
from typing import Dict, Optional

from ..models import TargetInfo
from ..adapters.cracker import crack_with_hashcat, crack_with_aircrack
from ..adapters.capture import find_crackable_material
from ..adapters.tool_runner import tool_available
from ..generator import generate_candidates
from .base import (
    PhaseResult,
    STATUS_CRACKED, STATUS_EXHAUSTED,
    STATUS_TIMEOUT, STATUS_SKIPPED, STATUS_DONE, STATUS_ERROR,
)

TIMEOUTS = {"PSK_SSID_LOGIC": 300, "PSK_ROCKYOU": 900}


class ClassifyWeakCryptoPhase:
    """Clasifica cifrado débil (Open, WEP) sin intentar explotar."""
    name = "CLASSIFY_WEAK_CRYPTO"

    def __init__(self, target: TargetInfo) -> None:
        self._target = target

    def can_run(self) -> bool:
        return self._target.encryption.upper() in ("OPEN", "WEP", "NONE")

    def run(self) -> PhaseResult:
        enc = self._target.encryption.upper()
        if enc in ("OPEN", "NONE"):
            return PhaseResult(
                phase_name=self.name, status=STATUS_DONE,
                credential="[no password — open network]",
                cred_type="Open Network (no encryption)",
                detail="Network has no authentication — documented as CWE-311",
            )
        return PhaseResult(
            phase_name=self.name, status=STATUS_DONE,
            cred_type=f"Weak encryption ({enc})",
            detail=f"Deprecated cipher {enc} detected — documented without exploit",
        )


class PSKSsidLogicPhase:
    """
    Crackeo offline usando candidatos generados por lógica de SSID.

    Estrategia
    ──────────
    1. Genera candidatos con CandidateGenerator (Base+Sep+Año, BSSID fragment, familia).
    2. Escribe el wordlist temporal al directorio de evidencia.
    3. Intenta crackeo con hashcat (si disponible) o aircrack-ng (fallback).
    4. Si lote1 falla y hay claves de familia, prueba lote2 (mutaciones).
    """
    name = "PSK_SSID_LOGIC"

    def __init__(
        self,
        target: TargetInfo,
        run_dir: str,
        family_keys: Optional[Dict[str, str]] = None,
    ) -> None:
        self._target     = target
        self._run_dir    = run_dir
        self._family_keys = family_keys or {}

    def can_run(self) -> bool:
        hc, cap = find_crackable_material(self._run_dir)
        has_material = bool(hc or cap)
        has_cracker  = tool_available("hashcat") or tool_available("aircrack-ng")
        return has_material and has_cracker

    def run(self) -> PhaseResult:
        if not self.can_run():
            return PhaseResult(phase_name=self.name, status=STATUS_SKIPPED,
                               detail="no crackable material or cracker available")
        t0 = time.time()
        try:
            candidate_set = generate_candidates(
                ssid=self._target.ssid,
                bssid=self._target.bssid,
                brand=self._target.brand or "",
                family_keys=self._family_keys,
            )
        except Exception as exc:
            return PhaseResult(phase_name=self.name, status=STATUS_ERROR,
                               detail=f"candidate generation failed: {exc}",
                               elapsed_sec=round(time.time()-t0, 2))

        wl_path = os.path.join(self._run_dir, "ssid_candidates.txt")
        with open(wl_path, "w", encoding="utf-8") as f:
            f.write(candidate_set.to_wordlist_lines())

        hc_path, cap_path = find_crackable_material(self._run_dir)
        result = None

        # ── Intento 1: hashcat con lote1 ─────────────────────────────────────
        if hc_path and tool_available("hashcat"):
            result = crack_with_hashcat(
                hash_path=hc_path,
                wordlist=wl_path,
                timeout=TIMEOUTS["PSK_SSID_LOGIC"] // 2,
                desc=f"hashcat SSID-logic ({candidate_set.total} candidates)",
            )

        # ── Intento 1b: aircrack fallback ────────────────────────────────────
        if (result is None or not result.cracked) and cap_path and tool_available("aircrack-ng"):
            result = crack_with_aircrack(
                cap_path=cap_path,
                wordlist=wl_path,
                bssid=self._target.bssid,
                timeout=TIMEOUTS["PSK_SSID_LOGIC"] // 2,
                desc=f"aircrack-ng SSID-logic",
            )

        if result and result.cracked:
            return PhaseResult(
                phase_name=self.name, status=STATUS_CRACKED,
                credential=result.password, cred_type=result.method,
                detail=f"{candidate_set.meta.get('batch_1_total', 0)} candidates tried",
                elapsed_sec=round(time.time()-t0, 2),
                evidence=[wl_path],
            )

        # ── Intento 2: lote2 (mutaciones de familia) ─────────────────────────
        if candidate_set.batch_2:
            wl2_path = os.path.join(self._run_dir, "ssid_candidates_family.txt")
            with open(wl2_path, "w", encoding="utf-8") as f:
                f.write("\n".join(candidate_set.batch_2))

            if hc_path and tool_available("hashcat"):
                result2 = crack_with_hashcat(
                    hash_path=hc_path, wordlist=wl2_path,
                    timeout=TIMEOUTS["PSK_SSID_LOGIC"] // 4,
                    desc="hashcat family-mutations",
                )
                if result2.cracked:
                    return PhaseResult(
                        phase_name=self.name, status=STATUS_CRACKED,
                        credential=result2.password, cred_type=result2.method,
                        detail="cracked via family key mutation (batch_2)",
                        elapsed_sec=round(time.time()-t0, 2),
                        evidence=[wl2_path],
                    )

        elapsed = round(time.time()-t0, 2)
        if result and result.status == "timeout":
            return PhaseResult(phase_name=self.name, status=STATUS_TIMEOUT,
                               elapsed_sec=elapsed)
        return PhaseResult(phase_name=self.name, status=STATUS_EXHAUSTED,
                           detail=f"{candidate_set.total} candidates exhausted",
                           elapsed_sec=elapsed, evidence=[wl_path])


class PSKRockyouPhase:
    """Crackeo offline con rockyou.txt (fallback de último recurso)."""
    name = "PSK_ROCKYOU"

    def __init__(
        self,
        target: TargetInfo,
        run_dir: str,
        wordlist_path: Optional[str] = None,
    ) -> None:
        self._target       = target
        self._run_dir      = run_dir
        self._wordlist     = wordlist_path

    def _find_rockyou(self) -> Optional[str]:
        if self._wordlist and os.path.isfile(self._wordlist):
            return self._wordlist
        candidates = [
            "/usr/share/wordlists/rockyou.txt",
            os.path.join(self._run_dir, "../../offline_bundle/wordlists/rockyou.txt"),
        ]
        for c in candidates:
            if os.path.isfile(c) and os.path.getsize(c) > 1_000_000:
                return c
        return None

    def can_run(self) -> bool:
        hc, cap = find_crackable_material(self._run_dir)
        has_material = bool(hc or cap)
        has_cracker  = tool_available("hashcat") or tool_available("aircrack-ng")
        return has_material and has_cracker and self._find_rockyou() is not None

    def run(self) -> PhaseResult:
        if not self.can_run():
            return PhaseResult(phase_name=self.name, status=STATUS_SKIPPED,
                               detail="rockyou.txt or cracker not available")

        rockyou = self._find_rockyou()
        hc_path, cap_path = find_crackable_material(self._run_dir)
        t0 = time.time()

        result = None
        if hc_path and tool_available("hashcat"):
            result = crack_with_hashcat(
                hash_path=hc_path, wordlist=rockyou,
                timeout=TIMEOUTS["PSK_ROCKYOU"],
                desc=f"hashcat rockyou · {self._target.ssid}",
            )
        if (result is None or not result.cracked) and cap_path and tool_available("aircrack-ng"):
            result = crack_with_aircrack(
                cap_path=cap_path, wordlist=rockyou,
                bssid=self._target.bssid,
                timeout=TIMEOUTS["PSK_ROCKYOU"],
                desc="aircrack-ng rockyou",
            )

        elapsed = round(time.time()-t0, 2)
        if result and result.cracked:
            return PhaseResult(
                phase_name=self.name, status=STATUS_CRACKED,
                credential=result.password, cred_type=result.method,
                elapsed_sec=elapsed,
            )
        if result and result.status == "timeout":
            return PhaseResult(phase_name=self.name, status=STATUS_TIMEOUT,
                               elapsed_sec=elapsed)
        return PhaseResult(phase_name=self.name, status=STATUS_EXHAUSTED,
                           detail="rockyou exhausted", elapsed_sec=elapsed)
