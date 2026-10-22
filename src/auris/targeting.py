"""
AURIS — targeting.py
Ranking de objetivos para la selección automática (`run-all --auto`).

Heurística offline y explicable: señal, WPS, cifrado, clientes y catálogo
Broadcom. No toca radio ni firma por el operador: ordena y justifica; la
puerta RoE sigue exigiendo `--force-roe` en modo automático.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from .broadcom import BroadcomError, lookup as broadcom_lookup
from .vendor_profiles import resolve_brand


@dataclass(frozen=True)
class RankedTarget:
    target: Dict
    score: int
    reasons: Tuple[str, ...]

    @property
    def bssid(self) -> str:
        return str(self.target.get("bssid", "")).upper()

    @property
    def ssid(self) -> str:
        return str(self.target.get("ssid", "?"))


def _int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def brand_of(target: Dict) -> str:
    return resolve_brand(
        target.get("oui", ""),
        target.get("ssid", ""),
        target.get("brand", "Unknown"),
    )


def affected_models(vendor: str) -> List[str]:
    """Modelos afectados del catálogo Broadcom para un fabricante (o [])."""
    if not vendor or vendor == "Unknown":
        return []
    try:
        matches = broadcom_lookup(vendor)
    except BroadcomError:
        return []
    return [
        f"{match.vendor} {match.product}"
        for match in matches
        if match.status == "affected"
    ]


def score_target(target: Dict) -> RankedTarget:
    score = 0
    reasons: List[str] = []

    rssi = _int(target.get("signal_strength"), -100)
    signal_points = max(0, min(60, 100 + rssi))
    score += signal_points
    if signal_points >= 45:
        reasons.append(f"señal fuerte ({rssi} dBm)")

    if target.get("wps_enabled"):
        if target.get("wps_locked"):
            score += 5
            reasons.append("WPS con lockout")
        else:
            score += 35
            reasons.append("WPS abierto")

    encryption = str(target.get("encryption", "")).upper()
    if "WEP" in encryption:
        score += 25
        reasons.append("cifrado WEP")
    elif encryption.startswith("WPA-") or encryption == "WPA":
        score += 15
        reasons.append("WPA/TKIP")
    if "WPA3" in encryption or "SAE" in encryption:
        score -= 20
        reasons.append("WPA3/SAE (más resistente)")

    clients = _int(target.get("clients"), 0)
    if clients > 0:
        score += min(10, clients * 2)
        reasons.append(f"{clients} cliente(s)")

    models = affected_models(brand_of(target))
    if models:
        score += 15
        reasons.append(f"Broadcom SDK candidato ({len(models)} modelo(s))")

    return RankedTarget(
        target=target,
        score=score,
        reasons=tuple(reasons) or ("sin señales fuertes",),
    )


def rank_targets(targets: Sequence[Dict]) -> List[RankedTarget]:
    """Ordena de mayor a menor puntaje; empate por BSSID para ser determinista."""
    ranked = [score_target(target) for target in targets]
    ranked.sort(key=lambda item: (-item.score, item.bssid))
    return ranked


def select_targets(targets: Sequence[Dict], top: int = 0) -> List[RankedTarget]:
    """Top-N del ranking (top<=0 devuelve todos)."""
    ranked = rank_targets(targets)
    return ranked[:top] if top and top > 0 else ranked
