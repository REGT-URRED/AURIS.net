"""
AURIS / Wifite4 — generator.py
Motor combinatorio inteligente de candidatos PSK.

Objetivo de diseño
──────────────────
Reemplazar la dependencia de diccionarios genéricos masivos (rockyou.txt)
por candidatos específicamente calculados para el AP bajo análisis.

La lógica es:
  1. Números: fragmentos de hardware (BSSID), canal, año de despliegue.
  2. Letras: nombre de red (SSID), nombre de fabricante/ISP, sufijos comunes.
  3. Combinación exacta: [Base] + [Separador] + [Número/Token] + [Sufijo OEM]

Esta estrategia reduce el espacio de búsqueda de ~14M entradas (rockyou)
a un conjunto de 500-5000 candidatos altamente probables para routers CPE
de ISPs (Askey, Huawei, TP-Link, MitraStar, Sagemcom, Arcadyan, ZyXEL).

El módulo es 100% offline — no realiza conexiones de red ni accede al aire.
Puede ejecutarse en cualquier plataforma (Linux / Windows / macOS).

Contribución Open Source / Wifite4
────────────────────────────────────
Este módulo fue extraído y refactorizado del runner.py de AURIS como
componente independiente y testeable. La separación permite:
  - Pruebas unitarias sin hardware WiFi.
  - Reutilización en otros proyectos de investigación de seguridad.
  - Contribución como plugin a wifit3 / wifite4.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set


# ─── Tokens conocidos de ISPs y OEMs ──────────────────────────────────────────
# Fuente: análisis de flotas desplegadas documentadas públicamente.
# NO incluye contraseñas reales; solo prefijos/sufijos conocidos del fabricante.

ISP_TOKENS: List[str] = [
    # Operadoras hispanas
    "movistar", "jazztel", "vodafone", "ono", "orange", "livebox",
    "fibra", "fibraoptica", "internet", "casa", "hogar",
    # OEMs CPE comunes
    "huawei", "tplink", "tp-link", "mitrastar", "askey", "arcadyan",
    "sagemcom", "zyxel", "zte", "gemtek",
    # Tokens genéricos del segmento doméstico
    "admin", "router", "wifi", "wlan", "wireless",
]

# Separadores habituales en contraseñas generadas por ISPs/fábricas
SEPARATORS: List[str] = ["", "_", "-", ".", "@", "#"]

# Sufijos numéricos observados en flotas de routers domésticos
NUMERIC_TAILS: List[str] = [
    "1", "2", "3", "01", "02", "03", "12", "123", "1234", "12345",
    "007", "000", "111", "222", "333", "999", "2019", "2020",
    "2021", "2022", "2023", "2024", "2025", "2026",
]

# Ventana de despliegue de routers CPE domésticos (años de configuración de fábrica)
DEPLOYMENT_YEARS: List[str] = [str(y) for y in range(2018, 2027)]


# ─── Modelo de resultado ───────────────────────────────────────────────────────

@dataclass
class CandidateSet:
    """
    Resultado del motor combinatorio para un AP concreto.

    Atributos
    ─────────
    batch_1 : Claves de alta prioridad (derivadas directamente del SSID, BSSID y familia).
    batch_2 : Claves de segunda prioridad (mutaciones de claves de APs hermanos).
    meta    : Metadata del proceso de generación (estadísticas, motivo de cada grupo).
    """
    ssid: str
    bssid: str
    batch_1: List[str] = field(default_factory=list)
    batch_2: List[str] = field(default_factory=list)
    meta: Dict[str, object] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.batch_1) + len(self.batch_2)

    def all_candidates(self) -> Iterator[str]:
        """Iterador unificado: batch_1 primero (mayor probabilidad), luego batch_2."""
        yield from self.batch_1
        yield from self.batch_2

    def to_wordlist_lines(self) -> str:
        """Texto listo para escribir a un archivo de diccionario."""
        return "\n".join(self.all_candidates())


# ─── Utilidades internas ───────────────────────────────────────────────────────

def _ssid_family_base(ssid: str) -> str:
    """
    Extrae la base de familia de un SSID eliminando sufijos de APs hermanos.

    Ejemplos:
      "MiRed_2"   → "MiRed"
      "CASA-5G"   → "CASA"
      "ISP_PLUS"  → "ISP"
      "WiFi3"     → "WiFi"  (número final)
    """
    base = (ssid or "").strip()
    pattern = r"(?i)([ _.\\-]?(2|3|4|5|plus|5g|2g|ext|guest|iot|2\.4g|\d+))$"
    m = re.search(pattern, base)
    if m and len(base) - len(m.group(0)) >= 3:
        return base[: -len(m.group(0))]
    return base


def _case_variants(text: str) -> List[str]:
    """Genera variantes de mayúsculas/minúsculas para un string."""
    seen: Set[str] = set()
    result: List[str] = []
    for v in (text, text.lower(), text.upper(), text.capitalize(),
              text[0].upper() + text[1:].lower() if len(text) > 1 else text):
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result


def _bssid_fragments(bssid: str) -> List[str]:
    """
    Extrae fragmentos del BSSID para combinar con el SSID.

    El último octeto es el más específico por unidad; los últimos 3 octetos
    (OUI de fábrica extendido) son frecuentes en claves derivadas de MAC.
    """
    clean = bssid.replace(":", "").replace("-", "").upper()
    frags: Set[str] = set()
    for length in (4, 6, 8):  # 2, 3 y 4 últimos octetos
        frags.add(clean[-length:])
        frags.add(clean[-length:].lower())
    return [f for f in frags if f]


def _mutate_key(key: str) -> List[str]:
    """
    Genera mutaciones de una clave de AP hermano para intentar con el objetivo.

    Estrategia: los ISPs tienden a usar la misma clave base con pequeñas
    variaciones entre APs de la misma cuenta o localización.

    Ejemplos:
      "wifi@2026@"  → ["wifi@2026@1", "wifi@2026@2", "wifi@2027@"]
      "casa123"     → ["casa124", "casa1231", "casa1232"]
    """
    mutations: List[str] = []
    for tail in ("1", "2", "3", "12", "123", "2024", "2025", "2026", "_1", "-1"):
        mutations.append(f"{key}{tail}")

    # Incrementar el último número encontrado en la clave
    m = re.search(r"(\d+)([^0-9]*)$", key)
    if m:
        digits, tail = m.group(1), m.group(2)
        for d in ("1", "2", "3"):
            if d != digits:
                mutations.append(key[: m.start(1)] + d + tail)
        try:
            mutations.append(key[: m.start(1)] + str(int(digits) + 1) + tail)
        except ValueError:
            pass

    return mutations


# ─── Motor principal ───────────────────────────────────────────────────────────

class CandidateGenerator:
    """
    Motor combinatorio inteligente de candidatos PSK para auditoría WiFi.

    Parámetros de construcción
    ──────────────────────────
    max_batch_1 : Límite de candidatos en la primera tanda (alta probabilidad).
    max_batch_2 : Límite de candidatos en la segunda tanda (mutaciones de familia).
    min_length  : Longitud mínima de WPA-PSK válida (estándar: 8 caracteres).
    max_length  : Longitud máxima de WPA-PSK (estándar: 63 caracteres).
    """

    def __init__(
        self,
        max_batch_1: int = 5_000,
        max_batch_2: int = 2_000,
        min_length: int = 8,
        max_length: int = 63,
    ) -> None:
        self.max_batch_1 = max_batch_1
        self.max_batch_2 = max_batch_2
        self.min_length = min_length
        self.max_length = max_length

    def _valid(self, candidate: str, seen: Set[str]) -> bool:
        return (
            bool(candidate)
            and self.min_length <= len(candidate) <= self.max_length
            and candidate not in seen
        )

    def generate(
        self,
        ssid: str,
        bssid: str = "",
        brand: str = "",
        family_keys: Optional[Dict[str, str]] = None,
    ) -> CandidateSet:
        """
        Genera un CandidateSet para el AP especificado.

        Parámetros
        ──────────
        ssid        : Nombre de la red objetivo.
        bssid       : Dirección MAC del AP (se usa para extraer sufijos numéricos).
        brand       : Fabricante detectado (Askey, Huawei, TP-Link, …).
        family_keys : Diccionario {ssid_hermano: clave_crackeada} de APs de la
                      misma familia. Permite reutilización y mutación de claves.
        """
        ssid = (ssid or "").strip()
        bssid = (bssid or "").strip()
        brand = (brand or "").strip().lower()
        family_keys = family_keys or {}

        result = CandidateSet(ssid=ssid, bssid=bssid)
        my_base = _ssid_family_base(ssid).lower()
        seen: Set[str] = set()

        def add_b1(c: str) -> bool:
            if self._valid(c, seen) and len(result.batch_1) < self.max_batch_1:
                seen.add(c)
                result.batch_1.append(c)
                return True
            return False

        # ── [A] Claves exactas de APs hermanos (reutilización directa) ──────
        exact_count = 0
        for sib_ssid, key in family_keys.items():
            if sib_ssid == ssid or not key:
                continue
            if _ssid_family_base(sib_ssid).lower() != my_base:
                continue
            if add_b1(key):
                exact_count += 1

        # ── [B] Bases del SSID con variantes de capitalización ───────────────
        bases = [ssid, _ssid_family_base(ssid)]
        all_bases: List[str] = []
        for b in bases:
            for v in _case_variants(b):
                if v not in all_bases:
                    all_bases.append(v)

        base_only_count = 0
        for b in all_bases:
            if add_b1(b):
                base_only_count += 1

        # ── [C] Combinación Exacta: Base + Separador + (Año | Token) ─────────
        # Lógica núcleo: "números + letras = la combinación exacta"
        combined_count = 0
        isp_tails = NUMERIC_TAILS + DEPLOYMENT_YEARS + ISP_TOKENS
        if brand and brand not in isp_tails:
            isp_tails.append(brand)

        for base in all_bases:
            for sep in SEPARATORS:
                for tail in isp_tails:
                    if add_b1(f"{base}{sep}{tail}"):
                        combined_count += 1
                    # Patrón corporativo ISP: base@año@ (muy frecuente en HGUs)
                    if sep == "@":
                        if tail in DEPLOYMENT_YEARS:
                            add_b1(f"{base}@{tail}@")

        # ── [D] Fragmentos de BSSID combinados con la base ───────────────────
        bssid_count = 0
        if bssid:
            for frag in _bssid_fragments(bssid):
                for base in all_bases[:2]:
                    for c in (f"{base}{frag}", f"{base}_{frag}", f"{base}-{frag}"):
                        if add_b1(c):
                            bssid_count += 1

        # ── [E] Tokens genéricos de cierre (red flags mínimas) ───────────────
        for generic in (
            "password", "12345678", "87654321", "admin1234",
            "wifi1234", "qwerty123", "internet1", "contrasena",
        ):
            add_b1(generic)

        # ── [F] batch_2: Mutaciones de claves de APs hermanos ────────────────
        mut_count = 0
        for sib_ssid, key in family_keys.items():
            if sib_ssid == ssid or not key or len(key) < 4:
                continue
            if _ssid_family_base(sib_ssid).lower() != my_base:
                continue
            for m in _mutate_key(key):
                if (self._valid(m, seen)
                        and m not in result.batch_2
                        and len(result.batch_2) < self.max_batch_2):
                    seen.add(m)
                    result.batch_2.append(m)
                    mut_count += 1

        # ── Metadata del proceso ──────────────────────────────────────────────
        result.meta = {
            "ssid_family_base": my_base,
            "batch_1_total": len(result.batch_1),
            "batch_2_total": len(result.batch_2),
            "sources": {
                "family_exact_reuse": exact_count,
                "ssid_base_only": base_only_count,
                "combined_base_sep_tail": combined_count,
                "bssid_fragments": bssid_count,
                "family_mutations": mut_count,
            },
        }

        return result


# ─── API de conveniencia ───────────────────────────────────────────────────────

def generate_candidates(
    ssid: str,
    bssid: str = "",
    brand: str = "",
    family_keys: Optional[Dict[str, str]] = None,
    max_candidates: int = 5_000,
) -> CandidateSet:
    """
    Función de conveniencia para generar candidatos PSK sin instanciar directamente
    `CandidateGenerator`.

    Uso típico desde runner.py / wifit4:
        cs = generate_candidates(ssid="MiRed", bssid="AC:CC:8A:XX:XX:XX",
                                  brand="Askey", family_keys=known_psks)
        with open("wordlist.txt", "w") as f:
            f.write(cs.to_wordlist_lines())
    """
    gen = CandidateGenerator(max_batch_1=max_candidates)
    return gen.generate(ssid=ssid, bssid=bssid, brand=brand, family_keys=family_keys)
