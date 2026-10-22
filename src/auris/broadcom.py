"""
AURIS — broadcom.py
Integración de la investigación Broadcom WPS (research/broadcom-wps).

Tres capacidades, todas offline salvo el escaneo RF explícito:

1. Catálogo de equipos afectados/parcheados (data/seed/broadcom_affected.csv),
   generado desde la tabla del README upstream.
2. Fingerprinter vendorizado: distingue wps_monitor de hostapd. Corre como
   subproceso (uv o Python 3.11+ con scapy); AURIS nunca importa scapy.
3. Reglas YARA sobre firmware extraído (binario `yara` del sistema).

No se explota nada: el resultado es evidencia de familia de implementación.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, List, Optional, Sequence, Tuple

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
BROADCOM_DIR = os.path.join(PROJECT_DIR, "research", "broadcom-wps")
SCRIPT = os.path.join(BROADCOM_DIR, "broadcom_fingerprint.py")
YARA_RULES = os.path.join(BROADCOM_DIR, "broadcom_wps_monitor.yar")
CATALOG = os.path.join(PROJECT_DIR, "data", "seed", "broadcom_affected.csv")

AFFECTED = "affected"
PATCHED = "patched"


class BroadcomError(RuntimeError):
    """Fallo de entorno o de entrada visible para el operador."""


@dataclass(frozen=True)
class BroadcomMatch:
    status: str
    vendor: str
    product: str
    versions: str = ""
    isps: str = ""


@dataclass(frozen=True)
class FingerprintRun:
    assessment: str
    implementation: str
    target_health: str
    bssid: str
    channel: object
    vendor: str
    model: str
    warning: Optional[str]
    evidence: Tuple[str, ...]
    json_path: Optional[str]
    pcap_path: Optional[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    path: str


def _key(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (text or "").casefold()).strip()


@lru_cache(maxsize=1)
def _catalog_rows() -> Tuple[dict, ...]:
    if not os.path.isfile(CATALOG):
        raise BroadcomError(f"catálogo Broadcom ausente: {CATALOG}")
    with open(CATALOG, newline="", encoding="utf-8") as handle:
        return tuple(dict(row) for row in csv.DictReader(handle))


def lookup(vendor: str, model: str = "") -> List[BroadcomMatch]:
    """Busca fabricante/modelo en el catálogo offline. Vacío = sin coincidencia."""
    if not _key(vendor):
        raise BroadcomError("indicá un fabricante (--lookup)")
    wanted_vendor = _key(vendor)
    wanted_model = _key(model)
    found: List[BroadcomMatch] = []
    for row in _catalog_rows():
        row_vendor = _key(row.get("vendor", ""))
        row_product = _key(row.get("product", ""))
        if wanted_vendor not in row_vendor and row_vendor not in wanted_vendor:
            continue
        if (
            wanted_model
            and wanted_model not in row_product
            and row_product not in wanted_model
        ):
            continue
        found.append(
            BroadcomMatch(
                status=row.get("status", ""),
                vendor=row.get("vendor", ""),
                product=row.get("product", ""),
                versions=row.get("versions", ""),
                isps=row.get("isps", ""),
            )
        )
    found.sort(key=lambda item: (item.status != AFFECTED, item.vendor, item.product))
    return found


def _interpreter_command(arguments: Sequence[str]) -> List[str]:
    if not os.path.isfile(SCRIPT):
        raise BroadcomError(f"fingerprinter ausente: {SCRIPT}")
    if shutil.which("uv"):
        return ["uv", "run", "--with", "scapy", SCRIPT, *arguments]
    if sys.version_info >= (3, 11):
        try:
            import scapy  # noqa: F401
        except ImportError as exc:
            raise BroadcomError(
                "falta scapy: pip install scapy (o instalá uv para un entorno efímero)"
            ) from exc
        return [sys.executable, SCRIPT, *arguments]
    raise BroadcomError("el fingerprinter requiere Python 3.11+ o uv")


def _run(command: Sequence[str], cwd: str):
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True)


def _report_field(stdout: str, name: str) -> Optional[str]:
    match = re.search(rf"^{name}:\s+(\S.*)$", stdout, re.MULTILINE)
    return match.group(1).strip() if match else None


def _tail(text: str, lines: int = 3) -> str:
    chunks = [line for line in (text or "").strip().splitlines() if line.strip()]
    return " | ".join(chunks[-lines:])


def fingerprint(
    interface: str,
    ssid: str,
    debug_assoc: bool = False,
    cwd: Optional[str] = None,
    runner: Optional[Callable[[Sequence[str], str], object]] = None,
) -> FingerprintRun:
    """
    Ejecuta el fingerprinter vendorizado y devuelve el assessment parseado.

    Los artefactos (result.json, traffic.pcap) quedan en un subdirectorio
    broadcom-fingerprint-<ts>/ dentro de `cwd` (por defecto evidence/).
    """
    if not interface or not ssid:
        raise BroadcomError("fingerprint requiere --interface y --ssid")
    encoded = ssid.encode("utf-8")
    if not 1 <= len(encoded) <= 32:
        raise BroadcomError("el SSID debe codificar entre 1 y 32 bytes UTF-8")

    workdir = cwd or os.path.join(PROJECT_DIR, "evidence")
    os.makedirs(workdir, exist_ok=True)
    arguments = ["--interface", interface, "--ssid", ssid]
    if debug_assoc:
        arguments.append("--debug-assoc")

    process = (runner or _run)(_interpreter_command(arguments), workdir)
    stdout = getattr(process, "stdout", "") or ""
    stderr = getattr(process, "stderr", "") or ""
    returncode = int(getattr(process, "returncode", 2))

    json_path = _report_field(stdout, "JSON")
    pcap_path = _report_field(stdout, "PCAP")
    document: dict = {}
    if json_path and os.path.isfile(json_path):
        try:
            with open(json_path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError):
            document = {}

    if not document and returncode not in (0, 1):
        raise BroadcomError(
            f"fingerprinter falló (rc={returncode}): {_tail(stderr) or _tail(stdout)}"
        )

    target = document.get("target") or {}
    identity = target.get("wps_identity") or {}
    assessment = (
        document.get("assessment")
        or _report_field(stdout, "Assessment")
        or "INCONCLUSIVE"
    )
    return FingerprintRun(
        assessment=str(assessment),
        implementation=str(document.get("implementation") or "INCONCLUSIVE"),
        target_health=str(document.get("target_health") or "UNKNOWN"),
        bssid=str(target.get("bssid") or _report_field(stdout, "BSSID") or "Unknown"),
        channel=target.get("channel", _report_field(stdout, "Channel") or "Unknown"),
        vendor=str(
            identity.get("vendor") or _report_field(stdout, "Vendor") or "Unknown"
        ),
        model=str(identity.get("model") or _report_field(stdout, "Model") or "Unknown"),
        warning=document.get("warning"),
        evidence=tuple(document.get("broadcom_sdk", {}).get("evidence") or ()),
        json_path=json_path,
        pcap_path=pcap_path,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def parse_yara_output(text: str) -> List[YaraMatch]:
    """Convierte la salida `regla ruta` de yara en objetos."""
    matches: List[YaraMatch] = []
    for line in (text or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        rule, path = parts
        if rule.startswith("error") or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*", rule
        ):
            continue
        # shortcut: rutas con espacios no se reportan; yara imprime "regla ruta"
        # sin delimitador mejor. Upgrade: `yara -s`/JSON si hace falta.
        if not path or " " in path:
            continue
        matches.append(YaraMatch(rule=rule, path=path))
    return matches


def scan_firmware(target: str) -> List[YaraMatch]:
    """Escanea un directorio/archivo de firmware con las reglas vendorizadas."""
    if not os.path.exists(target):
        raise BroadcomError(f"ruta de firmware inexistente: {target}")
    if not os.path.isfile(YARA_RULES):
        raise BroadcomError(f"reglas YARA ausentes: {YARA_RULES}")
    yara = shutil.which("yara")
    if not yara:
        raise BroadcomError("yara no instalado (sudo apt install yara)")
    process = subprocess.run(
        [yara, "-w", "-r", YARA_RULES, target],
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise BroadcomError(
            f"yara falló (rc={process.returncode}): {_tail(process.stderr)}"
        )
    return parse_yara_output(process.stdout)
