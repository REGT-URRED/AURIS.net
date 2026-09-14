"""
AURIS — Auditoría WiFi Secuencial
Versión: 2.1.0-wifite4

Paquete Python para investigación ética de seguridad inalámbrica en CPEs domésticos.

Módulos principales
───────────────────
cli             Interfaz de línea de comandos (Typer).
runner          Motor de ejecución secuencial (máquina de estados FSM).
scanner         Escaneo de redes WiFi (hcxdumptool > wash > airodump-ng).
decision_engine Motor de decisión STRIDE y árbol de caminos.
vendor_profiles Base de conocimiento offline de fabricantes y flotas ISP.
generator       Motor combinatorio inteligente de candidatos PSK (Wifite4).
hal             Hardware Abstraction Layer USB en userland (Wifite4).
wids            Sensor WIDS (actual: simulado; futuro: integración HAL).
models          Modelos de datos Pydantic (TargetInfo, Profile, STRIDE, HAL, WPS).
lan_audit       Auditoría de superficie LAN (solo lectura, solo laboratorio).
report_writer   Generador de informes Markdown/JSON multi-destinatario.
reporter        Clase Reporter de alto nivel.
roe             Validación de Rules of Engagement (scope.yml).
session         Gestión de sesión y directorio de ejecución.
monitor         Gestión de modo monitor de la interfaz inalámbrica.
terminal        Salida enriquecida (rich / spinners / tablas).
wordlists       Verificación y localización de diccionarios offline.
db              Base de datos SQLite local (vendors, runs, findings).
doctor          Verificación de dependencias del sistema.
"""

__version__ = "2.1.0-wifite4"
__author__ = "AURIS Research Project"
__license__ = "MIT"

# Exportaciones públicas para uso como librería
from .models import (
    TargetInfo,
    Profile,
    ThreatModelSTRIDE,
    AURISScore,
    WidsAlert,
    HALStatus,
    WPSInfo,
    PBCEvent,
)
from .generator import generate_candidates, CandidateGenerator, CandidateSet
from .hal import (
    detect_adapters,
    hal_status_report,
    CHIPSET_REGISTRY,
    USBAdapterInfo,
    Dot11Frame,
    StubbedTransceiver,
)

__all__ = [
    # Modelos
    "TargetInfo", "Profile", "ThreatModelSTRIDE", "AURISScore",
    "WidsAlert", "HALStatus", "WPSInfo", "PBCEvent",
    # Generator
    "generate_candidates", "CandidateGenerator", "CandidateSet",
    # HAL
    "detect_adapters", "hal_status_report", "CHIPSET_REGISTRY",
    "USBAdapterInfo", "Dot11Frame", "StubbedTransceiver",
    # Meta
    "__version__", "__author__", "__license__",
]
