from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import datetime


class TargetInfo(BaseModel):
    bssid: str
    ssid: str
    channel: int
    encryption: str
    wps_enabled: bool
    wps_version: Optional[str] = None
    wps_locked: bool = False       # Indica si el AP tiene un mecanismo de bloqueo activo
    oui: str
    signal_strength: int
    brand: Optional[str] = None
    wpa3_supported: bool = False   # Detección de SAE (Simultaneous Authentication of Equals)
    dpp_supported: bool = False    # Detección de Device Provisioning Protocol (Easy Connect)
    # ── Campos añadidos: metadatos WPS extraídos de beacons (Wifite4 / HAL) ──
    wps_manufacturer: Optional[str] = None   # TLV 0x1021 del IE WPS
    wps_model_number: Optional[str] = None   # TLV 0x1024 del IE WPS
    wps_device_name: Optional[str] = None    # TLV 0x1011 del IE WPS
    wps_pbc_active: bool = False             # True cuando se detecta botón PBC presionado


class WidsAlert(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    alert_type: str
    severity: str
    source_mac: str
    dest_mac: str
    channel: int
    frame_count: int
    details: dict = {}


class ThreatModelSTRIDE(BaseModel):
    spoofing: int = 0
    tampering: int = 0
    repudiation: int = 0
    information_disclosure: int = 0
    denial_of_service: int = 0
    elevation_of_privilege: int = 0

    @property
    def total_risk(self) -> int:
        return sum([self.spoofing, self.tampering, self.repudiation,
                    self.information_disclosure, self.denial_of_service,
                    self.elevation_of_privilege])


class AURISScore(BaseModel):
    crypto_score: int = 0      # 0-25
    config_score: int = 0      # 0-25
    governance_score: int = 0  # 0-25
    resilience_score: int = 0  # 0-25

    @property
    def total_score(self) -> int:
        return (self.crypto_score + self.config_score
                + self.governance_score + self.resilience_score)


class Profile(BaseModel):
    brand: str
    model: Optional[str] = None
    pin_class: str = "unknown"
    isp_locked_fw: bool = False
    last_fw_known: Optional[str] = None


# ── Modelos nuevos: subsistema HAL (Hardware Abstraction Layer) ────────────────

class HALStatus(BaseModel):
    """
    Estado del subsistema HAL USB en el sistema actual.

    Indica si las dependencias de userland (PyUSB / libusb-1.0) están
    disponibles y cuántos adaptadores soportados hay conectados.
    En ausencia de PyUSB, AURIS degrada a los binarios clásicos del sistema.
    """
    pyusb_available: bool = False
    libusb1_available: bool = False
    adapters_found: int = 0
    adapter_descriptions: List[str] = Field(default_factory=list)
    chipsets_in_registry: int = 0
    userland_capable: bool = False   # True sólo si PyUSB + libusb + ≥1 adaptador

    @property
    def summary(self) -> str:
        if self.userland_capable:
            return (f"HAL activo — {self.adapters_found} adaptador(es) USB soportado(s); "
                    "modo userland disponible (sin kernel/NDIS)")
        if self.pyusb_available and not self.libusb1_available:
            return "HAL parcial — PyUSB instalado pero libusb-1.0 no encontrado"
        if not self.pyusb_available:
            return "HAL no disponible — PyUSB ausente; AURIS usa herramientas del sistema"
        return f"HAL iniciado — {self.adapters_found} adaptador(es) detectados"


class WPSInfo(BaseModel):
    """
    Metadatos completos extraídos del Information Element (IE) WPS
    de un beacon o probe response.

    Los campos corresponden a los TLVs definidos en la especificación WPS
    (Wi-Fi Protected Setup) de la Wi-Fi Alliance.
    Fuente: IEEE 802.11 / WFA WPS Technical Spec v2.0.
    """
    version: Optional[str] = None           # TLV 0x104A: versión WPS (ej. "1.0", "2.0")
    state: Optional[str] = None             # TLV 0x1044: "Configured" / "Not Configured"
    ap_setup_locked: bool = False           # TLV 0x1057: True si el AP bloqueó el registro
    uuid: Optional[str] = None             # TLV 0x1047: UUID-E del registrar
    manufacturer: Optional[str] = None     # TLV 0x1021: Fabricante (ej. "Askey Computer Corp.")
    model_name: Optional[str] = None       # TLV 0x1023: Nombre de modelo (ej. "RTF3505VW")
    model_number: Optional[str] = None     # TLV 0x1024: Número de modelo (ej. "1.0.0")
    serial_number: Optional[str] = None    # TLV 0x1042: Número de serie (cuando está presente)
    device_name: Optional[str] = None      # TLV 0x1011: Nombre del dispositivo visible
    primary_device_type: Optional[str] = None  # TLV 0x1054: Categoría (ej. "Network Infrastructure")
    rf_bands: Optional[str] = None         # TLV 0x103C: "2.4GHz", "5GHz", "both"
    config_methods: Optional[str] = None   # TLV 0x1008: métodos (PBC, PIN, NFC, …)
    selected_registrar: bool = False        # TLV 0x1041: True cuando PBC está activo
    pbc_active: bool = False               # Derivado: True si selected_registrar=True y config_methods include PBC

    @property
    def vendor_fingerprint(self) -> str:
        """Huella del fabricante para cruzar con la base de conocimiento."""
        parts = [p for p in (self.manufacturer, self.model_name, self.model_number) if p]
        return " | ".join(parts) if parts else "Unknown"


class PBCEvent(BaseModel):
    """
    Evento de pulsación del botón WPS PushButton Connect (PBC).

    Cuando un usuario o administrador presiona el botón WPS físico del router,
    el AP activa el flag `Selected Registrar` en sus beacons durante ~120 segundos.
    Durante ese ventana, es posible completar el intercambio WPS sin PIN,
    obteniendo la PSK en texto claro.

    Este modelo documenta la detección del evento y la evidencia capturada.
    Uso en AURIS: se registra como hallazgo con severidad Media/Alta dependiendo
    de si el router tiene WPS v1.0 (también vulnerable a PixieDust).
    """
    timestamp: datetime = Field(default_factory=datetime.now)
    bssid: str
    ssid: str
    channel: int
    wps_version: Optional[str] = None
    window_seconds: int = 120      # Duración estándar de la ventana PBC
    psk_extracted: bool = False    # True si se completó el intercambio y se obtuvo la PSK
    psk_value: Optional[str] = None   # Solo en contexto de lab con autorización escrita
    evidence_file: Optional[str] = None  # Ruta al .pcapng con la captura del intercambio

    @property
    def severity(self) -> str:
        """Severidad del hallazgo según las condiciones observadas."""
        if self.psk_extracted:
            return "High"
        return "Medium"

    @property
    def cwe_id(self) -> str:
        """CWE más representativo del riesgo documentado."""
        return "CWE-287"   # Improper Authentication (WPS PBC no requiere secreto compartido)

    @property
    def finding_title(self) -> str:
        return "WPS PushButton activo — ventana de autenticación sin PIN detectada"

