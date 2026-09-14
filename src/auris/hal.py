"""
AURIS / Wifite4 — hal.py
Hardware Abstraction Layer (HAL) en espacio de usuario.

Objetivo de diseño
──────────────────
Proporcionar una interfaz abstracta y desacoplada para controlar
adaptadores WiFi USB *sin* depender de:
  - controladores del kernel Linux (nl80211 / mac80211),
  - binarios externos (airmon-ng, ip link, iw),
  - NDIS en Windows.

La capa HAL habla directamente con el firmware del chipset USB mediante
PyUSB / libusb-1.0.  Cada chipset soportado implementa `WirelessTransceiver`
y se registra en el `CHIPSET_REGISTRY`.

Estado actual
─────────────
• `WirelessTransceiver`   — Protocolo (interfaz abstracta, tipo-segura).
• `Dot11Frame`            — Contenedor de trama 802.11 capturada.
• `USBAdapterInfo`        — Metadatos de un adaptador conectado.
• `USBDeviceEnumerator`   — Detecta adaptadores USB soportados.
• `StubbedTransceiver`    — Implementación stub para pruebas sin hardware.
• `CHIPSET_REGISTRY`      — Registro extensible de pares (VID, PID) → chipset.

Próximos pasos (contribución Open Source / Wifite4)
────────────────────────────────────────────────────
Implementar `WirelessTransceiver` para cada chipset listado en el registro:
  - Atheros AR9271   → sub-módulo `hal_ar9271.py`
  - MediaTek MT7612U → sub-módulo `hal_mt7612u.py`
  - Realtek RTL8812AU → sub-módulo `hal_rtl8812au.py`

Esto permite que Wifite4 opere en Windows y macOS de forma nativa
sin necesidad de distribuciones especializadas (Kali / Parrot).

Ref: derv82/wifit3 — arquitectura USB userland
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Protocol, Tuple, runtime_checkable

# ─── Modelos de datos ─────────────────────────────────────────────────────────

@dataclass
class Dot11Frame:
    """Trama 802.11 capturada normalizada."""
    timestamp: float          # epoch UTC
    channel: int              # canal 802.11 (1-14 para 2.4 GHz; 36-177 para 5 GHz)
    raw_bytes: bytes          # payload IEEE 802.11 completo
    rssi: int = 0             # potencia de señal recibida en dBm (negativo)
    adapter_id: str = ""      # identificador del adaptador que capturó la trama

    @property
    def frame_type(self) -> str:
        """Tipo de trama: Management / Control / Data / Extension."""
        if len(self.raw_bytes) < 2:
            return "Unknown"
        fc = self.raw_bytes[0] & 0x0C
        return {0x00: "Management", 0x04: "Control", 0x08: "Data", 0x0C: "Extension"}.get(fc, "Unknown")

    @property
    def frame_subtype(self) -> int:
        """Sub-tipo de trama (0-15)."""
        return (self.raw_bytes[0] >> 4) & 0x0F if self.raw_bytes else -1


@dataclass
class USBAdapterInfo:
    """Metadatos de un adaptador USB inalámbrico detectado."""
    vendor_id: int            # USB VID
    product_id: int           # USB PID
    chipset: str              # Nombre técnico del chipset (ej. "Realtek RTL8812AU")
    bus: int = 0
    address: int = 0
    product_name: str = ""    # Nombre del producto tal como lo expone el descriptor USB
    manufacturer: str = ""    # Fabricante según descriptor USB
    supports_monitor: bool = True
    supports_injection: bool = True
    bands: List[str] = field(default_factory=lambda: ["2.4GHz"])

    @property
    def usb_id(self) -> str:
        return f"{self.vendor_id:04X}:{self.product_id:04X}"

    def __str__(self) -> str:
        bands_str = " + ".join(self.bands)
        return f"[{self.usb_id}] {self.chipset} ({bands_str}) — {self.product_name}"


# ─── Protocolo / Interfaz abstracta ──────────────────────────────────────────

@runtime_checkable
class WirelessTransceiver(Protocol):
    """
    Contrato que debe cumplir cada controlador USB en espacio de usuario.

    Diseñado como `typing.Protocol` para que las implementaciones no necesiten
    heredar de una clase base; basta con que implementen los métodos correctamente.
    """

    adapter_info: USBAdapterInfo

    def open_device(self) -> None:
        """
        Inicializa el endpoint USB y carga micro-firmware si el chipset lo requiere.
        Lanza `RuntimeError` si el dispositivo no puede abrirse.
        """
        ...

    def set_channel(self, channel: int) -> None:
        """
        Sintoniza la frecuencia de radio.
        - Canales 1-14 → 2.4 GHz
        - Canales 36, 40, 44 … 177 → 5 GHz
        Lanza `ValueError` si el canal no es soportado por el chipset.
        """
        ...

    def read_frames(self, timeout_ms: int = 100) -> Iterator[Dot11Frame]:
        """
        Captura tramas en el canal actual sin pasar por el stack del SO.
        Devuelve un iterador; puede estar vacío si no hay tráfico en el timeout.
        """
        ...

    def inject_frame(self, frame_bytes: bytes) -> bool:
        """
        Transmite una trama raw 802.11 directamente a través del hardware.
        Retorna True si el chipset confirma la transmisión.
        """
        ...

    def close_device(self) -> None:
        """Libera la interfaz USB y restaura el estado del dispositivo."""
        ...


# ─── Registro de chipsets soportados ──────────────────────────────────────────
#
# Formato: (VendorID, ProductID) → metadatos del chipset
# Fuente de referencia: wifit3 README / Linux USB IDs database
#
# Para añadir soporte de un nuevo chipset al ecosistema Open Source:
#   1. Agregar su entrada aquí con VID:PID correctos.
#   2. Crear `hal_<chipset>.py` que implemente `WirelessTransceiver`.
#   3. Registrar la fábrica en `_CHIPSET_FACTORIES` (más abajo).
#   4. Abrir un Pull Request en el repositorio principal.

CHIPSET_REGISTRY: Dict[Tuple[int, int], USBAdapterInfo] = {
    # ── Atheros ──────────────────────────────────────────────────────────────
    (0x0CF3, 0x9271): USBAdapterInfo(
        vendor_id=0x0CF3, product_id=0x9271,
        chipset="Atheros AR9271",
        product_name="ALFA AWUS036NHA / TP-Link TL-WN722N v1",
        manufacturer="Atheros / Qualcomm",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz"],
    ),
    # ── MediaTek ─────────────────────────────────────────────────────────────
    (0x0E8D, 0x7610): USBAdapterInfo(
        vendor_id=0x0E8D, product_id=0x7610,
        chipset="MediaTek MT7610U",
        product_name="ALFA AWUS036ACHM / Panda PAU0B",
        manufacturer="MediaTek",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz", "5GHz"],
    ),
    (0x0E8D, 0x7612): USBAdapterInfo(
        vendor_id=0x0E8D, product_id=0x7612,
        chipset="MediaTek MT7612U",
        product_name="ALFA AWUS036ACM",
        manufacturer="MediaTek",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz", "5GHz"],
    ),
    (0x0E8D, 0x7921): USBAdapterInfo(
        vendor_id=0x0E8D, product_id=0x7921,
        chipset="MediaTek MT7921AU",
        product_name="ALFA AWUS036AXML / Panda PAU0F",
        manufacturer="MediaTek",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz", "5GHz"],
    ),
    (0x0E8D, 0x7925): USBAdapterInfo(
        vendor_id=0x0E8D, product_id=0x7925,
        chipset="MediaTek MT7925U",
        product_name="Netgear A9000",
        manufacturer="MediaTek",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz", "5GHz"],
    ),
    # ── Realtek ──────────────────────────────────────────────────────────────
    (0x0BDA, 0x8812): USBAdapterInfo(
        vendor_id=0x0BDA, product_id=0x8812,
        chipset="Realtek RTL8812AU",
        product_name="ALFA AWUS036ACH",
        manufacturer="Realtek",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz", "5GHz"],
    ),
    (0x0BDA, 0x8814): USBAdapterInfo(
        vendor_id=0x0BDA, product_id=0x8814,
        chipset="Realtek RTL8814AU",
        product_name="ALFA AWUS1900",
        manufacturer="Realtek",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz", "5GHz"],
    ),
    (0x0BDA, 0x8821): USBAdapterInfo(
        vendor_id=0x0BDA, product_id=0x8821,
        chipset="Realtek RTL8821AU",
        product_name="ALFA AWUS036ACS / TP-Link Archer T2U",
        manufacturer="Realtek",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz", "5GHz"],
    ),
    (0x0BDA, 0x8822): USBAdapterInfo(
        vendor_id=0x0BDA, product_id=0x8822,
        chipset="Realtek RTL8822BU",
        product_name="TP-Link T3U Plus / Archer T4U v3",
        manufacturer="Realtek",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz", "5GHz"],
    ),
    (0x0BDA, 0x8187): USBAdapterInfo(
        vendor_id=0x0BDA, product_id=0x8187,
        chipset="Realtek RTL8187L",
        product_name="ALFA AWUS036H",
        manufacturer="Realtek",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz"],
    ),
    (0x0BDA, 0x8179): USBAdapterInfo(
        vendor_id=0x0BDA, product_id=0x8179,
        chipset="Realtek RTL8188EUS",
        product_name="TP-Link TL-WN722N v2/v3",
        manufacturer="Realtek",
        supports_monitor=True, supports_injection=False,  # v2/v3: sin inyección nativa
        bands=["2.4GHz"],
    ),
    (0x0BDA, 0xC811): USBAdapterInfo(
        vendor_id=0x0BDA, product_id=0xC811,
        chipset="Realtek RTL8821CU",
        product_name="Auscoumer 600 Mbps",
        manufacturer="Realtek",
        supports_monitor=True, supports_injection=True,
        bands=["2.4GHz", "5GHz"],
    ),
}


# ─── Enumerador de adaptadores ────────────────────────────────────────────────

class USBDeviceEnumerator:
    """
    Detecta adaptadores USB inalámbricos soportados conectados al sistema.

    Utiliza PyUSB (backend libusb-1.0) si está disponible.
    En entornos sin libusb (ej. Windows sin WinUSB), registra el estado
    y proporciona retroalimentación clara al usuario.
    """

    def __init__(self) -> None:
        self._pyusb_available: Optional[bool] = None
        self._libusb_available: Optional[bool] = None

    def probe_dependencies(self) -> Dict[str, bool]:
        """Comprueba la disponibilidad de PyUSB y libusb-1.0."""
        result: Dict[str, bool] = {}
        try:
            import usb.core  # type: ignore
            import usb.backend.libusb1  # type: ignore
            backend = usb.backend.libusb1.get_backend()
            result["pyusb"] = True
            result["libusb1"] = backend is not None
        except ImportError:
            result["pyusb"] = False
            result["libusb1"] = False
        self._pyusb_available = result["pyusb"]
        self._libusb_available = result.get("libusb1", False)
        return result

    def enumerate(self) -> List[USBAdapterInfo]:
        """
        Devuelve la lista de adaptadores soportados detectados.

        Si PyUSB no está disponible, retorna lista vacía con una advertencia
        en lugar de lanzar excepción (comportamiento degradable).
        """
        deps = self.probe_dependencies()
        if not deps["pyusb"] or not deps["libusb1"]:
            return []

        import usb.core
        import usb.backend.libusb1

        found: List[USBAdapterInfo] = []
        backend = usb.backend.libusb1.get_backend()

        for (vid, pid), info in CHIPSET_REGISTRY.items():
            devices = list(usb.core.find(idVendor=vid, idProduct=pid,
                                         find_all=True, backend=backend) or [])
            for dev in devices:
                entry = USBAdapterInfo(
                    vendor_id=info.vendor_id,
                    product_id=info.product_id,
                    chipset=info.chipset,
                    bus=getattr(dev, "bus", 0),
                    address=getattr(dev, "address", 0),
                    product_name=info.product_name,
                    manufacturer=info.manufacturer,
                    supports_monitor=info.supports_monitor,
                    supports_injection=info.supports_injection,
                    bands=list(info.bands),
                )
                found.append(entry)
        return found


# ─── Implementación stub para pruebas sin hardware ─────────────────────────────

class StubbedTransceiver:
    """
    Implementación stub de `WirelessTransceiver` para pruebas unitarias
    y entornos sin adaptador USB físico.

    Emite tramas sintéticas a partir de una lista inyectada en el constructor.
    Permite validar el pipeline de AURIS sin hardware real.
    """

    def __init__(self, synthetic_frames: Optional[List[Dot11Frame]] = None) -> None:
        self.adapter_info = USBAdapterInfo(
            vendor_id=0x0000, product_id=0x0000,
            chipset="Stub (no hardware)",
            product_name="Stub Transceiver (testing only)",
            supports_monitor=True, supports_injection=False,
        )
        self._frames: List[Dot11Frame] = synthetic_frames or []
        self._open = False
        self._channel: int = 1

    def open_device(self) -> None:
        self._open = True

    def set_channel(self, channel: int) -> None:
        if not 1 <= channel <= 177:
            raise ValueError(f"Canal inválido: {channel}")
        self._channel = channel

    def read_frames(self, timeout_ms: int = 100) -> Iterator[Dot11Frame]:
        """Devuelve los frames sintéticos del canal actual y espera el timeout."""
        time.sleep(timeout_ms / 1000)
        for frame in self._frames:
            if frame.channel == self._channel:
                yield frame

    def inject_frame(self, frame_bytes: bytes) -> bool:
        """Stub: siempre retorna False (sin hardware de inyección)."""
        return False

    def close_device(self) -> None:
        self._open = False


# ─── Utilidades públicas ───────────────────────────────────────────────────────

def detect_adapters() -> List[USBAdapterInfo]:
    """
    Punto de entrada principal para detectar adaptadores USB soportados.
    Retorna lista (puede ser vacía si no hay PyUSB o hardware compatible).
    """
    return USBDeviceEnumerator().enumerate()


def hal_status_report() -> Dict[str, object]:
    """
    Genera un reporte de estado del HAL: dependencias, adaptadores detectados.
    Útil para el comando `auris doctor` y diagnósticos en laboratorio.
    """
    enumerator = USBDeviceEnumerator()
    deps = enumerator.probe_dependencies()
    adapters = enumerator.enumerate() if all(deps.values()) else []

    return {
        "dependencies": deps,
        "adapters_found": len(adapters),
        "adapters": [str(a) for a in adapters],
        "chipsets_in_registry": len(CHIPSET_REGISTRY),
        "userland_capable": all(deps.values()) and len(adapters) > 0,
    }
