"""
AURIS / Wifite4 — wids.py
Wireless Intrusion Detection Sensor (WIDS).

Modo actual: SIMULADO
─────────────────────
Las alertas actuales son sintéticas (probabilidad aleatoria cada 2 s).
El informe las etiqueta explícitamente como [SIMULATED] para no inducir
a error al investigador o al docente que revise los resultados.

Hoja de ruta (contribución Open Source / Wifite4)
──────────────────────────────────────────────────
La integración con la capa HAL (hal.py / WirelessTransceiver) permitirá
que el WIDS analice tramas reales capturadas en userland:

  Paso 1: Pasar un `WirelessTransceiver` al constructor.
  Paso 2: Leer `transceiver.read_frames()` en el hilo de monitoreo.
  Paso 3: Aplicar las reglas de detección sobre las tramas reales.
  Paso 4: Eliminar la generación aleatoria y marcar SIMULATED = False.

Adicionalmente, el método `detect_pbc_event()` prepara la detección del
botón WPS PushButton (PBC) en el flujo de tramas — capacidad de Wifite4.
"""

import time
import threading
import random
from datetime import datetime
from typing import Callable, List, Optional

from .terminal import console


class WIDSSensor:
    """
    Sensor de detección de intrusiones inalámbrico.

    Atributos de clase
    ──────────────────
    SIMULATED : bool
        Siempre True hasta que se integre la lectura de tramas reales
        mediante la capa HAL. Los informes consumen este flag para etiquetar
        correctamente las alertas generadas.
    """
    SIMULATED: bool = True  # Etiqueta honesta: alertas NO provienen de sniffing real

    # ── Tipos de alerta detectables (en modo simulado y futuro modo real) ────
    ALERT_TYPES = [
        "Deauth Flood",
        "WPS Brute Force",
        "PMKID Capture Attempt",
        "Probe Scan (Aggressive)",
        "Rogue AP (Evil Twin)",
        "PBC Window Open",          # WPS PushButton activo — nuevo en Wifite4
    ]

    def __init__(self, interface: str = "wlan1") -> None:
        self.interface = interface
        self._running: bool = False
        self._thread: Optional[threading.Thread] = None
        self.alerts: List[dict] = []
        self._callback: Optional[Callable[[dict], None]] = None

        # Hook para integración futura con HAL (WirelessTransceiver)
        # Cuando HAL esté disponible, asignar el transceptor aquí y leer
        # tramas reales en lugar de generar alertas sintéticas.
        # Ejemplo: self._transceiver = hal.StubbedTransceiver()
        self._transceiver = None   # type: ignore[assignment]

    def set_alert_callback(self, callback: Callable[[dict], None]) -> None:
        """Registra una función que se llama cada vez que se emite una alerta."""
        self._callback = callback

    def _emit_alert(self, alert: dict) -> None:
        """Registra y distribuye una alerta."""
        self.alerts.append(alert)
        if self._callback:
            self._callback(alert)

    # ── Modo simulado ──────────────────────────────────────────────────────────

    def _simulate_monitoring(self) -> None:
        """
        Bucle de monitoreo simulado.

        Probabilidad del 10 % cada 2 s de emitir una alerta sintética.
        El campo `simulated: True` garantiza que el informe no confunda
        estas alertas con detecciones reales de tráfico de radio.
        """
        while self._running:
            time.sleep(2)
            if random.random() < 0.10:
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": random.choice(self.ALERT_TYPES),
                    "severity": random.choice(["Low", "Medium", "High"]),
                    "source_mac": "00:AA:BB:CC:DD:EE",
                    "dest_mac": "FF:FF:FF:FF:FF:FF",
                    "channel": random.randint(1, 13),
                    "simulated": True,   # ← campo clave: identifica origen sintético
                }
                self._emit_alert(alert)

    # ── Detección de PBC (WPS PushButton) — Wifite4 ───────────────────────────

    def detect_pbc_event(self, bssid: str, ssid: str, channel: int) -> Optional[dict]:
        """
        Detecta si un AP tiene el flag WPS PushButton activo (Selected Registrar).

        En modo real (con HAL conectado): lee beacons del AP y busca el TLV
        `Selected Registrar` (0x1041) con valor True en el IE WPS.

        En modo actual (sin HAL): método preparado pero no operativo.
        Retorna None hasta que se integre la capa HAL.

        Cuando se detecte un evento PBC, se registra automáticamente como
        alerta "PBC Window Open" con severidad "High" y se genera un
        `PBCEvent` (models.PBCEvent) para el informe de hallazgos.
        """
        # TODO (Wifite4 contribución): integrar lectura de beacons desde
        # self._transceiver.read_frames() y parsear el IE WPS para buscar
        # el TLV Selected Registrar (0x1041).
        #
        # Ejemplo de lógica futura:
        #   for frame in self._transceiver.read_frames(timeout_ms=500):
        #       if frame.frame_subtype == 8:  # Beacon
        #           wps_ie = parse_wps_ie(frame.raw_bytes)
        #           if wps_ie and wps_ie.selected_registrar:
        #               alert = { "alert_type": "PBC Window Open", ... }
        #               self._emit_alert(alert)
        #               return alert
        return None  # Retorna None mientras HAL no esté conectado

    # ── Control del sensor ─────────────────────────────────────────────────────

    def start(self) -> None:
        """Inicia el sensor. Si HAL no está disponible, usa modo simulado."""
        if self._running:
            return
        self._running = True

        if self._transceiver is not None:
            # Modo real (futuro): iniciar hilo de lectura HAL
            # self._thread = threading.Thread(target=self._real_monitoring, daemon=True)
            console.print(f"  [blue]◉ WIDS[/blue] [dim]en {self.interface} (modo HAL real)[/dim]")
        else:
            # Modo actual: simulado con alertas sintéticas
            self._thread = threading.Thread(target=self._simulate_monitoring, daemon=True)
            self._thread.start()
            console.print(
                f"  [blue]◉ WIDS [SIMULADO][/blue] "
                f"[dim]en {self.interface} (tráfico sintético — sin sniffing real)[/dim]"
            )

    def stop(self) -> None:
        """Detiene el sensor limpiamente."""
        if not self._running:
            return
        self._running = False
        if self._thread:
            self._thread.join(timeout=1.0)
        console.print("  [dim]◉ WIDS detenido[/dim]")

    def get_alerts(self) -> List[dict]:
        """Retorna todas las alertas registradas en esta sesión."""
        return list(self.alerts)

    def get_alerts_by_type(self, alert_type: str) -> List[dict]:
        """Filtra alertas por tipo."""
        return [a for a in self.alerts if a.get("alert_type") == alert_type]

    @property
    def real_alerts(self) -> List[dict]:
        """Sólo alertas reales (no simuladas). Vacío hasta integración HAL."""
        return [a for a in self.alerts if not a.get("simulated", True)]

