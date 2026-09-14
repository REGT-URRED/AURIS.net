"""
AURIS — phases/base.py
Contrato de fase (PhaseProtocol) y contenedor de resultado (PhaseResult).

Por qué existe este módulo
──────────────────────────
El problema original de runner.py es que mezcla el contrato de ejecución de
una fase, la lógica de cada fase, el orquestador y la persistencia — todo en
un solo archivo de 980 líneas. Eso es código espagueti: cualquier cambio en
una fase puede romper el orquestador, y el orquestador no puede testearse sin
ejecutar todo.

La solución es establecer un CONTRATO ÚNICO que todas las fases cumplen:
  1. Cada fase es una clase independiente.
  2. Recibe exactamente lo que necesita (no "scope" global ni "todo").
  3. Devuelve un PhaseResult tipado y predecible.
  4. El orquestador (pipeline.py) sólo sabe del contrato, no de la implementación.

Esto permite:
  - Testear cada fase en aislamiento con un stub de herramienta.
  - Añadir nuevas fases sin tocar el orquestador.
  - Reemplazar una fase (ej. reaver → hal.WirelessTransceiver) sin efectos laterales.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable


# ─── Resultado estándar de cualquier fase ─────────────────────────────────────

# Valores canónicos del campo `status`. Usar SÓLO estos valores en todas las fases.
STATUS_CRACKED          = "cracked"           # credencial PSK/PIN obtenida
STATUS_CLASS_CONFIRMED  = "class_confirmed"   # clase de vulnerabilidad confirmada
STATUS_EOL_CONFIRMED    = "eol_confirmed"     # brecha de firmware EOL documentada
STATUS_CAPTURED         = "captured"          # material de captura (pcap/hash) obtenido
STATUS_LOCKED           = "locked"            # AP detectó lockout / rate-limit → STOP
STATUS_NOT_FOUND        = "not_found"         # fase completada sin resultado útil
STATUS_TIMEOUT          = "timeout"           # fase expiró su presupuesto de tiempo
STATUS_SKIPPED          = "skipped"           # fase omitida (herramienta ausente o condición)
STATUS_EXHAUSTED        = "exhausted"         # wordlist o espacio de búsqueda agotado sin éxito
STATUS_DONE             = "done"              # fase informativa completada
STATUS_ERROR            = "error"             # excepción inesperada





@dataclass
class PhaseResult:
    """
    Resultado normalizado de la ejecución de una fase.

    Todos los campos son inmutables una vez creado el objeto.
    El orquestador (pipeline.py) consume sólo esta estructura;
    no sabe cómo la produjo la fase.

    Campos
    ──────
    phase_name  : Nombre canónico de la fase (ej. "CAPTURE_PMKID").
    status      : Uno de los STATUS_* definidos arriba.
    credential  : Clave o PIN recuperado en texto claro (solo en lab autorizado).
    cred_type   : Descripción del tipo de credencial (ej. "WPS Pixie Dust").
    detail      : Mensaje corto para el log / terminal. Nunca vuelca secretos.
    elapsed_sec : Segundos reales que tardó la fase.
    evidence    : Ruta(s) al archivo de evidencia generado (pcapng, json…).
    """
    phase_name:  str
    status:      str
    credential:  Optional[str] = None
    cred_type:   Optional[str] = None
    detail:      str = ""
    elapsed_sec: float = 0.0
    evidence:    list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """True para resultados que producen material útil para el informe."""
        return self.status in (
            STATUS_CRACKED, STATUS_CLASS_CONFIRMED,
            STATUS_EOL_CONFIRMED, STATUS_CAPTURED, STATUS_DONE,
        )

    @property
    def is_lockout(self) -> bool:
        """True si el AP activó un mecanismo de bloqueo → el pipeline debe parar."""
        return self.status == STATUS_LOCKED

    def __str__(self) -> str:
        cred = f" [{self.cred_type}]" if self.cred_type else ""
        return f"[{self.phase_name}] {self.status}{cred} ({self.elapsed_sec:.1f}s)"


# ─── Contrato de fase ──────────────────────────────────────────────────────────

@runtime_checkable
class PhaseProtocol(Protocol):
    """
    Interfaz que toda fase debe implementar.

    Reglas de diseño
    ────────────────
    1. `name` es el identificador canónico que usa el decision_engine y el pipeline.
    2. `can_run()` verifica dependencias sin tocar el aire — se llama ANTES de run().
    3. `run()` ejecuta la fase y devuelve un PhaseResult. NUNCA lanza excepciones
       al orquestador; las captura internamente y retorna status=STATUS_ERROR.
    4. Una fase NO debe:
       - Llamar a otras fases.
       - Escribir al terminal directamente (usa `detail` en PhaseResult).
       - Importar módulos de otras fases.
    """

    name: str

    def can_run(self) -> bool:
        """
        Retorna True si la fase puede ejecutarse (herramientas disponibles,
        condiciones del target satisfechas). Si retorna False, el pipeline
        genera automáticamente un PhaseResult con status=STATUS_SKIPPED.
        """
        ...

    def run(self) -> PhaseResult:
        """
        Ejecuta la fase con todos los parámetros que recibió en el constructor.
        Debe respetar el timeout configurado y capturar todas las excepciones.
        """
        ...
