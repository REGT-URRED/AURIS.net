# Lista de Tareas Visual (Tasklist)

Seguimiento del estado de tareas con alto contraste visual.

---

## Tareas Completadas

- [x] Agregar `LICENSE` MIT (el README ya lo declaraba)
- [x] Redactar propuesta de integración upstream (`docs/upstream/`)

- [x] Vendorizar broadcom-wps en `research/broadcom-wps/` con licencia y procedencia
- [x] Subcomando `auris broadcom` (uv o Python 3.11 + scapy)
- [x] Incluir `research/` en el paquete de campo y tests de integración
- [x] Suite de tests portable (sin fallos por Windows/bundle ausente)

- [x] Vendorizar ContextBase v1.0.0 en `tools/contextbase/` (sin npm, sin red)
- [x] Wrapper Linux `scripts/contextbase.sh` con validación de Node >= 18
- [x] Corregir `contextbase task done` (ReferenceError por variables sin declarar)
- [x] Añadir soporte OpenCode a `installSkill()`
- [x] Inicializar `contextbase/` con arquitectura real de AURIS.net
- [x] Inyectar reglas en `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.windsurfrules`
- [x] Integrar contextbase en `auris doctor`
- [x] Integrar `nodejs` + comando global en `setup.sh`
- [x] Incluir `nodejs` en el bundle offline (`scripts/bootstrap.sh`)
- [x] Incluir `contextbase/` y `tools/` en el paquete de campo (`scripts/pack.sh`)
- [x] Tests de integración de contextbase (`tests/test_contextbase.py`)
- [x] Documentar la integración en README y CHANGELOG

## Tareas Pendientes / En Progreso

- [ ] Autenticar GitHub (`gh auth login`) y hacer push de `main`
- [ ] Publicar el issue upstream en `qkaiser/broadcom-wps` con el texto de `docs/upstream/`

- [ ] Cablear `pipeline.py` (PhaseProtocol) en `runner.py` y retirar el dispatcher legacy
- [ ] Registrar `PSK_DEFAULTS` en `phases/__init__.py` (hoy solo en el camino legacy)
- [ ] Integrar `wids.py` a tramas reales del HAL y quitar `[SIMULATED]`
- [ ] Evaluar backend PyUSB para `WirelessTransceiver`
- [ ] Agregar CI Linux que corra `pytest` y `bash scripts/contextbase.sh status`
- [ ] Validar `setup.sh` completo en Kali limpia con el bundle regenerado

---

*Regla: marcar con `[x]` lo completado y agregar con `[ ]` cada requerimiento
nuevo. Actualizar también `changelog.md`.*
