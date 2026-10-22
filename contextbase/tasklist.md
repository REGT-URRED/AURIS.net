# Lista de Tareas Visual (Tasklist)

Seguimiento del estado de tareas con alto contraste visual.

---

## Tareas Completadas

- [x] Cadena de evaluación secuencial `BROADCOM_EVAL`: prepone el fingerprint
  Broadcom en las rutas WPS y salta las fases WPS cuando el AP está parcheado
- [x] Informe final: `## Contraseñas recuperadas`,
  `## Vulnerabilidades verificadas` y `reports/auris_<ts>_claves.txt`
- [x] Robustez del análisis: timeouts del fingerprinter, guardia de filas sin
  BSSID, motivo "señal desconocida", aviso único del mapa OUI, notas de render
- [x] Tests `tests/test_eval_chain.py` (14 casos). Suite: 160 passed, 14 skipped

- [x] Ranking autónomo de objetivos (`--auto`, `--top`) y enriquecimiento Broadcom
- [x] Tests de targeting (señal, WPS, cifrado, catálogo, top-N)

- [x] Catálogo offline de equipos Broadcom (`data/seed/broadcom_affected.csv`)
- [x] `auris broadcom` con modos `--lookup`, `--firmware` y fingerprint
- [x] Reporte de artefactos Broadcom en `auris doctor`
- [x] Tests de catálogo, parser YARA y orquestación del fingerprint

- [x] Push de `main` a `REGT-URRED/AURIS.net` (4 commits)
- [x] Issue upstream publicado: qkaiser/broadcom-wps#28
- [x] Agregar `LICENSE` MIT (el README ya lo declaraba)

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

- [ ] Cablear `pipeline.py` (PhaseProtocol) en `runner.py` — APLAZADO: la
  evaluación secuencial `BROADCOM_EVAL` se implementó directamente en el
  dispatcher de `runner.py`; fusionar el registry de `phases/` queda para una
  iteración futura de refactor
- [ ] Registrar `PSK_DEFAULTS` en `phases/__init__.py` — ya está en
  `ATTACK_PHASES` del dispatcher legacy de `runner.py`; la tarea queda solo
  para el registry de `phases/` cuando se cablee `pipeline.py`
- [ ] Integrar `wids.py` a tramas reales del HAL y quitar `[SIMULATED]`
- [ ] Evaluar backend PyUSB para `WirelessTransceiver`
- [ ] Agregar CI Linux que corra `pytest` y `bash scripts/contextbase.sh status`
- [ ] Validar `setup.sh` completo en Kali limpia con el bundle regenerado

---

*Regla: marcar con `[x]` lo completado y agregar con `[ ]` cada requerimiento
nuevo. Actualizar también `changelog.md`.*
