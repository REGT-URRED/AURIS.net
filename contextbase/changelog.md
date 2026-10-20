# Bitácora Histórica del Proyecto (Changelog)

Registro metódico del progreso técnico, las decisiones de arquitectura y la
evolución del sistema. Formato basado en Keep a Changelog.

---

## Cambios Realizados

### 2026-10-20 — Consolidación de broadcom-wps dentro de AURIS.net

- Se incorporó `research/broadcom-wps/` con el fingerprinter, las reglas YARA,
  el README upstream y la licencia MIT (commit `0727296`), más `VENDOR.md` con
  procedencia, uso y límites. Se descartaron cachés locales (`.atl/`,
  `.ruff_cache/`).
- Nuevo subcomando `auris broadcom --interface <mon> --ssid <ssid>`: delega en
  el script vendorizado, prefiriendo `uv run --with scapy` y cayendo a
  `python3 + scapy`; error explícito si falta el runtime.
- `scripts/pack.sh` incluye `research/` en el paquete de campo; `.gitignore`
  ignora los artefactos `broadcom-fingerprint-*/`.
- Tests portables: `test_bundle_debs` se omite si falta `offline_bundle/`,
  los shims `/bin/sh` se omiten en Windows, `test_mac_stable_loopback` sólo
  corre en Linux y las lecturas de archivos usan UTF-8 explícito. La suite
  queda en verde en Windows de desarrollo.

### 2026-10-20 — Integración de memoria técnica persistente (contextbase)

- Se vendorizó ContextBase v1.0.0 en `tools/contextbase/` (Node ESM, sin
  dependencias npm) para que el proyecto no dependa de una instalación global
  ni de red.
- Se agregó `scripts/contextbase.sh`: wrapper POSIX que valida Node `>= 18`,
  resuelve la raíz del repo y ejecuta el CLI vendorizado.
- **Fix upstream:** `contextbase task done` lanzaba `ReferenceError`
  (`lines`, `matched`, `query` sin declarar). Se reescribió el bucle con
  variables locales; el comando ahora mueve la tarea a "Completadas".
- **Fix upstream:** `installSkill()` no cubría OpenCode. Se agregó
  `~/.config/opencode/skills/contextbase/SKILL.md` (solo si el directorio
  existe), además de los paths de Gemini y Claude.
- Se inicializó `contextbase/` con contenido real del proyecto (no genérico):
  arquitectura por módulo, flujo RoE, fases, deuda técnica y comandos.
- Se inyectó el bloque de reglas en `AGENTS.md`, `CLAUDE.md`, `.cursorrules` y
  `.windsurfrules`; `AGENTS.md` además lleva comandos y reglas propias del repo.
- `auris doctor` ahora reporta Node, el wrapper y el estado de los tres
  documentos de contextbase.
- `setup.sh`: verifica/instala `nodejs`, crea el comando global
  `/usr/local/bin/contextbase` y muestra el estado de la memoria al final.
- `scripts/bootstrap.sh`: `nodejs` entra en la lista de paquetes del bundle
  offline.
- `scripts/pack.sh`: `contextbase/` y `tools/` entran en el `.tar.gz` de campo.
- `tests/test_contextbase.py`: verifica documentos, wrapper y el fix de
  `task done` (se omite si no hay Node).
- `.gitignore`: se ignoran `contextbase-pack.txt` y `node_modules/`.
- `.gitattributes`: `eol=lf` forzado en `.sh`/`.py`; en Windows el checkout
  dejaba CRLF y `bash -n setup.sh` fallaba.

### 2026-09-15 — Flujo wifite y Top-20 defaults

- `docs(readme)`: flujo wifite interactivo, fase Top-20 y comandos CLI.
- `feat(psk)`: Top-20 defaults sigiloso tras CAPTURE, con jitter 2-5 s y
  omisión automática de WPS/diccionarios si acierta.
- `fix(monitor+runner)`: adopción de `wlan0mon` renombrado, sintaxis
  hcxdumptool 6.3.1 válida, NetworkManager verificado y restaurado.
- `feat(roe)`: flujo sin BSSIDs previos; el marcado explícito es la firma.

### 2026-09-14 — Selección estilo wifite y empaquetado

- `feat(run-all)`: escaneo de 25 s, pausa y selección `1,3-5`/`all`/`q`;
  `--select`, `--targets`, `--all`.
- `fix(setup)`: guards `|| true` en pipelines con `head` bajo
  `set -e + pipefail` (SIGPIPE mataba la instalación).
- `docs`: despliegue Kali offline/online y README sin emojis.
- `build(packaging)`: arquitectura Wifite4 integrada al bundle y al CLI.

### 2026-09-14 — Base de la versión 2.1.0-wifite4

- HAL userland, generador heurístico, motor por fases, WIDS, gobernanza RoE,
  informes MITRE ATT&CK / D3FEND y suite de tests hermética.

---

## Cambios por Hacer

- Cablear `pipeline.py` (PhaseProtocol) en `runner.py` y retirar el dispatcher
  `if/elif` legacy.
- Agregar `PSK_DEFAULTS` al registry de `phases/__init__.py`; hoy solo existe en
  el camino legacy.
- Integrar `wids.py` a tramas reales del HAL y quitar el etiquetado
  `[SIMULATED]`.
- Evaluar backend PyUSB real para `WirelessTransceiver` (hoy solo contrato).
- CI mínimo en Linux (pytest + `contextbase status`) para que la memoria no se
  desincronice del código.

---

*Nota: cada cambio completado se registra aquí y se refleja en `tasklist.md`.*
