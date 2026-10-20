# Fundamentos del Proyecto: AURIS.net

## 1. Objetivo Principal

AURIS.net es un framework modular de auditoría y evaluación de seguridad
inalámbrica (802.11) sobre routers y CPEs domésticos. Integra orquestación de
pruebas por fases, abstracción de hardware en espacio de usuario (HAL),
generación heurística de claves y gobernanza estricta de Reglas de Compromiso
(RoE). El despliegue de campo es 100% offline: Kali/Parrot portátil, bundle con
`.deb`, wheels y wordlists en USB, sin conexión a internet.

Este documento fija las bases arquitectónicas, las reglas operativas y el
contexto técnico que debe sobrevivir entre sesiones y entre agentes de código.

---

## 2. Reglas de Desarrollo (Obligatorias)

1. **Regla Crítica de Actualización:** todo cambio de código termina con la
   actualización de `contextbase/changelog.md`, `contextbase/tasklist.md` y
   este documento si cambió la arquitectura, una dependencia o un comando.
2. **Autorización primero (RoE):** ninguna fase ofensiva se ejecuta sin
   `scope.yml` válido y firma de sesión (selección explícita de objetivos,
   `--force-roe` o `--dry-run`). Nunca relajar esa puerta para "probar".
3. **Offline por diseño:** ningún módulo de runtime abre sockets, hace DNS o
   descarga recursos. `audit_lan` es la única excepción y es solo lectura,
   explícita (`--allow-lan`) y restringida a RFC1918.
4. **Sin dependencias nuevas sin justificar:** el bundle offline debe seguir
   siendo reproducible con `scripts/bootstrap.sh`.
5. **Tests herméticos:** `PYTHONPATH=src pytest tests/ -v` corre sin hardware
   WiFi, sin root y sin red. Los tests no escriben fuera del repositorio.
6. **Idioma:** documentación, bitácora y mensajes de usuario en español;
   código, identificadores y nombres de archivo en inglés.
7. **Compatibilidad Linux:** rutas POSIX, `#!/usr/bin/env bash`,
   `set -euo pipefail` en scripts, sin supuestos de Windows.

---

## 3. Arquitectura y Contexto Técnico

- **Nombre:** `AURIS.net`
- **Versión:** `2.1.0-wifite4`
- **Ecosistema:** Python 3.10+ (Typer, Pydantic v2, SQLAlchemy 2, Rich, PyYAML)
- **Plataforma:** Linux (Kali, Parrot, Debian 12+, Ubuntu 22.04+)
- **Persistencia:** SQLite (`data/auris.db`) + JSON de sesión (`data/sessions/`)
- **Evidencia:** `evidence/<run_id>/` (capturas, logs de stderr, defaults)
- **Informes:** `reports/*.md` y `reports/*.json`

### 3.1 Mapa de módulos (`src/auris/`)

| Módulo | Responsabilidad |
|---|---|
| `cli.py` | Comandos Typer: `run-all`, `doctor`, `hal`, `candidates`, `db-init`, `verify-rockyou`. Orquesta el flujo completo y las puertas RoE. |
| `monitor.py` | Modo monitor: orden manual `ip`+`iw` primero (compatible hcxdumptool 6.3.1), `airmon-ng` como fallback, adopción de interfaces renombradas, restauración verificada de NetworkManager. |
| `scanner.py` | Descubrimiento: `hcxdumptool` > `wash` > `airodump-ng`, normalizado a la misma estructura de targets. |
| `decision_engine.py` | Modelo STRIDE (`calculate_stride_threat`) y árbol de decisión de path (`decide_path`). |
| `runner.py` | Ejecución de UN target: dispatcher secuencial de fases, presupuestos de tiempo, corte temprano al crackear, WIDS opcional. |
| `pipeline.py` | Orquestador basado en `PhaseProtocol` + `PhaseResult` (módulo nuevo, aún no cableado desde `runner.py`; ver deuda técnica). |
| `phases/` | Clases de fase: `capture`, `wps`, `psk`, `network`, `governance`, con contrato en `base.py`. |
| `adapters/` | Frontera con herramientas externas: `capture` (hcxdumptool/airodump), `cracker` (hashcat/aircrack/reaver/bully), `tool_runner` (único punto de `subprocess`). |
| `hal.py` | HAL userland: catálogo `CHIPSET_REGISTRY` (VID/PID, bandas, inyección), `USBAdapterInfo`, `WirelessTransceiver` (protocolo), `detect_adapters()`. Hoy es catálogo + detección; la operación USB directa (PyUSB) no está en `requirements.txt`. |
| `generator.py` | Generador combinatorio de candidatos PSK a partir de SSID, BSSID, marca y familia de equipos. |
| `vendor_profiles.py` | Base de conocimiento offline: marcas, OEMs, deuda histórica de firmware, evidencia de reutilización de PSK entre APs hermanos. |
| `roe.py` | Alcance, ventana temporal, firma de sesión, MAC estable, cadena de custodia y directorio de evidencia. |
| `session.py` | Persistencia atómica del progreso (tmp + rename) y reanudación (`--resume-last`, `--resume-file`). |
| `db.py` / `models.py` | SQLAlchemy (`Vendor`, catálogo CWE) y modelos Pydantic (`TargetInfo`, `Profile`, `ThreatModelSTRIDE`). |
| `report_writer.py` / `reporter.py` | Informe académico Markdown/JSON con mapeo MITRE ATT&CK / D3FEND. |
| `wids.py` | Sensor defensivo. **Estado actual: SIMULADO**; las alertas se etiquetan `[SIMULATED]` en el informe. |
| `doctor.py` | Verificación de entorno: privilegios, interfaces, binarios, paquetes Python, wordlists, scope, DB y (desde esta integración) contextbase. |
| `terminal.py` | Tablas Rich, banners, selección interactiva de objetivos (`1,3-5`, `all`, `q`). |
| `wordlists.py` | Localización y verificación de `rockyou.txt` (chequeo rápido y conteo profundo). |
| `lan_audit.py` | Superficie LAN de solo lectura (banners TCP, RFC1918), detrás de `--allow-lan`. |

### 3.2 Flujo de ejecución (`run-all`)

1. **Puerta RoE fase A:** `enforce_scope(dry_run=True)` exige ventana temporal.
2. **Sesión:** `new_session()`; opcional `--resume-last`.
3. **Modo monitor:** se omite en `--dry-run`; se restaura en `finally`.
4. **Escaneo:** 25 s por defecto; `--target-bssid` omite el escaneo.
5. **Filtro de scope:** lista blanca vacía = modo wifite (la autorización la da
   el marcado); lista blanca real = filtrado estricto.
6. **Selección:** prompt interactivo, `--targets`, `--all` o `--no-select`.
7. **Puerta RoE fase B:** la selección explícita es la firma de sesión.
8. **Por target:** `PROFILE → STRIDE → DECIDE → EXEC → REPORT`, con corte
   temprano si se recupera credencial.
9. **Informes:** `reports/auris_<ts>.json` y `..._informe.md`.
10. **Cierre:** verificación de MAC estable si el scope lo exige.

### 3.3 Fases y presupuesto

`CAPTURE_PMKID`, `CAPTURE_HANDSHAKE`, `PSK_DEFAULTS` (Top-20 con jitter
2-5 s), `WPS_PIXIE`, `WPS_CLASS`, `DETECT_WPS_LOCKOUT`, `CLASSIFY_WEAK_CRYPTO`,
`PSK_SSID_LOGIC`, `PSK_ROCKYOU`, `EOL_GOVERNANCE`, `AUDIT_DPP_VULNERABILITIES`,
`AUDIT_LAN_SURFACE`, `RESILIENCE_TEST`, `VALIDATE_COUNTERMEASURE`.
Los timeouts viven en `runner.py` (`PHASE_TIMEOUTS`) y el corte por credencial
en `ATTACK_PHASES`.

### 3.4 Investigación vendorizada (`research/broadcom-wps/`)

Código MIT de `qkaiser/broadcom-wps` (commit `0727296`) para CPEs con SDK
Broadcom. No forma parte del runtime de `src/auris`; se invoca por el
subcomando `auris broadcom` o directamente.

- `broadcom_fingerprint.py`: distingue `wps_monitor` (vulnerable) de `hostapd`
  parcheado combinando el IE propietario de Broadcom con la respuesta a un
  primer fragmento EAP-WPS de longitud cero. Requiere monitor mode, `scapy` y
  Python 3.11+ (o `uv`).
- `broadcom_wps_monitor.yar`: reglas estáticas ELF32 ARM/MIPS para firmware.
- `VENDOR.md`: procedencia, licencia, uso y límites. El resultado
  `LIKELY_VULNERABLE` es evidencia de familia de implementación, no prueba de
  explotabilidad.

### 3.5 Deuda técnica conocida

- `pipeline.py` está implementado y testeado, pero `run_single_target` sigue
  usando el dispatcher `if/elif` legacy de `runner.py`.
- `wids.py` emite alertas simuladas; falta integrarlo a tramas reales del HAL.
- La HAL declara el contrato USB (`WirelessTransceiver`) pero no hay backend
  PyUSB instalado por defecto: la operación es por herramientas del sistema.
- `auris broadcom` depende de `uv` o de `scapy` en Python 3.11+; no está en
  `requirements.txt` para no cargar el bundle offline.

---

## 4. Dependencias y Despliegue

### 4.1 Python (`requirements.txt`)

`typer>=0.9`, `pydantic>=2.4`, `sqlalchemy>=2.0.20`, `pytest>=7.4`,
`rich>=13.0`, `pyyaml>=6.0`.

### 4.2 Sistema (según fase)

`aircrack-ng`, `hcxdumptool>=6.3.1`, `hcxtools`, `reaver`, `bully`, `pixiewps`,
`wash`, `iw`, `wireless-tools`, `macchanger`, `hashcat`.
`nodejs >= 18` es requisito **solo** para la memoria técnica contextbase.

### 4.3 Instalación

```bash
# Con red
git clone https://github.com/REGT-URRED/AURIS.net.git
cd AURIS.net && python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt && python3 auris.py db-init

# Offline en campo
mkdir -p ~/auris && tar xzf auris-kali.tar.gz -C ~/auris && cd ~/auris
sudo bash setup.sh
```

### 4.4 Pruebas

```bash
PYTHONPATH=src pytest tests/ -v
```

---

## 5. Memoria Técnica Persistente (contextbase)

El CLI ContextBase está vendorizado en `tools/contextbase/` (Node ESM, sin
dependencias npm) y se invoca con `scripts/contextbase.sh`, que valida Node
`>= 18` y ejecuta siempre desde la raíz del repositorio.

```bash
bash scripts/contextbase.sh status        # estado de la memoria y progreso
bash scripts/contextbase.sh log "..."     # registrar cambio en changelog.md
bash scripts/contextbase.sh task add "..."# agregar tarea pendiente
bash scripts/contextbase.sh task done "..."# completar tarea
bash scripts/contextbase.sh dump          # volcar los tres documentos
bash scripts/contextbase.sh pack          # empaquetado estilo Repomix
```

Reglas de convivencia:

- `scripts/contextbase.sh init` **no** se ejecuta en campo: los tres documentos
  están versionados y se editan, no se regeneran (`--force` los pisaría).
- `setup.sh` instala `nodejs` desde el bundle offline si existe el `.deb` y deja
  el comando global `/usr/local/bin/contextbase` apuntando a este wrapper.
- `scripts/pack.sh` incluye `contextbase/` y `tools/` en el `.tar.gz` de campo.
- `auris doctor` reporta el estado de Node y de los tres documentos.

---

## 6. Convenciones

- Nombres de fase en mayúsculas (`PSK_DEFAULTS`), clases en PascalCase
  (`PSKDefaultsPhase`), módulos en snake_case.
- Todo resultado de fase retorna `PhaseResult(status, detail, ...)`.
- La evidencia se escribe en `evidence/<run_id>/`; nunca en la raíz.
- Los informes no se versionan (`.gitignore`).
- Los commits siguen Conventional Commits en inglés, sin atribución a IA.

---

*Documento mantenido a mano. ContextBase v1.0.0 (vendorizado) no lo regenera
salvo que se use `init --force`.*
