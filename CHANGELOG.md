# CHANGELOG — AURIS / Wifite4 Research Project

Todas las entregas notables se documentan en este archivo.  
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/).

---

## [No publicado]

### Añadido
- Flujo wifite puro sin BSSIDs previos: `allowed_bssids: []` = modo
  selección; la marca explícita tras el scan (prompt tecleado / `--targets` /
  `--target-bssid`) ES la firma RoE (`selection_consent`). `sudo auris run-all`
  escanea 25s, marcas `1,3-5` y audita en secuencia sin nada más. Solo el modo
  totalmente automático (`--all`/`--no-select`/sin TTY) sigue exigiendo
  `--force-roe`. Scopes por defecto con lista vacía; `doctor`/`setup.sh`
  re-mensajados; `LEEME-USB.txt` reescrito sin pre-edición de BSSIDs.
- Flujo de selección de objetivos estilo wifite en `run-all`: escanea 25s
  (default, antes 60s), detiene el escáner y deja marcar redes con prompt
  interactivo (`1,3-5` · `all` · Enter=todas · `q`=abortar). Nuevas flags
- Fase `PSK_DEFAULTS` Top-20 sigilosa: 20 claves por error humano (12345678,
  password…), probadas en 2×10 tras cada CAPTURE con pausa+jitter 2-5s y sin
  barra ruidosa; si acierta, omite WPS/SSID/rockyou automáticamente (omisión de
  trabajo del 50% en parques con defaults). Trazable en `evidence/defaults_*.txt`.
  Tiempo <60s agregado; no se ejecuta en ruta WPA3-SAE. Incluida en MITRE y tests.
  `--select/--no-select`, `--targets "1,3-5,all"` y `--all` para uso
  no-interactivo/offline automático. Helpers `parse_target_selection()` y
  `prompt_target_selection()` en `terminal.py` + tests en
  `tests/test_target_select.py`.

### Corregido
- `setup.sh` moría en silencio tras "118 paquetes .deb" por `set -e + pipefail`
  + `grep` sin match en .deb sin dependencia libc6 (ca-certificates, fonts…):
  añadido `|| true` al filtro de glibc (y al `ls` de pip wheel).
- `setup.sh` se colgaba en `macchanger` por pregunta debconf interactiva:
  preseed `automatically_change_mac=false` + `DEBIAN_FRONTEND=noninteractive`
  en `dpkg --configure` / `apt-get -f install`.
- `setup.sh`: guard `|| true` en pipelines con `head` (`GLIBC_VER`, pip wheel)
  que bajo `set -e + pipefail` podían matar el instalador con SIGPIPE.
- `monitor.py`: airmon-ng con `rc=1` pero con `wlan0mon` creado ya no aborta:
  adopta el renombre (`find_monitor_iface`); orden manual `ip+iw` primero
  (compatible hcxdumptool), airmon fallback; NM con restart verificado +
  diagnóstico; `cli.py` aborta con guía si hay hardware pero sin monitor,
  y restaura NM incluso si `enable` falló a medias.
- `runner.py`: sintaxis hcxdumptool 6.3.1 válida (`-w`/`-c <ch><banda>`/
  `--rcascan=p`/`--tot`/`--bpf` por objetivo vía `tcpdump -ddd`; fin de flags
  inexistentes `--filterlist_ap`/`--filtermode`/`-o`/`--rcascan=<seg>` que
  hacían fallar todo CAPTURE; filtrado posterior `hcxhashtool --mac-ap` y
  `evidence/*_stderr.log` para no oscurecer errores.
- `tests`: `test_session` con cwd portátil (no Windows-path), WPS/resilience
  con `run_dir`, `test_target_select` con `explicit` vs auto (RoE),
  `test_find_rockyou_override` hermético (rockyou del sistema).

## [2.1.0-wifite4] — 2026-09-14

### Propósito de esta entrega
Integración de la arquitectura **Wifite4** dentro del proyecto AURIS: los módulos
nuevos y refactorizados de esta versión forman la base tecnológica para una
contribución Open Source que une el paradigma de **hardware en userland** de
`derv82/wifit3` con la **inteligencia de dispositivos y divulgación coordinada**
de AURIS.

---

### Añadido

#### `src/auris/hal.py` *(nuevo)*
- **Hardware Abstraction Layer (HAL) en espacio de usuario**: permite controlar
  adaptadores WiFi USB directamente sin depender del kernel de Linux (`nl80211`/
  `mac80211`) ni de NDIS en Windows.
- **`WirelessTransceiver`** (Protocol / interfaz abstracta): contrato tipo-seguro
  que deben implementar los controladores de cada chipset.
- **`Dot11Frame`**: contenedor normalizado de trama 802.11 capturada (timestamp,
  canal, RSSI, bytes crudos).
- **`USBAdapterInfo`**: metadatos de un adaptador USB soportado (VID/PID, chipset,
  bandas, capacidades de monitor e inyección).
- **`CHIPSET_REGISTRY`**: registro extensible con 14 chipsets soportados:
  - Atheros: AR9271
  - MediaTek: MT7610U, MT7612U, MT7921AU, MT7925U
  - Realtek: RTL8812AU, RTL8814AU, RTL8821AU, RTL8822BU, RTL8187L,
    RTL8188EUS, RTL8821CU
- **`USBDeviceEnumerator`**: detecta adaptadores soportados via PyUSB / libusb-1.0.
  Degrada graciosamente si PyUSB no está instalado.
- **`StubbedTransceiver`**: implementación stub para pruebas unitarias sin hardware.
- **`detect_adapters()`** y **`hal_status_report()`**: utilidades de diagnóstico
  para el comando `auris doctor`.

#### `src/auris/generator.py` *(nuevo)*
- **Motor combinatorio inteligente de candidatos PSK** extraído y refactorizado
  desde `runner.py` como componente independiente y testeable.
- **`CandidateGenerator`**: clase principal con parámetros configurables
  (`max_batch_1`, `max_batch_2`, `min_length`, `max_length`).
- **`CandidateSet`**: modelo de resultado con `batch_1` (alta probabilidad) y
  `batch_2` (mutaciones de familia), metadata de fuentes y `to_wordlist_lines()`.
- **Estrategia combinatoria documentada**:
  - `[A]` Claves exactas de APs hermanos (reutilización directa).
  - `[B]` Variantes de capitalización de la base del SSID.
  - `[C]` Combinación exacta: `Base + Separador + (Año | Token ISP/OEM)`.
  - `[D]` Fragmentos del BSSID (últimos 2/3/4 octetos).
  - `[E]` Tokens genéricos de cierre mínimos.
  - `[F]` Mutaciones de claves de familia en `batch_2`.
- **`generate_candidates()`**: función de conveniencia para uso directo.
- Reduce el espacio de búsqueda de ~14M entradas (rockyou) a 500–5.000
  candidatos de alta probabilidad para CPEs de ISPs.

#### Modelos nuevos en `src/auris/models.py`
- **`HALStatus`**: estado del subsistema HAL USB con property `summary`.
- **`WPSInfo`**: metadatos completos del IE WPS (14 campos TLV: manufacturer,
  model_name, model_number, serial, device_name, rf_bands, config_methods,
  selected_registrar, pbc_active…) con property `vendor_fingerprint`.
- **`PBCEvent`**: evento de pulsación del botón WPS PushButton con severidad
  automática (`High`/`Medium`), CWE-287 y título de hallazgo.

#### Campos nuevos en `TargetInfo`
- `wps_manufacturer` (TLV 0x1021): fabricante extraído directamente del beacon.
- `wps_model_number` (TLV 0x1024): número de modelo del IE WPS.
- `wps_device_name` (TLV 0x1011): nombre del dispositivo WPS.
- `wps_pbc_active`: indicador de ventana PBC activa.

---

### Cambiado

#### `src/auris/wids.py`
- Refactorizado completamente con docstring de módulo y docstrings de clase/método.
- Añadido `ALERT_TYPES` como lista de clase (incluye `"PBC Window Open"` para Wifite4).
- `_emit_alert()`: método centralizado para registro y distribución de alertas.
- **`detect_pbc_event()`** *(preparado, sin HAL activo)*: método esqueleto con
  `TODO` documentado para integración futura con `hal.WirelessTransceiver`.
- Añadidos `get_alerts_by_type()` y property `real_alerts`.
- Tipo `_transceiver = None` preparado como hook de integración HAL.

#### `src/auris/__init__.py`
- Versión actualizada a `2.1.0-wifite4`.
- Exportaciones públicas actualizadas: `HALStatus`, `WPSInfo`, `PBCEvent`,
  `generate_candidates`, `CandidateGenerator`, `CandidateSet`,
  `detect_adapters`, `hal_status_report`, `CHIPSET_REGISTRY`,
  `USBAdapterInfo`, `Dot11Frame`, `StubbedTransceiver`.

---

### Arquitectura: relación con la comunidad Open Source

| Capa | Módulo AURIS | Origen de inspiración | Siguiente paso para Wifite4 |
|---|---|---|---|
| 1. HAL USB Userland | `hal.py` | `derv82/wifit3` | Implementar `hal_ar9271.py`, `hal_mt7612u.py`, `hal_rtl8812au.py` |
| 2. Telemetría 802.11 | `scanner.py` + `hal.py` | AURIS + wifit3 | Parser de IE WPS sobre `Dot11Frame` |
| 3. Inteligencia de Dispositivo | `vendor_profiles.py` + `generator.py` | AURIS | Exportar como plugin para wifit3/wifite4 |
| 4. Orquestador FSM | `runner.py` | AURIS | Stop-on-lockout + PBC detection |
| 5. Divulgación VDP | `report_writer.py` | AURIS | PR para wifit3 README con formato VDP |

---

### Hoja de ruta

- [ ] **`hal_ar9271.py`**: implementación real del transceptor para chipset Atheros AR9271.
- [ ] **`hal_mt7612u.py`**: implementación real para MediaTek MT7612U (AWUS036ACM).
- [ ] **`dot11_parser.py`**: deserializador de IE WPS para poblar `WPSInfo` desde `Dot11Frame`.
- [ ] **`detect_pbc_event()`** (wids.py): conectar con `WirelessTransceiver` y `WPSInfo`.
- [ ] Tests unitarios: `tests/test_generator.py`, `tests/test_hal.py`, `tests/test_models.py`.
- [ ] Pull Request a `derv82/wifit3`: proponer integración del motor de perfilado AURIS.

---

## [2.0.0] — anterior

Versión base AURIS con CLI (Typer + Rich), scanner multi-backend,
motor STRIDE, auditoría LAN, reporte multi-destinatario y WIDS simulado.
