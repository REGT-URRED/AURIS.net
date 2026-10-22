# Vendor: broadcom-wps

Código de terceros incorporado a AURIS.net para investigación de CPEs con SDK
Broadcom. No fue modificado.

- **Upstream:** https://github.com/qkaiser/broadcom-wps
- **Commit vendorizado:** `0727296` (2026, `main`)
- **Autor:** Quentin Kaiser (Konkretesec)
- **Licencia:** MIT — ver `LICENSE.md` en esta carpeta

## Contenido

| Archivo | Qué hace |
|---|---|
| `broadcom_fingerprint.py` | Fingerprint dinámico: distingue `wps_monitor` (vulnerable) de `hostapd` parcheado usando el IE propietario de Broadcom y la respuesta a un primer fragmento EAP-WPS de longitud cero. Requiere monitor mode, `scapy` y Python 3.11+. |
| `broadcom_wps_monitor.yar` | Detección estática sobre firmware extraído (ELF32 ARM/MIPS): reglas `BRCM_WPS_Monitor_Generic_ELF`, `BRCM_WPS_Monitor_HAL_Config_ELF` y `VULN_BRCM_WPS_EAP_Fragment_Reassembly_ELF`. |
| `README.md` | Documentación original: uso, límites de hardware y lista de equipos afectados. |

## Uso dentro de AURIS

```bash
# Catálogo offline (data/seed/broadcom_affected.csv, generado del README)
auris broadcom --lookup Askey
auris broadcom --lookup Sagemcom --model F5598T

# Firmware extraído con las reglas YARA
auris broadcom --firmware /ruta/firmware_extraido

# Fingerprint en vivo (interfaz ya en modo monitor)
sudo auris broadcom --interface wlan0mon --ssid "MOVISTAR_XXXX"
```

Implementación: `src/auris/broadcom.py` (catálogo, parser de `result.json` y
de la salida YARA) y el subcomando `auris broadcom` en `src/auris/cli.py`.
`auris doctor` reporta los artefactos, `yara` y `uv`.

Equivalente directo, sin AURIS:

```bash
sudo uv run --with scapy research/broadcom-wps/broadcom_fingerprint.py \
    --interface wlan0mon --ssid "MOVISTAR_XXXX"
yara -w -r research/broadcom-wps/broadcom_wps_monitor.yar firmware_extraido/
```

Artefactos por corrida: `evidence/broadcom-fingerprint-<timestamp>/`
(`result.json` + `traffic.pcap`), ignorados por git.

## Límites y ética

- El fingerprinter transmite tramas 802.11: aplícalo sólo a objetivos
  autorizados por el RoE vigente. El marcado explícito sigue siendo la firma.
- Un resultado `LIKELY_VULNERABLE` es evidencia de familia de implementación,
  no prueba de explotabilidad. `PATCHED_HOSTAPD` no exime de revisar el resto
  de la superficie.
- El script upstream no explota nada: sólo mide la respuesta al primer
  fragmento y limpia la sesión (deauth del station sintético).
