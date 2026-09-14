"""
AURIS v2 — report_writer.py
Generador de informe académico completo.

Genera:
  - Markdown estructurado (para presentar al docente)
  - JSON con todos los datos técnicos
  - Tabla MITRE ATT&CK / D3FEND
  - Recomendaciones de firmware para el ISP/OEM
  - Sección de defensa con contramedidas concretas
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional


# ── Mapeo MITRE ATT&CK + D3FEND ───────────────────────────────────────────────
MITRE_ATTACK = {
    "CAPTURE_HANDSHAKE":      {"id": "T1557.002", "name": "ARP Cache Poisoning / Handshake Capture",  "tactic": "Collection"},
    "CAPTURE_PMKID":          {"id": "T1040",     "name": "Network Sniffing (PMKID)",                  "tactic": "Credential Access"},
    "WPS_CLASS":              {"id": "T1110.001", "name": "Brute Force: Password Guessing (WPS PIN)",  "tactic": "Credential Access"},
    "WPS_PIXIE":              {"id": "T1110.002", "name": "Brute Force: Password Cracking (Pixie Dust)","tactic": "Credential Access"},
    "PSK_SSID_LOGIC":         {"id": "T1110.002", "name": "Brute Force: Password Cracking (Logic WL)", "tactic": "Credential Access"},
    "PSK_ROCKYOU":            {"id": "T1110.002", "name": "Brute Force: Password Cracking (Dictionary)","tactic": "Credential Access"},
    "CLASSIFY_WEAK_CRYPTO":   {"id": "T1600",     "name": "Weaken Encryption (WEP/Open)",              "tactic": "Defense Evasion"},
    "EOL_GOVERNANCE":         {"id": "T1195",     "name": "Supply Chain Compromise (Firmware)",        "tactic": "Initial Access"},
    "RESILIENCE_TEST":        {"id": "T1499",     "name": "Endpoint Denial of Service (Deauth)",       "tactic": "Impact"},
    "DETECT_WPS_LOCKOUT":     {"id": "D3-WSAA",   "name": "Wireless Security Audit (Lockout Detect)",  "tactic": "Detect", "type": "D3FEND"},
    "DETECT_WPA3_SAE":        {"id": "D3-NTA",    "name": "Network Traffic Analysis (WPA3 SAE Detect)","tactic": "Detect", "type": "D3FEND"},
    "AUDIT_DPP_VULNERABILITIES": {"id": "D3-PMAD","name": "Protocol Metadata Anomaly Detection (DPP)", "tactic": "Detect", "type": "D3FEND"},
    "AUDIT_LAN_SURFACE":   {"id": "T1046",     "name": "Network Service Discovery (Mgmt Surface)", "tactic": "Discovery"},
    "VALIDATE_COUNTERMEASURE": {"id": "T1595.002", "name": "Active Scanning: Vulnerability Scanning (Control Re-check)", "tactic": "Reconnaissance"},
}

# Marcadores de pipeline, no actividades: excluidos de la cobertura MITRE.
TERMINAL_PHASES = {"REPORT", "START_WIDS_MONITORING"}

# ── Hallazgos por tipo de resultado ───────────────────────────────────────────
FINDINGS_TEMPLATES = {
    "cracked": {
        "severity":    "CRITICAL",
        "cvss":        "9.8",
        "cwe":         "CWE-330 (Uso de Valores Predecibles en PSK)",
        "headline":    "Credencial WiFi comprometida en auditoría controlada",
        "description": (
            "La clave PSK del AP fue obtenida durante el proceso de auditoría. "
            "Esto demuestra que la contraseña configurada en el dispositivo no cumple "
            "con los requisitos mínimos de entropía o fue derivada de un patrón predecible "
            "(SSID, OUI, patrones de fábrica). Un actor no autorizado con acceso físico "
            "al área de cobertura podría obtener el mismo resultado."
        ),
        "recommendation_user": (
            "Cambiar inmediatamente la contraseña WiFi a una frase de al menos 20 caracteres "
            "aleatorios. No usar nombre de red, dirección, ni fecha. "
            "Usar un gestor de contraseñas para generarla."
        ),
        "recommendation_isp": (
            "Implementar un proceso de generación de PSK únicos por dispositivo en la línea de "
            "producción/provisión. No usar algoritmos que deriven la PSK del SSID o la MAC. "
            "Auditar el parque instalado para detectar dispositivos con PSK de baja entropía."
        ),
        "recommendation_oem": (
            "Generar PSKs únicas por unidad usando un CSPRNG en fábrica. "
            "No usar patrones derivados de identidad del equipo. "
            "Publicar una VDP (Vulnerability Disclosure Policy) para reportes externos."
        ),
    },
    "class_confirmed": {
        "severity":    "HIGH",
        "cvss":        "7.5",
        "cwe":         "CWE-259 (PIN WPS con clase predecible)",
        "headline":    "PIN WPS con clase o familia predecible confirmada",
        "description": (
            "El PIN WPS del dispositivo pertenece a una familia de valores conocida o predecible. "
            "Esto significa que el espacio de búsqueda efectivo es significativamente menor que "
            "el teórico (10^7), haciendo viable un ataque de fuerza bruta dirigido."
        ),
        "recommendation_user":  "Desactivar WPS en el panel de administración del router.",
        "recommendation_isp":   "Deshabilitar WPS vía TR-069/CWMP en el parque instalado. Notificar al OEM.",
        "recommendation_oem":   "Generar PINs WPS únicos y criptográficamente aleatorios por unidad. Eliminar familias de PINs.",
    },
    "locked": {
        "severity":    "INFO",
        "cvss":        "0.0",
        "cwe":         "N/A",
        "headline":    "Mecanismo de bloqueo WPS activo (mitigación efectiva detectada)",
        "description": (
            "El AP tiene activo un mecanismo de bloqueo WPS (Lockout). "
            "Este es un control defensivo efectivo que mitiga los ataques de fuerza bruta. "
            "El WPS sigue estando habilitado (superficie de ataque presente), pero la "
            "explotación activa está mitigada."
        ),
        "recommendation_user":  "El lockout está activo. Para mayor seguridad, deshabilitar WPS completamente.",
        "recommendation_isp":   "Confirmar que el lockout está habilitado en todo el parque. Evaluar deshabilitar WPS.",
        "recommendation_oem":   "Habilitar lockout WPS por defecto en firmware. Considerar eliminar WPS PIN.",
    },
    "exhausted": {
        "severity":    "LOW",
        "cvss":        "2.0",
        "cwe":         "N/A",
        "headline":    "PSK resistente a ataque de diccionario estándar",
        "description": (
            "La contraseña WiFi no fue encontrada en los diccionarios utilizados. "
            "Esto sugiere una PSK de mayor entropía. Sin embargo, el AP sigue siendo "
            "susceptible a ataques con diccionarios especializados o fuerza bruta dirigida."
        ),
        "recommendation_user":  "Contraseña actual parece robusta. Mantener y revisar periódicamente.",
        "recommendation_isp":   "Documentar como caso positivo en la auditoría del parque instalado.",
        "recommendation_oem":   "Mantener la práctica de PSKs de alta entropía en nuevos modelos.",
    },
    "eol_confirmed": {
        "severity":    "HIGH",
        "cvss":        "7.2",
        "cwe":         "CWE-1104 (Firmware EoL no distribuido por ISP)",
        "headline":    "Dispositivo con firmware EOL o sin actualización del ISP",
        "description": (
            "El OEM ha publicado actualizaciones de firmware que corrigen vulnerabilidades conocidas, "
            "pero el ISP no ha distribuido dichas actualizaciones al parque instalado. "
            "El dispositivo permanece expuesto a vulnerabilidades ya parchadas."
        ),
        "recommendation_user":  "Contactar al ISP para solicitar actualización. Como mitigación: deshabilitar WPS y cambiar PSK.",
        "recommendation_isp":   "Establecer un SLA de distribución de firmware. Implementar push automático vía TR-069.",
        "recommendation_oem":   "Notificar proactivamente al ISP de actualizaciones críticas. Mantener canal de divulgación.",
    },
    "done": {
        "severity":    "INFO",
        "cvss":        "0.0",
        "cwe":         "N/A",
        "headline":    "Fase de análisis completada sin hallazgos activos",
        "description": "La fase fue completada sin detectar vulnerabilidades explotables.",
        "recommendation_user":  "Sin acción requerida.",
        "recommendation_isp":   "Sin acción requerida.",
        "recommendation_oem":   "Sin acción requerida.",
    },
    "not_found": {
        "severity":    "LOW",
        "cvss":        "0.0",
        "cwe":         "N/A",
        "headline":    "Sin vulnerabilidades explotables en los vectores analizados",
        "description": (
            "Los vectores evaluados (p. ej. WPA3-SAE, DPP) no presentaron "
            "fallas explotables con las pruebas ejecutadas. La superficie "
            "permanece sujeta a revisión ante nuevos firmwares o diccionarios."
        ),
        "recommendation_user":  "Mantener firmware actualizado y contraseña robusta.",
        "recommendation_isp":   "Documentar como caso sin hallazgos en la auditoría del parque instalado.",
        "recommendation_oem":   "Mantener el nivel de hardening actual en nuevos firmwares.",
    },
}


def _severity_badge(sev: str) -> str:
    badges = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH":     "🟠 HIGH",
        "MEDIUM":   "🟡 MEDIUM",
        "LOW":      "🟢 LOW",
        "INFO":     "🔵 INFO",
    }
    return badges.get(sev, sev)


def generate_markdown_report(
    session_results: List[Dict[str, Any]],
    scope: Dict[str, Any],
    output_path: str,
) -> str:
    """
    Genera el informe académico completo en formato Markdown con evidencia de contraseñas.
    """
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    date_str  = now.strftime("%Y-%m-%d")

    # Estadísticas globales
    total = len(session_results)
    critical = sum(1 for r in session_results if r.get("result") in ("cracked",))
    high     = sum(1 for r in session_results if r.get("result") in ("class_confirmed", "eol_confirmed"))
    low      = sum(1 for r in session_results if r.get("result") in ("exhausted", "locked"))
    total_alerts = sum(r.get("wids_alerts", 0) for r in session_results)
    recovered_creds = [r for r in session_results if r.get("recovered_key")]

    lines = []

    # ── Portada ────────────────────────────────────────────────────────────────
    lines += [
        "# AURIS v2 — Informe de Auditoría WiFi",
        "",
        f"**Fecha:** {timestamp}",
        f"**Institución:** {scope.get('institution', 'N/D')}",
        f"**Estudiante:** {scope.get('student', 'N/D')}",
        f"**Supervisor:** {scope.get('supervisor', 'N/D')}",
        f"**Autorización:** {scope.get('authorization', 'N/D')}",
        f"**Ventana de análisis:** {scope.get('time_window', 'N/D')}",
        "",
        "---",
        "",
        "## Resumen Ejecutivo",
        "",
        f"| Redes analizadas | Críticas | Alta severidad | Baja severidad | Alertas WIDS | Contraseñas Obtenidas |",
        f"|:---:|:---:|:---:|:---:|:---:|:---:|",
        f"| {total} | {critical} | {high} | {low} | {total_alerts} | {len(recovered_creds)} |",
        "",
    ]

    if total_alerts > 0 and any(r.get("wids_simulated") for r in session_results):
        lines += [
            "> *Nota WIDS: las alertas de esta sesión son **simuladas** (generador interno, "
            "no sniffing real de tramas). No constituyen evidencia de ataques observados; "
            "la detección real por sniffer es trabajo futuro documentado.*",
            "",
        ]

    # Diagnóstico general
    if critical > 0:
        lines += [
            "> **⚠ RESULTADO CRÍTICO:** Se encontraron redes con credenciales comprometibles.",
            "> Se requiere acción inmediata del ISP y/o el OEM.",
            "",
        ]
    elif high > 0:
        lines += [
            "> **⚠ RESULTADO ALTO:** Se detectaron configuraciones de alta severidad.",
            "> Se recomienda aplicar las correcciones indicadas a la brevedad.",
            "",
        ]
    else:
        lines += [
            "> **✓ RESULTADO POSITIVO:** No se encontraron vulnerabilidades críticas.",
            "> Las configuraciones analizadas muestran una postura de seguridad adecuada.",
            "",
        ]

    # ── Tabla destacada de credenciales obtenidas (Evidencia Primordial) ────────
    lines += [
        "### 🔑 Registro de Credenciales y Contraseñas Obtenidas (Evidencia Primordial)",
        "",
        "> **Sustento de Evaluación para el Laboratorio y Docente:**",
        "> En auditorías de seguridad perimetral, la obtención del valor en texto claro de la ",
        "> contraseña (PSK) o PIN WPS es la prueba fehaciente e irrefutable de vulnerabilidad. ",
        "> Este valor demuestra de manera tangible el fallo en los mecanismos de aislamiento y ",
        "> sirve como argumento primordial para exigir al ISP y OEM la actualización de firmware ",
        "> y la erradicación de algoritmos deterministas o PINs predecibles.",
        "",
    ]

    if recovered_creds:
        lines += [
            "| Red (SSID) | BSSID | Cifrado | Vector Exitoso | Contraseña / Clave Obtenida | Severidad | Estado |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in recovered_creds:
            s = r.get("ssid", "?")
            b = r.get("bssid", "?")
            enc = r.get("encryption", "?")
            k_type = r.get("key_type") or "WPA-PSK"
            k_val = r.get("recovered_key", "N/D")
            lines.append(
                f"| **{s}** | `{b}` | {enc} | {k_type} | **`{k_val}`** | 🔴 CRÍTICA | **COMPROMETIDO** |"
            )
        lines.append("")
    else:
        lines += [
            "> **Resultado:** No se recuperaron contraseñas en texto claro durante esta sesión. ",
            "> Las políticas de contraseña y mecanismos de protección (como WPS Lockout) ",
            "> resistieron los diccionarios y pruebas de penetración ejecutadas.",
            "",
        ]

    lines += [
        "---",
        "",
        "## 1. Metodología",
        "",
        "La auditoría fue realizada con la herramienta **AURIS v2** siguiendo el marco:",
        "",
        "- **Modelo de amenazas:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege)",
        "- **Framework ofensivo:** MITRE ATT&CK for ICS / Wireless",
        "- **Framework defensivo:** MITRE D3FEND",
        "- **Estándares aplicados:** IEEE 802.11, WPA3 SAE, Device Provisioning Protocol (DPP), RFC 3748 (EAP)",
        "- **Scope:** Solo dispositivos en `config/scope.yml` con autorización documentada",
        "",
        "### 1.1 Flujo de ejecución",
        "",
        "```",
        "wlan0 → MONITOR MODE (wlan0mon)",
        "   ↓",
        "Scan: airodump-ng + wash (enriquecimiento WPS)",
        "   ↓",
        "Por cada AP en scope:",
        "   ↓",
        "Perfil OUI → Modelo STRIDE → Decisión de path → Ejecución secuencial",
        "   ↓",
        "Reporte por AP + Resumen de sesión",
        "```",
        "",
        "---",
        "",
        "## 2. Resultados por dispositivo",
        "",
    ]

    # ── Resultados individuales ────────────────────────────────────────────────
    for idx, result in enumerate(session_results, 1):
        ssid   = result.get("ssid", "?")
        bssid  = result.get("bssid", "?")
        res    = result.get("result", "?")
        path   = result.get("path", [])
        alerts = result.get("wids_alerts", 0)
        elapsed = result.get("elapsed_sec", "?")

        finding = FINDINGS_TEMPLATES.get(res, FINDINGS_TEMPLATES.get("done", {}))
        severity = finding.get("severity", "INFO")

        lines += [
            f"### 2.{idx} {ssid}",
            "",
            f"| Campo | Valor |",
            f"|---|---|",
            f"| **BSSID** | `{bssid}` |",
            f"| **Cifrado** | {result.get('encryption', '?')} |",
            f"| **WPS** | {'Habilitado' if result.get('wps_enabled') else 'Deshabilitado'} (v{result.get('wps_version', 'N/A')}) |",
            f"| **WPS Lockout** | {'Sí ✓' if result.get('wps_locked') else 'No'} |",
            f"| **WPA3/SAE** | {'Sí ✓' if result.get('wpa3_supported') else 'No'} |",
            f"| **Fabricante (OUI)** | {result.get('brand', '?')} |",
            f"| **Contraseña / Clave** | **`{result.get('recovered_key') or 'No comprometida / Resistente'}`** |",
            f"| **Tipo de Credencial** | {result.get('key_type') or 'N/A'} |",
            f"| **Resultado** | {_severity_badge(severity)} — {finding.get('headline', res)} |",
            f"| **Duración** | {elapsed}s |",
            f"| **Alertas WIDS** | {alerts} |",
            f"| **Evidencia sellada** | {len(result.get('evidence_manifest') or {})} archivos SHA256 (`{result.get('run_id', 'dry-run')}`) |",
            "",
            f"**Path de análisis ejecutado:** `{' → '.join(path)}`",
            "",
        ]

        if result.get("recovered_key"):
            lines += [
                "> [!CAUTION]",
                "> **EVIDENCIA DE COMPROMISO — VALOR DE LA CONTRASEÑA OBTENIDO:**",
                f"> - **Contraseña / Clave:** `{result.get('recovered_key')}`",
                f"> - **Mecanismo:** {result.get('key_type', 'N/A')}",
                f"> - **Argumentación Técnica:** La exposición de este valor permite a cualquier atacante asociarse a la red WiFi, interceptar el tráfico local e invadir el segmento doméstico. Esto demuestra una debilidad crítica en la clave predeterminada o en la implementación WPS del firmware, respaldando la necesidad inmediata de una actualización de software por parte del fabricante.",
                "",
            ]

        # ── Perfil de fabricante + deuda histórica (offline) ─────────────────
        try:
            from .vendor_profiles import render_vendor_section_md
            lines += render_vendor_section_md(result)
        except Exception:
            pass

        # ── Superficie LAN (si se auditó con --allow-lan) ─────────────────────
        try:
            from .lan_audit import render_lan_section_md
            lines += render_lan_section_md(result)
        except Exception:
            pass

        # ── Gobernanza EOL ───────────────────────────────────────────────────
        try:
            from .vendor_profiles import render_eol_section_md
            lines += render_eol_section_md(result)
        except Exception:
            pass

        # ── Onboarding DPP ───────────────────────────────────────────────────
        try:
            from .vendor_profiles import render_dpp_section_md
            lines += render_dpp_section_md(result)
        except Exception:
            pass

        lines += [
            f"#### Hallazgo: {finding.get('headline', '')}",
            "",
            f"{finding.get('description', '')}",
            "",
            f"**CWE:** {finding.get('cwe', 'N/A')} | **CVSS Base:** {finding.get('cvss', '0.0')}",
            "",
            "#### Recomendaciones",
            "",
            f"| Actor | Recomendación |",
            f"|---|---|",
            f"| 👤 Usuario final | {finding.get('recommendation_user', 'N/A')} |",
            f"| 🏢 ISP/Operador | {finding.get('recommendation_isp', 'N/A')} |",
            f"| 🏭 Fabricante OEM | {finding.get('recommendation_oem', 'N/A')} |",
            "",
            "---",
            "",
        ]

    # ── Mapeo MITRE ────────────────────────────────────────────────────────────
    lines += [
        "## 3. Mapeo MITRE ATT&CK / D3FEND",
        "",
        "| Fase AURIS | ID MITRE | Técnica | Táctica |",
        "|---|---|---|---|",
    ]

    seen_mitre = set()
    for result in session_results:
        for phase in result.get("path", []):
            if phase in MITRE_ATTACK and phase not in seen_mitre:
                m = MITRE_ATTACK[phase]
                framework = m.get("type", "ATT&CK")
                lines.append(
                    f"| `{phase}` | [{m['id']}](https://attack.mitre.org/techniques/{m['id'].replace('.','/')}) | "
                    f"{m['name']} | {m['tactic']} ({framework}) |"
                )
                seen_mitre.add(phase)

    lines += [
        "",
        "---",
        "",
        "## 4. Recomendaciones de Actualización de Firmware",
        "",
        "Basado en los hallazgos de EOL Governance, contraseñas comprometidas y el perfil OUI detectado:",
        "",
        "| Dispositivo | Marca | Contraseña Expuesta | Acción requerida | Urgencia |",
        "|---|---|---|---|---|",
    ]

    for result in session_results:
        rec_k = result.get('recovered_key')
        if rec_k:
            lines.append(
                f"| {result.get('ssid','?')} ({result.get('bssid','?')}) | "
                f"{result.get('brand','?')} | "
                f"**SÍ (`{rec_k}`)** | "
                f"Actualizar firmware de fábrica: forzar generador CSPRNG para PSK, desactivar WPS por defecto e implementar WPA3-SAE obligatorio | "
                f"**CRÍTICA** |"
            )
        elif result.get("result") == "eol_confirmed":
            lines.append(
                f"| {result.get('ssid','?')} ({result.get('bssid','?')}) | "
                f"{result.get('brand','?')} | "
                f"No detectada | "
                f"Solicitar actualización de firmware al ISP vía canal de soporte oficial (parche EOL) | "
                f"**ALTA** |"
            )
        elif result.get("result") in ("cracked", "class_confirmed"):
            lines.append(
                f"| {result.get('ssid','?')} ({result.get('bssid','?')}) | "
                f"{result.get('brand','?')} | "
                f"Vulnerable a clase WPS | "
                f"Deshabilitar WPS inmediatamente. Cambiar PSK. Solicitar revisión de configuración de fábrica | "
                f"**CRÍTICA** |"
            )

    lines += [
        "",
        "---",
        "",
        "## 5. Defensa — Plan de Respuesta",
        "",
        "### 5.1 Acciones inmediatas (0-24h)",
        "",
        "- [ ] Cambiar PSK WiFi a frase aleatoria de ≥20 caracteres",
        "- [ ] Deshabilitar WPS en todos los dispositivos accesibles",
        "- [ ] Contactar al ISP para reportar los hallazgos y solicitar push de firmware",
        "",
        "### 5.2 Acciones a corto plazo (1-4 semanas)",
        "",
        "- [ ] Implementar segmentación de red (IoT en VLAN separada)",
        "- [ ] Habilitar WPA3 si el dispositivo lo soporta",
        "- [ ] Activar monitoreo pasivo con WIDS",
        "- [ ] Documentar y enviar VDP al OEM del dispositivo",
        "",
        "### 5.3 Acciones estratégicas (ISP/OEM)",
        "",
        "- [ ] Establecer proceso de actualización de firmware automatizado (TR-069/CWMP)",
        "- [ ] Generar PSK y PINs WPS únicos por dispositivo desde producción",
        "- [ ] Publicar y mantener una política de divulgación responsable (VDP)",
        "- [ ] Migrar parque instalado a WPA3 según el roadmap de la alianza Wi-Fi",
        "",
        "---",
        "",
        "## 6. Conclusión",
        "",
        "La herramienta AURIS v2 demostró la capacidad de realizar un análisis integral del ",
        "ecosistema WiFi doméstico combinando perspectivas ofensiva (Red Team) y defensiva (Blue Team). ",
        "Los hallazgos obtenidos proveen argumentos técnicos concretos y verificables para que el ISP ",
        "y el OEM prioricen la actualización del firmware y el hardening de la configuración de fábrica.",
        "",
        "*Informe generado automáticamente por AURIS v2. Todos los análisis fueron realizados bajo ",
        "consentimiento documentado (scope.yml) en dispositivos propios del laboratorio académico.*",
        "",
        "---",
        f"*Generado: {timestamp} | AURIS v2 — Proyecto de Tesis*",
    ]

    content = "\n".join(lines)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path


def generate_json_report(
    session_results: List[Dict[str, Any]],
    scope: Dict[str, Any],
    output_path: str,
) -> str:
    """Guarda los resultados completos en formato JSON."""
    recovered_creds = [
        {
            "ssid": r.get("ssid"),
            "bssid": r.get("bssid"),
            "recovered_key": r.get("recovered_key"),
            "key_type": r.get("key_type"),
            "result": r.get("result"),
        }
        for r in session_results
        if r.get("recovered_key")
    ]

    payload = {
        "auris_version":   "2.0",
        "generated_at":    datetime.now().isoformat(),
        "scope":           scope,
        "mitre_framework": list(MITRE_ATTACK.values()),
        "results":         session_results,
        "summary": {
            "total_targets":          len(session_results),
            "critical":               sum(1 for r in session_results if r.get("result") == "cracked"),
            "high":                   sum(1 for r in session_results if r.get("result") in ("class_confirmed", "eol_confirmed")),
            "low":                    sum(1 for r in session_results if r.get("result") in ("exhausted", "locked")),
            "total_wids_alerts":      sum(r.get("wids_alerts", 0) for r in session_results),
            "compromised_keys_count": len(recovered_creds),
            "recovered_credentials":  recovered_creds,
        },
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str, ensure_ascii=False)
    return output_path
