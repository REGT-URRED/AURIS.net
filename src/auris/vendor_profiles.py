"""
AURIS v2 — Inteligencia de fabricantes y deuda histórica de vulnerabilidades.

100% OFFLINE: este módulo no abre sockets, no hace DNS ni HTTP.
Toda la información es una base de conocimiento curada y autocontenida.

Cubre la flota del laboratorio: Huawei, TP-Link, Askey, MitraStar (+ Arcadyan/ZyXEL
como OEMs hermanos) y equipos desconocidos. Cada entrada histórica incluye:
  - causa técnica del bug (qué falló en el diseño/implementación),
  - qué prueba ejecuta AURIS hoy contra esa clase (mapeo honesto),
  - cómo defenderse / qué exigir al ISP-OEM (remediación).
"""

from typing import Dict, List, Optional
import json
import os

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

# Override de laboratorio: data/vendor_map.json {"001CDF": "Askey", ...}.
# Permite fijar la marca exacta de los 5 routers del lab sin tocar código.
# Ver data/vendor_map.example.json. Cacheado (el scan llama miles de veces).
_VENDOR_MAP_CACHE: Optional[Dict[str, str]] = None


def _lab_overrides(path: Optional[str] = None) -> Dict[str, str]:
    global _VENDOR_MAP_CACHE
    if path is not None:
        try:
            with open(path) as f:
                raw = json.load(f)
            return {str(k).replace(":", "").replace("-", "").upper(): str(v)
                    for k, v in raw.items() if isinstance(v, str) and v.strip()}
        except (OSError, ValueError, AttributeError):
            return {}
    if _VENDOR_MAP_CACHE is None:
        _VENDOR_MAP_CACHE = {}
        for cand in (os.path.join(PROJECT_DIR, "data", "vendor_map.json"),
                     "data/vendor_map.json"):
            m = _lab_overrides(cand)
            if m:
                _VENDOR_MAP_CACHE = m
                break
    return _VENDOR_MAP_CACHE

# ─── Resolución de marca ─────────────────────────────────────────────────────
# Solo OUIs ya verificados dentro del propio repo + patrones SSID documentados
# de flotas ISP. Nada inventado: lo no reconocido cae a "Unknown" con heurística
# de flota por SSID. Un laboratorio puede afinar con data/vendor_map.json
# (formato {"001CDF": "Askey", ...}) sin tocar código.

OUI_HINTS: Dict[str, str] = {
    "001CDF": "Askey",
    "001F9F": "Askey",
    "ACCC8A": "Askey",
}

# Patrones de SSID de fábrica por flota (prefijos en mayúsculas).
# Fuente: firmwares y despliegues ISP documentados públicamente.
SSID_FLEET: List[tuple] = [
    ("HUAWEI-", "Huawei"),
    ("HUAWEI_", "Huawei"),
    ("TP-LINK_", "TP-Link"),
    ("TP-Link_", "TP-Link"),
    ("TPLINK_", "TP-Link"),
    ("MOVISTAR_", "ISP Fleet (HGU)"),
    ("MOVISTAR-", "ISP Fleet (HGU)"),
    ("MOVISTAR_PLUS", "ISP Fleet (HGU)"),
    ("WLAN_", "ISP Fleet (Legacy)"),
    ("JAZZTEL_", "ISP Fleet (Legacy)"),
    ("ONO", "ISP Fleet (Legacy)"),
    ("VODAFONE", "ISP Fleet (Legacy)"),
    ("Vodafone-", "ISP Fleet (Legacy)"),
    ("ORANGE-", "ISP Fleet (Legacy)"),
    ("Orange-", "ISP Fleet (Legacy)"),
    ("Livebox-", "ISP Fleet (Legacy)"),
    ("MIWIFI_", "Xiaomi"),
    ("D-LINK", "D-Link"),
    ("DLINK_", "D-Link"),
]

# Tokens de operadora/fabricante para el generador de candidatos PSK offline.
# Las PSK de fábrica de flotas ISP suelen derivarse del nombre visible.
ISP_TOKENS: List[str] = [
    "movistar", "movistar1", "jazztel", "vodafone", "ono", "orange",
    "livebox", "huawei", "tplink", "tp-link", "mitrastar", "askey",
    "fibra", "fibraoptica", "internet", "casa", "hogar",
]


def resolve_brand(oui_raw: str = "", ssid: str = "", scanned_brand: str = "") -> str:
    """Resuelve la marca: override lab > OUI verificado > escaneo > patrón SSID > Unknown."""
    oui = (oui_raw or "").replace(":", "").replace("-", "").upper()
    lab = _lab_overrides()
    if oui in lab:
        return lab[oui]
    if oui in OUI_HINTS:
        return OUI_HINTS[oui]
    if scanned_brand and scanned_brand.strip().lower() not in ("", "?", "unknown"):
        return scanned_brand.strip()
    s = (ssid or "").strip()
    for prefix, fleet in SSID_FLEET:
        if s.upper().startswith(prefix.upper()):
            return fleet
    return "Unknown"


# ─── Perfiles de fabricante del laboratorio ───────────────────────────────────

VENDOR_PROFILES: Dict[str, Dict] = {
    "Huawei": {
        "oem_notes": "Flota HG5xx/HG8xx (GPON/DSL) y CPE móviles. Firmware de operadora, "
                     "TR-069/TR-064 expuesto en LAN; historial de inyección de comandos.",
        "wps_behavior": "WPS activo por defecto en modelos viejos; PIN imprimible en etiqueta.",
        "default_creds_lan": ["admin/admin", "root/admin", "user/user", "telecomadmin/admintelecom"],
        "chipset_hint": "HiSilicon/Broadcom según generación",
    },
    "TP-Link": {
        "oem_notes": "Archer/CPE domésticos. Interfaz web en LAN con historial de RCE "
                     "autenticado y sin autenticar (TDP, locale). WPS con lockout parcial.",
        "wps_behavior": "WPS con PIN; algunos modelos sin lockout agresivo.",
        "default_creds_lan": ["admin/admin"],
        "chipset_hint": "Qualcomm Atheros / MediaTek según modelo",
    },
    "Askey": {
        "oem_notes": "OEM de HGUs de Telefónica/Movistar (RTF3505VW, RTF8115VW...). "
                     "Familias de PIN WPS predecibles por OUI y PSK de fábrica con "
                     "estructura derivada del SSID. Firmware bloqueado por ISP.",
        "wps_behavior": "PIN de fábrica por familia OUI — clase prioritaria para WPS_CLASS.",
        "default_creds_lan": ["1234/1234", "admin/1234"],
        "chipset_hint": "Broadcom/Realtek (Pixie-Dust sensible en serie RTL819x)",
    },
    "MitraStar": {
        "oem_notes": "OEM de HGUs Movistar (GPT-2541GNAC, GPT-2731GNAC...). Final de ZyXEL. "
                     "Credenciales LAN débiles de fábrica, WPS activo, telnet/HTTP en LAN.",
        "wps_behavior": "WPS activo por defecto; PIN en etiqueta, a menudo sin lockout.",
        "default_creds_lan": ["1234/1234", "admin/1234", "support/support"],
        "chipset_hint": "Broadcom/Econet según generación",
    },
    "ISP Fleet (HGU)": {
        "oem_notes": "Puerta de enlace de operadora (HGU): Askey/MitraStar/Huawei bajo "
                     "firma del ISP. Firmware solo vía TR-069 del operador.",
        "wps_behavior": "WPS activo de fábrica en la mayoría de despliegues.",
        "default_creds_lan": ["1234/1234", "admin/admin", "admin/1234"],
        "chipset_hint": "Variable por lote de fabricación",
    },
    "ISP Fleet (Legacy)": {
        "oem_notes": "Flota ADSL/fibra 2010-2016 (WLAN_XXXX, JAZZTEL_XXXX, ONOXXXX...). "
                     "Claves de fábrica DERIVADAS del SSID/BSSID con algoritmos "
                     "públicos desde ~2010: compromiso casi garantizado si no se cambió.",
        "wps_behavior": "WPS v1.0 sin lockout en la mayoría.",
        "default_creds_lan": ["admin/admin", "1234/1234"],
        "chipset_hint": "Atheros/Realtek/Ralink de la época (Pixie-Dust sensible)",
    },
    "Unknown": {
        "oem_notes": "Fabricante no identificado por OUI ni SSID: se aplica batería "
                     "genérica completa sin asumir familia de PIN.",
        "wps_behavior": "Desconocido: Pixie Dust primero si WPS v1.0.",
        "default_creds_lan": ["admin/admin"],
        "chipset_hint": "Desconocido",
    },
}

# ─── Base histórica: bugs que fueron zero-day y hoy son deuda ─────────────────
# detection: cómo los cubre AURIS hoy (offline).
#   fingerprint = se correlaciona por marca/flota y se reporta con remediación.
#   active      = prueba real en el laboratorio (tráfico propio, con scope).
#   candidates  = el motor de claves la ataca por construcción.

HISTORIC_VULNS: List[Dict] = [
    {
        "id": "CVE-2017-17215",
        "title": "Inyección de comandos TR-064 en Huawei HG532 (Mirai Okiru/Satori)",
        "year": 2017, "severity": "CRITICAL", "cvss": "9.8",
        "affected": ["Huawei HG532 y derivados HiSilicon"],
        "cause": "El servicio TR-064 (puerto 37215, UPnP) concatenaba el valor de "
                 "NewNTPServer1..5 en un comando shell sin sanear (';' + payload). "
                 "Explotable sin autenticación desde WAN/LAN: RCE como root.",
        "auris": "fingerprint: si la marca resuelve a Huawei, el informe exige "
                 "firmware post-2018 y bloqueo de TR-064 en WAN. Verificación activa "
                 "solo en LAN del laboratorio con autorización (guía en el informe).",
        "fix": "Firmware posterior a dic-2017; cerrar 37215/UPnP hacia WAN; ACL de "
               "gestión solo-LAN; rotar credenciales TR-069.",
        "detection": "fingerprint",
    },
    {
        "id": "CVE-2023-1389",
        "title": "RCE en TP-Link Archer AX21 vía parámetro de configuración (TDP)",
        "year": 2023, "severity": "HIGH", "cvss": "8.8",
        "affected": ["TP-Link Archer AX21 (y superficie similar en familia Archer)"],
        "cause": "Un campo de configuración expuesto al demonio de red local se "
                 "inyectaba en shell sin sanear: petición LAN artesanal = comandos "
                 "como root. Explotado por Mirai en campo.",
        "auris": "fingerprint: marca TP-Link → el informe exige firmware ≥1.1.4 "
                 "Build 20230219 y gestión remota desactivada.",
        "fix": "Actualizar a firmware corregido; desactivar gestión remota/WAN; "
               "segmentar IoT en red invitada.",
        "detection": "fingerprint",
    },
    {
        "id": "CVE-2014-8361",
        "title": "RCE miniigd UPnP del SDK Realtek (cientos de modelos OEM)",
        "year": 2014, "severity": "CRITICAL", "cvss": "10.0",
        "affected": ["Routers con SDK Realtek (TP-Link/D-Link/Askey antiguos y otros)"],
        "cause": "AddPortMapping/NewInternalClient del demonio miniigd pasaba la IP "
                 "a system() sin sanear: una petición UPnP = shell como root.",
        "auris": "fingerprint: flota legacy + UPnP típico → exigir firmware con "
                 "SDK parcheado y UPnP desactivado en WAN.",
        "fix": "Firmware con miniigd corregido; desactivar UPnP salvo necesidad; "
               "nunca exponer UPnP a WAN.",
        "detection": "fingerprint",
    },
    {
        "id": "CVE-2014-9222 / CVE-2014-9223 (Misfortune Cookie)",
        "title": "Bypass de autenticación + RCE en RomPager/Allegro (flotas SOHO)",
        "year": 2014, "severity": "CRITICAL", "cvss": "9.8",
        "affected": ["Múltiples routers SOHO/ISP con servidor RomPager < 4.34"],
        "cause": "Cookie de sesión predecible + heap overflow: tomar la web de "
                 "administración y escalar a ejecución remota.",
        "auris": "fingerprint: equipos legacy/EOL → el informe marca la web LAN "
                 "como superficie a re-auditar y exige RomPager ≥4.34.",
        "fix": "Firmware con RomPager ≥4.34; credenciales únicas de fábrica; "
               "HTTPS de gestión con certificado válido.",
        "detection": "fingerprint",
    },
    {
        "id": "CVE-2017-13077…13088 (KRACK)",
        "title": "Reinstalación de claves en el handshake WPA2 (todas las marcas)",
        "year": 2017, "severity": "HIGH", "cvss": "8.1",
        "affected": ["Todo WPA2 sin parche oct-2017: Huawei, TP-Link, Askey, MitraStar..."],
        "cause": "El 4-way handshake aceptaba retransmitir el mensaje 3 y "
                 "reinstalaba la PTK/GTK con nonce reutilizado: descifrado y "
                 "forja de tráfico sin conocer la PSK.",
        "auris": "candidates+fingerprint: toda red WPA2 de flota legacy/EOL se "
                 "reporta como 'probablemente sin parche KRACK' salvo firmware "
                 "verificado; la captura de handshake del path lo evidencia.",
        "fix": "Parches de oct-2017 en AP y clientes; migrar a WPA3-SAE; activar "
               "PMF (802.11w) donde exista.",
        "detection": "fingerprint",
    },
    {
        "id": "Pixie Dust (2014, sin CVE — fallo de diseño WPS)",
        "title": "Nonce predecibles en WPS v1.0 (Ralink/Realtek/Broadcom)",
        "year": 2014, "severity": "HIGH", "cvss": "7.4",
        "affected": ["APs con WPS v1.0 y chipset vulnerable (típico en flota legacy)"],
        "cause": "Los nonces E-S1/E-S2 del registro WPS eran débiles/predecibles: "
                 "con un intercambio se deriva el PIN sin fuerza bruta (minutos).",
        "auris": "active: path WPS_PIXIE con reaver -K sobre la interfaz monitor. "
                 "Si el AP es v1.0 y responde, la PSK cae en el laboratorio.",
        "fix": "Desactivar WPS por completo; en su defecto WPS v2.0 + lockout "
               "agresivo y PIN único por unidad.",
        "detection": "active",
    },
    {
        "id": "PIN WPS predecible por familia OEM (Askey/Arcadyan/HGU)",
        "title": "PINs WPS de fábrica generados por algoritmo por lote/OUI",
        "year": 2015, "severity": "HIGH", "cvss": "7.4",
        "affected": ["HGUs Askey/MitraStar de Telefónica/Movistar y OEMs hermanos"],
        "cause": "El PIN WPS de etiqueta salía de un generador determinista por "
                 "lote/OUI en vez de CSPRNG: con OUI+heurística se reduce el "
                 "espacio a familias probables (ataque por clase).",
        "auris": "active: path WPS_CLASS — detección de familia por OUI y prueba "
                 "de PINs de clase con bully/reaver en el laboratorio.",
        "fix": "PIN único aleatorio (CSPRNG) por unidad impreso en etiqueta; WPS "
               "desactivado por defecto; lockout tras 3 intentos.",
        "detection": "active",
    },
    {
        "id": "Claves ISP derivadas (WLAN_XXXX/JAZZTEL_XXXX/MOVISTAR_XXXX…)",
        "title": "PSK de fábrica = f(SSID/BSSID/serial), algoritmos públicos desde 2010",
        "year": 2010, "severity": "CRITICAL", "cvss": "9.1",
        "affected": ["Flotas Telefónica/Jazztel/ONO/Vodafone 2010-2016"],
        "cause": "La WPA de fábrica se derivaba del SSID visible o del BSSID con "
                 "algoritmos reversados y publicados: cualquiera que ve el SSID "
                 "recalcula la clave sin capturar nada.",
        "auris": "candidates: el motor SSID genera el lote estructural (base × "
                 "separador × sufijo + fragmentos OUI + reutilización entre "
                 "hermanos X/X2) y lo prueba offline con hashcat.",
        "fix": "PSK única aleatoria por unidad sin relación con SSID/MAC; forzar "
               "cambio en primer arranque; rotación en flota legacy.",
        "detection": "candidates",
    },
    {
        "id": "FragAttacks (2021, 12 CVEs: CVE-2020-24586… / CVE-2021-30038)",
        "title": "Fallos de fragmentación/agregación 802.11 (todas las marcas)",
        "year": 2021, "severity": "HIGH", "cvss": "8.1",
        "affected": ["Todo el ecosistema WiFi previo a parches 2021"],
        "cause": "Aceptar fragmentos sin borrar estado, mezclar fragmentos "
                 "cifrados de formas distintas y no validar A-MSDU: inyección de "
                 "tramas y exfiltración en redes WPA2/WPA3.",
        "auris": "fingerprint: todo equipo sin firmware ≥2021 se reporta como "
                 "potencialmente expuesto; se exige evidencia de parche.",
        "fix": "Firmware 2021+ en AP y clientes; PMF; validar A-MSDU y política "
               "de fragmentos en el driver.",
        "detection": "fingerprint",
    },
    {
        "id": "CVE-2019-15126 (Kr00k)",
        "title": "Claves todo-cero en chips Broadcom/Cypress al desasociar",
        "year": 2019, "severity": "HIGH", "cvss": "8.1",
        "affected": ["APs y clientes con WiFi Broadcom/Cypress (varias marcas)"],
        "cause": "Tras una desasociación, el chip cifraba el búfer restante con "
                 "clave temporal todo-ceros: forzar desasociaciones = leer restos.",
        "auris": "fingerprint: flotas con chipset Broadcom sin firmware ≥2020 "
                 "se marcan; el test de resiliencia (deauth controlado) es el "
                 "vector análogo en laboratorio.",
        "fix": "Firmware con driver corregido (2020+); PMF dificulta el trigger.",
        "detection": "fingerprint",
    },
    {
        "id": "CVE-2019-13377 (Dragonblood)",
        "title": "Degradación y side-channels en WPA3-SAE temprano",
        "year": 2019, "severity": "HIGH", "cvss": "8.1",
        "affected": ["Implementaciones SAE 2018-2019 en transición WPA2/WPA3"],
        "cause": "Downgrade a WPA2 forzable + curvas/grupos débiles + fugas por "
                 "tiempo/caché en el commit SAE: recuperar la contraseña por "
                 "observación.",
        "auris": "fingerprint: redes WPA3 en modo transición de flota vieja con "
                 "SAE temprano se reportan para re-auditoría de grupos y PMF.",
        "fix": "SAE actualizado, grupos ≥19, transición solo donde sea "
               "imprescindible, PMF requerido.",
        "detection": "fingerprint",
    },
    {
        "id": "CVE-2017-14491 (dnsmasq)",
        "title": "Heap overflow RCE en dnsmasq (DHCP/DNS de casi todo router)",
        "year": 2017, "severity": "CRITICAL", "cvss": "9.8",
        "affected": ["Routers con dnsmasq < 2.78 (prácticamente todas las marcas)"],
        "cause": "Opciones DHCPv6/RA mal validadas corrompían el heap del "
                 "demonio que corre como root: un cliente LAN malicioso = RCE.",
        "auris": "fingerprint: equipos EOL/legacy se reportan como portadores "
                 "probables de dnsmasq vulnerable; exige versión ≥2.78.",
        "fix": "dnsmasq ≥2.78 vía firmware;最小化 exposición de servicios LAN; "
               "firmware con ciclo de parches declarado.",
        "detection": "fingerprint",
    },
    {
        "id": "Mirai (2016) — credenciales telnet/SSH de fábrica",
        "title": "Botnet con ~60 pares user/pass por defecto de CPEs",
        "year": 2016, "severity": "CRITICAL", "cvss": "9.8",
        "affected": ["CPEs con telnet/SSH abierto y credenciales de fábrica "
                     "(Huawei, ZyXEL/MitraStar, D-Link, etc.)"],
        "cause": "Servicios de gestión expuestos con root/admin + password de "
                 "fábrica idéntica en millones de unidades.",
        "auris": "fingerprint: el informe lista las credenciales LAN por defecto "
                 "de la marca detectada y exige cambio forzado + cierre de "
                 "telnet/SSH en WAN.",
        "fix": "Credencial única por unidad; telnet/SSH cerrados por defecto y "
               "jamás en WAN; cambio obligatorio en primer acceso.",
        "detection": "fingerprint",
    },
]


def get_profile(brand: str) -> Dict:
    """Perfil de fabricante (falla a Unknown)."""
    return VENDOR_PROFILES.get(brand, VENDOR_PROFILES["Unknown"])


def intel_for(ssid: str = "", bssid: str = "", brand: str = "") -> Dict:
    """Paquete de inteligencia para un AP: marca, perfil y vulns aplicables."""
    resolved = resolve_brand("", ssid, brand) if not brand or brand == "Unknown" else brand
    if resolved not in VENDOR_PROFILES:
        resolved = resolve_brand("", ssid, "")
    profile = get_profile(resolved)

    legacy_markers = ("WLAN_", "JAZZTEL_", "ONO", "VODAFONE", "ORANGE-", "Livebox-")
    is_legacy = (ssid or "").upper().startswith(legacy_markers)
    is_hgu = resolved in ("Askey", "MitraStar", "ISP Fleet (HGU)", "ISP Fleet (Legacy)")

    applicable: List[Dict] = []
    for v in HISTORIC_VULNS:
        keep = False
        aff = " ".join(v["affected"]).lower()
        b = resolved.lower()
        if b.split()[0] in aff or "todas las marcas" in aff or "todo" in aff:
            keep = True
        if "legacy" in aff or "flota" in aff:
            keep = keep or is_legacy or is_hgu or resolved == "Unknown"
        if "hgu" in aff.lower() or "movistar" in aff.lower():
            keep = keep or is_hgu
        if keep:
            applicable.append(v)
    return {
        "brand": resolved,
        "profile": profile,
        "is_legacy_fleet": is_legacy,
        "is_hgu": is_hgu,
        "historic": applicable,
    }


def historic_coverage(result: str, key_type: Optional[str] = None) -> List[str]:
    """Clases históricas que un resultado AURIS demuestra (para el informe)."""
    cov: List[str] = []
    if result == "cracked":
        kt = (key_type or "").lower()
        if "familia" in kt or "lógica ssid" in kt:
            cov.append("Claves ISP derivadas (WLAN_XXXX/JAZZTEL_XXXX…) — clase 2010")
        if "rockyou" in kt or "diccionario" in kt:
            cov.append("PSK débil de diccionario (superficie Mirai/brute-force)")
        if "pin" in kt or "wps" in kt:
            cov.append("WPS predecible (clase Pixie Dust / PIN por familia OEM)")
        if not cov:
            cov.append("Compromiso de PSK (postura cripto de fábrica insuficiente)")
    elif result == "class_confirmed":
        cov.append("PIN WPS por familia OEM confirmado (clase Askey/Arcadyan)")
    elif result in ("locked", "exhausted", "not_found"):
        cov.append("Resiste batería actual — persisten clases KRACK/FragAttacks "
                   "si el firmware es anterior a 2021 (verificar versión)")
    return cov


def render_vendor_section_md(result: Dict) -> List[str]:
    """Sección Markdown por dispositivo: perfil + deuda histórica + defensa."""
    intel = result.get("vendor_intel") or {}
    brand = intel.get("brand", result.get("brand", "?"))
    profile = intel.get("profile", get_profile(brand))
    historic = intel.get("historic", [])
    cov = historic_coverage(result.get("result", ""), result.get("key_type"))

    lines = [
        f"#### Perfil de fabricante: {brand}",
        "",
        f"| Aspecto | Detalle |",
        f"|---|---|",
        f"| **Notas OEM** | {profile.get('oem_notes', 'N/D')} |",
        f"| **Comportamiento WPS** | {profile.get('wps_behavior', 'N/D')} |",
        f"| **Credenciales LAN de fábrica a rotar** | `{', '.join(profile.get('default_creds_lan', []))}` |",
        f"| **Chipset probable** | {profile.get('chipset_hint', 'N/D')} |",
        "",
        "**Clases históricas cubiertas por esta auditoría:**",
        "",
    ]
    for c in cov:
        lines.append(f"- {c}")
    lines += [
        "",
        "**Deuda histórica aplicable (bugs que fueron zero-day — qué falló, qué exige AURIS, cómo defenderse):**",
        "",
        "| ID / Año | Fallo técnico | Prueba AURIS | Defensa exigida |",
        "|---|---|---|---|",
    ]
    for v in historic:
        lines.append(
            f"| **{v['id']}** ({v['year']}, {v['severity']})<br>{v['title']} "
            f"| {v['cause']} | {v['auris']} | {v['fix']} |"
        )
    lines.append("")
    return lines


# ─── Base EOL / gobernanza de firmware (offline, cualitativa y honesta) ───────
# Desde WiFi NO se puede leer la versión de firmware: la evaluación es por
# clase de flota + bloqueo ISP. Cada veredicto dice QUÉ evidencia falta y
# DÓNDE obtenerla (HTTP admin, TR-069, etiqueta). Sin números de versión
# inventados: solo clases y rutas de verificación.

EOL_KB: Dict[str, Dict] = {
    "ISP Fleet (Legacy)": {
        "verdict": "eol_confirmed",
        "reasons": [
            "Hardware de flota 2010–2016: los OEM dejaron de publicar firmware hace años.",
            "Clases KRACK (2017), FragAttacks (2021) y dnsmasq RCE (2017) son posteriores "
            "al fin de soporte: ningún parche puede existir para este hardware.",
            "PSK de fábrica derivada del SSID (algoritmos públicos desde 2010).",
        ],
        "required_evidence": ["Ninguna adicional: la edad de la flota basta como argumento."],
        "action": "Reemplazo del equipo; si es imposible, aislar en VLAN invitada sin clientes sensibles.",
    },
    "Askey": {
        "verdict": "eol_confirmed",
        "reasons": [
            "Firmware bloqueado por el ISP: el usuario no puede verificar ni aplicar parches.",
            "PIN WPS por familia OEM + PSK estructural de fábrica (verificado por clase).",
            "Sin versión visible desde WiFi: se presume sin parchear KRACK/FragAttacks "
            "salvo que el ISP acredite versión con parches 2017+ y 2021+.",
        ],
        "required_evidence": [
            "Versión de firmware (HTTP admin LAN o requerimiento al ISP).",
            "Confirmación escrita del ISP de parches KRACK + FragAttacks.",
        ],
        "action": "Exigir al ISP firmware auditado o recambio por HGU con WPA3-SAE y WPS desactivado.",
    },
    "MitraStar": {
        "verdict": "eol_confirmed",
        "reasons": [
            "Firmware bloqueado por el ISP: el usuario no puede verificar ni aplicar parches.",
            "Credenciales LAN débiles de fábrica (1234/1234) + WPS activo + telnet/HTTP en LAN.",
            "Sin versión visible desde WiFi: se presume superficie Mirai/KRACK/FragAttacks "
            "salvo acreditación del ISP.",
        ],
        "required_evidence": [
            "Versión de firmware (HTTP admin LAN o requerimiento al ISP).",
            "Barrido AUDIT_LAN_SURFACE del gateway (telnet/TR-064/TR-069).",
        ],
        "action": "Rotar credenciales LAN, cerrar telnet, exigir firmware con parches al ISP.",
    },
    "Huawei": {
        "verdict": "needs_evidence",
        "reasons": [
            "Marca con historial crítico (CVE-2017-17215 TR-064, botnets Mirai).",
            "Desde WiFi no se distingue un HG532 sin parche (2017) de un modelo actual.",
        ],
        "required_evidence": [
            "Modelo exacto (etiqueta / HTTP admin) y fecha de firmware.",
            "Puerto 37215 cerrado hacia WAN (verificable en LAN con AUDIT_LAN_SURFACE).",
        ],
        "action": "Si es serie HG5xx sin parche 2017+: reemplazo inmediato; si es actual: hardening LAN.",
    },
    "TP-Link": {
        "verdict": "needs_evidence",
        "reasons": [
            "Historial RCE reciente (CVE-2023-1389 Archer) + SDK Realtek antiguo (CVE-2014-8361).",
            "Desde WiFi no se distingue generación ni versión.",
        ],
        "required_evidence": [
            "Modelo y build de firmware (etiqueta / web LAN).",
            "Gestión remota desactivada + firmware ≥ 2023 donde aplique.",
        ],
        "action": "Actualizar a build corregido; segmentar IoT en red invitada.",
    },
    "Unknown": {
        "verdict": "needs_evidence",
        "reasons": ["Sin identificar el OEM no se puede descartar ninguna clase histórica."],
        "required_evidence": [
            "Fijar marca en data/vendor_map.json tras identificar etiqueta/OUI.",
            "Versión de firmware vía HTTP admin.",
        ],
        "action": "Identificar primero; mientras tanto tratar como legacy (máxima precaución).",
    },
}


def eol_assessment(brand: str, ssid: str = "") -> Dict:
    """Evaluación EOL por flota. verdict: eol_confirmed | needs_evidence."""
    intel = intel_for(ssid=ssid, brand=brand)
    kb = EOL_KB.get(intel["brand"], EOL_KB["Unknown"])
    if intel["is_legacy_fleet"] and intel["brand"] not in EOL_KB:
        kb = EOL_KB["ISP Fleet (Legacy)"]
    return {
        "brand": intel["brand"],
        "verdict": kb["verdict"],
        "reasons": kb["reasons"],
        "required_evidence": kb["required_evidence"],
        "action": kb["action"],
    }


def render_eol_section_md(result: Dict) -> List[str]:
    """Bloque EOL por dispositivo ( reasons + evidencia faltante + acción)."""
    eol = result.get("eol_assessment")
    if not eol:
        return []
    lines = [
        "#### Gobernanza de firmware (EOL)",
        "",
        f"**Veredicto:** `{eol['verdict']}` — {eol['action']}",
        "",
        "**Fundamento:**",
        "",
    ]
    lines += [f"- {r}" for r in eol.get("reasons", [])]
    lines += ["", "**Evidencia requerida para cerrar el hallazgo:**", ""]
    lines += [f"- [ ] {e}" for e in eol.get("required_evidence", [])]
    lines.append("")
    return lines


# ─── Evaluación DPP / onboarding (por señales observables, sin internet) ──────
# DPP (Easy Connect) no expone versión por aire: se evalúan combinaciones
# riesgosas observables — modo transición, coexistencia WPS+DPP y stack
# temprano en flota legacy/bloqueada (clase Dragonblood 2019).

def dpp_assessment(brand: str, ssid: str = "", wpa3_supported: bool = False,
                   dpp_supported: bool = False, wps_enabled: bool = False,
                   encryption: str = "WPA2") -> Dict:
    """verdict: clear | needs_evidence | concern. Solo con dpp_supported."""
    intel = intel_for(ssid=ssid, brand=brand)
    signals: List[Dict] = []
    transition = dpp_supported and encryption == "WPA2" and wpa3_supported
    if transition:
        signals.append({"signal": "Modo transición WPA2/WPA3", "status": "warn",
                        "detail": "El AP acepta WPA2 y SAE a la vez: superficie de "
                                  "degradación forzada (clase Dragonblood CVE-2019-13377)."})
    if dpp_supported and wps_enabled:
        signals.append({"signal": "Coexistencia WPS + DPP", "status": "risk",
                        "detail": "Dos canales de onboarding conviviendo: el atacante usa "
                                  "el más débil (WPS). DPP no compensa un WPS vulnerable."})
    if dpp_supported and (intel["is_hgu"] or intel["is_legacy_fleet"]
                          or intel["brand"] in ("Askey", "MitraStar")):
        signals.append({"signal": "Stack DPP en flota ISP/bloqueada", "status": "risk",
                        "detail": "Firmwares HGU rara vez certifican Easy Connect reciente; "
                                  "presumir implementación temprana sin endurecer."})
    if not signals and dpp_supported:
        signals.append({"signal": "DPP aislado, WPA3 puro, sin WPS", "status": "ok",
                        "detail": "Configuración de onboarding correcta por lo observable."})
    levels = {"ok": 0, "warn": 1, "risk": 2}
    worst = max((levels[s["status"]] for s in signals), default=0)
    verdict = ["clear", "needs_evidence", "concern"][worst]
    return {
        "brand": intel["brand"], "verdict": verdict, "signals": signals,
        "fix": ("WPA3 puro (sin transición salvo necesidad), WPS desactivado, "
                "firmware con SAE actualizado y grupos >= 19."
                if verdict != "clear" else
                "Mantener: sin transición, sin WPS, firmware al día."),
    }


def render_dpp_section_md(result: Dict) -> List[str]:
    """Bloque DPP por dispositivo (solo si se evaluó)."""
    dpp = result.get("dpp_assessment")
    if not dpp or not dpp.get("signals"):
        return []
    icon = {"ok": "✅", "warn": "⚠️", "risk": "🔴"}
    lines = [
        "#### Onboarding DPP / Easy Connect",
        "",
        f"**Veredicto:** `{dpp['verdict']}`",
        "",
        "| Señal | Estado | Detalle |",
        "|---|---|---|",
    ]
    for s in dpp["signals"]:
        lines.append(f"| {s['signal']} | {icon.get(s['status'], '?')} {s['status']} | {s['detail']} |")
    lines += ["", f"**Defensa exigida:** {dpp['fix']}", ""]
    return lines
