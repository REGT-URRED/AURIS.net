#!/usr/bin/env bash
# =============================================================================
# AURIS v2 — setup.sh
# Script único de instalación para el equipo de campo (sin internet).
#
# Hace TODO automáticamente:
#   1. Detecta la distribución y el entorno
#   2. Instala herramientas del sistema desde .deb offline
#   3. Crea el entorno virtual Python
#   4. Instala las dependencias Python desde wheels offline
#   5. Configura e inicializa las wordlists
#   6. Inicializa la base de datos con semillas
#   7. Crea el comando global /usr/local/bin/auris
#   8. Auto-detecta la interfaz WiFi y configura scope.yml
#   9. Ejecuta `auris doctor` para verificar que todo funciona
#
# Uso (desde la raíz del proyecto descomprimido):
#   sudo bash setup.sh
# =============================================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ── Rutas ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"  # setup.sh está en la raíz del proyecto

BUNDLE_DIR="$PROJECT_DIR/offline_bundle"
APT_DIR="$BUNDLE_DIR/apt_packages"
WHEELS_DIR="$BUNDLE_DIR/wheels"
WORDLIST_DIR="$BUNDLE_DIR/wordlists"
VENV_DIR="$PROJECT_DIR/venv"
DATA_DIR="$PROJECT_DIR/data"
CONFIG_DIR="$PROJECT_DIR/config"
LOG_FILE="$PROJECT_DIR/setup.log"
WRAPPER="/usr/local/bin/auris"

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

_log()    { echo "$(date '+%H:%M:%S') $*" >> "$LOG_FILE"; }
info()    { echo -e "${CYAN}[....] $*${RESET}";     _log "[INFO] $*"; }
success() { echo -e "${GREEN}[ OK ] $*${RESET}";    _log "[ OK] $*"; }
warn()    { echo -e "${YELLOW}[WARN] $*${RESET}";   _log "[WARN] $*"; }
error()   { echo -e "${RED}[FAIL] $*${RESET}";      _log "[ERR] $*"; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}▶ $*${RESET}"; _log "[STEP] $*"; }

# ── Cabecera ──────────────────────────────────────────────────────────────────
clear 2>/dev/null || true  # sin TTY/TERM no debe matar la instalación (set -e)
echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  ╔══════════════════════════════════════════════════════════╗
  ║     AURIS v2 — Instalación Automática Offline           ║
  ║     Red/Blue Team WiFi Auditing Suite                   ║
  ║     Kali Linux / Parrot OS / Debian-based               ║
  ╚══════════════════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

echo "=== Setup iniciado: $(date --iso-8601=seconds) ===" > "$LOG_FILE"

# ── Verificaciones de entorno ──────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && error "Ejecutar como root: sudo bash setup.sh"

# Detectar distro
DISTRO="unknown"; DISTRO_VER="?"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"; DISTRO_VER="${VERSION_ID:-?}"
    info "Distribución: ${PRETTY_NAME:-$DISTRO $DISTRO_VER}"
else
    warn "No se detectó /etc/os-release. Asumiendo Debian-based."
fi

case "$DISTRO" in
    kali|parrot|debian|ubuntu|linuxmint|raspbian) ;;
    *) warn "Distribución '$DISTRO' no verificada. Continuando en modo Debian-compatible..." ;;
esac

# ── FASE 1: Paquetes del sistema ───────────────────────────────────────────────
step "FASE 1/8 — Herramientas del Sistema"

# Preseed debconf para instalación 100% desatendida (corrige bloqueo en macchanger
# que preguntaba "Change MAC automatically?" y colgaba setup.sh sin TTY).
if command -v debconf-set-selections >/dev/null 2>&1; then
    echo "macchanger macchanger/automatically_change_mac boolean false" | debconf-set-selections 2>>"$LOG_FILE" || true
fi
export DEBIAN_FRONTEND=noninteractive
export UCF_FORCE_CONFFOLD=1

APT_INSTALLED=0
APT_SKIPPED=0
APT_FAILED=0

if [[ -d "$APT_DIR" ]] && compgen -G "$APT_DIR/*.deb" > /dev/null 2>&1; then
    DEB_COUNT=$(ls "$APT_DIR"/*.deb 2>/dev/null | wc -l)
    info "Encontrados $DEB_COUNT paquetes .deb en bundle."

    # Filtrar por compatibilidad de glibc ANTES de tocar dpkg: instalar un .deb
    # que pide libc6 más nuevo deja el paquete a medias y traba dpkg.
    GLIBC_VER=$(ldd --version 2>/dev/null | head -1 | awk '{print $NF}')
    DEB_LIST=(); DEB_INCOMPAT=()
    for deb in "$APT_DIR"/*.deb; do
        # Nota: '|| true' es obligatorio — los .deb sin libc6 en Depends
        # (ca-certificates, fonts, tzdata...) hacen que grep salga 1 y con
        # 'set -e + pipefail' eso mataba setup.sh en silencio.
        need=$(dpkg-deb -f "$deb" Depends 2>/dev/null \
               | grep -oE 'libc6 \(>= [0-9]+\.[0-9]+[0-9.]*\)' \
               | sed -E 's/.*\(>= ([0-9.]+)\)/\1/' | sort -V | tail -1 || true)
        if [[ -n "$need" && -n "$GLIBC_VER" ]] && \
           ! dpkg --compare-versions "$need" le "$GLIBC_VER" 2>/dev/null; then
            DEB_INCOMPAT+=("$(basename "$deb")")
            continue
        fi
        DEB_LIST+=("$deb")
    done
    if [[ ${#DEB_INCOMPAT[@]} -gt 0 ]]; then
        warn "glibc del sistema: $GLIBC_VER — ${#DEB_INCOMPAT[@]} .deb omitidos por exigir libc6 mayor:"
        warn "  ${DEB_INCOMPAT[*]}"
    fi
    if [[ ${#DEB_LIST[@]} -eq 0 ]]; then
        warn "NINGÚN .deb del bundle es compatible con glibc $GLIBC_VER."
        warn "El bundle se generó para Kali 2024.2; en este sistema instala las"
        warn "herramientas con red una vez: sudo apt install hcxdumptool hcxtools"
        warn "aircrack-ng reaver iw macchanger wireless-tools ethtool rfkill"
        _log "APT: bundle incompatible con glibc $GLIBC_VER — nada instalado"
    fi
    info "Instalando ${#DEB_LIST[@]} paquetes compatibles..."

    # Instalar en lotes para mejor manejo de errores
    for deb in "${DEB_LIST[@]}"; do
        PKG_NAME=$(basename "$deb" | cut -d'_' -f1)
        if dpkg -l "$PKG_NAME" 2>/dev/null | grep -q "^ii"; then
            ((APT_SKIPPED++)) || true
        else
            if dpkg --install --force-depends "$deb" 2>>"$LOG_FILE"; then
                ((APT_INSTALLED++)) || true
            else
                ((APT_FAILED++)) || true
                _log "FAIL dpkg: $deb"
            fi
        fi
    done

    # Configurar todo lo desplegado (los .deb pueden quedar "unpacked" hasta
    # que sus dependencias del mismo lote están presentes).
    info "Configurando paquetes desplegados..."
    DEBIAN_FRONTEND=noninteractive dpkg --configure -a 2>>"$LOG_FILE" || true
    if [[ $APT_FAILED -gt 0 ]]; then
        info "Reparando dependencias rotas sin red..."
        apt-get -f install -y --no-download -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" 2>>"$LOG_FILE" || true
    fi

    success "APT: $APT_INSTALLED instalados, $APT_SKIPPED ya tenía, $APT_FAILED fallos."

    # Verificación real de binarios clave (no basta con que dpkg diga OK)
    TOOLS_CHECK=(hcxdumptool hcxpcapngtool aircrack-ng reaver iw macchanger wash)
    TOOLS_OK=(); TOOLS_NO=()
    for t in "${TOOLS_CHECK[@]}"; do
        if command -v "$t" >/dev/null 2>&1; then TOOLS_OK+=("$t"); else TOOLS_NO+=("$t"); fi
    done
    if [[ ${#TOOLS_OK[@]} -gt 0 ]]; then
        success "  Disponibles: ${TOOLS_OK[*]}"
    fi
    if [[ ${#TOOLS_NO[@]} -gt 0 ]]; then
        warn "  Aún ausentes: ${TOOLS_NO[*]}"
        warn "  (hashcat se instala aparte; sin él el crackeo PSK queda en 'skipped')"
    fi
    hashcat -I >/dev/null 2>&1 && success "  hashcat presente con backend OpenCL" || true
else
    warn "No se encontraron .deb en $APT_DIR"
    warn "Verificando qué herramientas están disponibles en el sistema..."

    MISSING_PKGS=()
    CHECK_PKGS=(aircrack-ng hcxdumptool hcxtools reaver hashcat iw wireless-tools python3 python3-pip python3-venv)
    for pkg in "${CHECK_PKGS[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            success "  $pkg — ya instalado"
        else
            warn "  $pkg — NO encontrado"
            MISSING_PKGS+=("$pkg")
        fi
    done

    if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
        warn "Herramientas faltantes: ${MISSING_PKGS[*]}"
        warn "El sistema puede funcionar en modo degradado."
    fi
fi

# ── FASE 2: Python — detectar versión ─────────────────────────────────────────
step "FASE 2/8 — Verificar Python"

PYTHON_BIN=""
MIN_VERSION="3.10"
for py in python3.12 python3.11 python3.10 python3; do
    if command -v "$py" &>/dev/null; then
        PY_VER=$("$py" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        if python3 -c "import sys; exit(0 if (sys.version_info >= (3,10)) else 1)" 2>/dev/null; then
            PYTHON_BIN="$py"
            success "Python $PY_VER encontrado: $(which $py)"
            break
        else
            warn "$py versión $PY_VER < $MIN_VERSION — buscando alternativa..."
        fi
    fi
done

[[ -z "$PYTHON_BIN" ]] && error "Python >= $MIN_VERSION no encontrado. Bundle requiere Python 3.10+. Instálalo manualmente."

# ── FASE 3: Entorno virtual (con fallback sin-venv) ────────────────────────────
step "FASE 3/8 — Entorno Virtual Python"

VENV_MODE="venv"
try_mkvenv() {
    rm -rf "$VENV_DIR"
    "$PYTHON_BIN" -m venv --system-site-packages "$VENV_DIR" 2>>"$LOG_FILE"
}

if [[ -d "$VENV_DIR" && -f "$VENV_DIR/bin/activate" ]] \
    && "$VENV_DIR/bin/python" -c "import sys" 2>/dev/null; then
    success "Entorno virtual existente está funcional."
else
    info "Creando entorno virtual..."
    if try_mkvenv && "$VENV_DIR/bin/python" -c "import sys" 2>/dev/null; then
        success "Entorno virtual creado: $VENV_DIR"
    else
        # Sin ensurepip/python3-venv: modo sistema (Kali mínima offline)
        warn "No se pudo crear venv (falta python3-venv/ensurepip)."
        warn "Modo sin-venv: se usará el Python del sistema."
        rm -rf "$VENV_DIR"
        VENV_MODE="system"
    fi
fi

if [[ "$VENV_MODE" == "venv" ]]; then
    # Activar para el resto del script
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    PYBIN="$VENV_DIR/bin/python"
    PIP_INSTALL=(pip install)
else
    # Sin pip en el sistema: arrancar pip desde el wheel del bundle (sin red).
    if ! "$PYTHON_BIN" -m pip --version &>/dev/null; then
        PIP_WHL=$(ls "$WHEELS_DIR"/pip-*.whl 2>/dev/null | head -1 || true)
        if [[ -n "$PIP_WHL" ]]; then
            info "pip no instalado — usando pip del bundle offline."
            PIP_BOOT="PYTHONPATH=$PIP_WHL $PYTHON_BIN -m pip"
            $PIP_BOOT --version &>/dev/null \
                || error "El pip del bundle no arranca. Instala python3-pip manualmente."
        else
            error "Sin pip en el sistema y sin pip-*.whl en bundle. Con internet una vez: apt install python3-pip ; sin red no se puede continuar."
        fi
    fi
    PYBIN="$PYTHON_BIN"
    if [[ -n "${PIP_BOOT:-}" ]]; then
        # shellcheck disable=SC2206
        PIP_INSTALL=($PIP_BOOT install --break-system-packages)
    else
        PIP_INSTALL=("$PYTHON_BIN" -m pip install --break-system-packages)
    fi
fi

# ── FASE 4: Dependencias Python ────────────────────────────────────────────────
step "FASE 4/8 — Dependencias Python (offline)"

PKGS_TO_INSTALL=(typer pydantic sqlalchemy pytest rich pyyaml click typing_extensions annotated-types)

if compgen -G "$WHEELS_DIR/*.whl" > /dev/null 2>&1; then
    WHEEL_COUNT=$(ls "$WHEELS_DIR"/*.whl 2>/dev/null | wc -l)
    info "Instalando desde $WHEEL_COUNT wheels locales (sin internet)..."

    # Verificar cuáles ya están instaladas (por import, válido en venv y sistema)
    MISSING_PY_PKGS=()
    for spec in "typer:typer" "pydantic:pydantic" "sqlalchemy:sqlalchemy" "pytest:pytest" "rich:rich" "pyyaml:yaml" "click:click" "typing_extensions:typing_extensions" "annotated-types:annotated_types"; do
        pkg="${spec%%:*}"; mod="${spec##*:}"
        if ! "$PYBIN" -c "import $mod" &>/dev/null 2>&1; then
            MISSING_PY_PKGS+=("$pkg")
        fi
    done

    if [[ ${#MISSING_PY_PKGS[@]} -eq 0 ]]; then
        success "Todas las dependencias Python ya están instaladas."
    else
        info "Instalando: ${MISSING_PY_PKGS[*]}"
        "${PIP_INSTALL[@]}" \
            --no-index \
            --find-links="$WHEELS_DIR" \
            --quiet \
            "${MISSING_PY_PKGS[@]}" 2>>"$LOG_FILE" \
            && success "Dependencias Python instaladas correctamente." \
            || {
                warn "Instalación offline falló para algunos paquetes. Intentando con opción --upgrade..."
                "${PIP_INSTALL[@]}" \
                    --no-index \
                    --find-links="$WHEELS_DIR" \
                    --upgrade \
                    "${PKGS_TO_INSTALL[@]}" 2>>"$LOG_FILE" \
                    && success "Dependencias instaladas con --upgrade." \
                    || warn "Algunas dependencias pueden faltar. Revisar setup.log."
            }
    fi
else
    warn "No se encontraron wheels en $WHEELS_DIR (bundle sin sección Python)."
    info "Verificando si el Python del sistema ya trae las dependencias..."
    SYS_MISSING=()
    # paquete pip -> módulo importable
    for spec in "typer:typer" "pydantic:pydantic" "sqlalchemy:sqlalchemy" "pytest:pytest" "rich:rich" "pyyaml:yaml" "click:click"; do
        pkg="${spec%%:*}"; mod="${spec##*:}"
        if ! "$PYBIN" -c "import $mod" &>/dev/null; then
            SYS_MISSING+=("$pkg")
        fi
    done
    if [[ ${#SYS_MISSING[@]} -eq 0 ]]; then
        success "Dependencias resueltas desde el sistema (venv con --system-site-packages). Modo degradado OK."
    else
        error "Faltan paquetes Python (${SYS_MISSING[*]}) y no hay wheels offline. En máquina CON internet ejecuta: bash scripts/bootstrap.sh ; luego re-copiar offline_bundle/ y repetir setup.sh."
    fi
fi

# ── FASE 5: Wordlists ─────────────────────────────────────────────────────────
step "FASE 5/8 — Wordlists"

SYSTEM_ROCKYOU="/usr/share/wordlists/rockyou.txt"
mkdir -p /usr/share/wordlists

# Orden de búsqueda de rockyou
ROCKYOU_SOURCES=(
    "/usr/share/wordlists/rockyou.txt"
    "/usr/share/wordlists/rockyou.txt.gz"
    "$WORDLIST_DIR/rockyou.txt"
    "$WORDLIST_DIR/rockyou.txt.gz"
)

ROCKYOU_READY=false
for src in "${ROCKYOU_SOURCES[@]}"; do
    if [[ -f "$src" ]]; then
        if [[ "$src" == *.gz ]]; then
            info "Descomprimiendo $src ..."
            if gunzip -c "$src" > "$SYSTEM_ROCKYOU" 2>>"$LOG_FILE"; then
                success "rockyou.txt instalada desde $src ($(du -sh "$SYSTEM_ROCKYOU" | cut -f1))"
            else
                warn "Fallo al descomprimir $src (¿disco lleno?) — probando siguiente fuente..."
                rm -f "$SYSTEM_ROCKYOU"
                continue
            fi
        elif [[ "$src" != "$SYSTEM_ROCKYOU" ]]; then
            if cp "$src" "$SYSTEM_ROCKYOU" 2>>"$LOG_FILE"; then
                success "rockyou.txt copiada a $SYSTEM_ROCKYOU ($(du -sh "$SYSTEM_ROCKYOU" | cut -f1))"
            else
                warn "Fallo al copiar $src (¿disco lleno?) — probando siguiente fuente..."
                continue
            fi
        else
            success "rockyou.txt ya presente: $SYSTEM_ROCKYOU ($(du -sh "$SYSTEM_ROCKYOU" | cut -f1))"
        fi
        ROCKYOU_READY=true
        break
    fi
done

"$ROCKYOU_READY" || warn "rockyou.txt no disponible. El modo PSK_ROCKYOU quedará degradado."

# Copiar wordlist lógica si existe en el bundle
if [[ -f "$WORDLIST_DIR/ssid_logic_template.txt" ]]; then
    cp "$WORDLIST_DIR/ssid_logic_template.txt" "$DATA_DIR/ssid_logic_template.txt" 2>/dev/null || \
        cp "$WORDLIST_DIR/ssid_logic_template.txt" "$PROJECT_DIR/ssid_logic_template.txt"
    success "Wordlist lógica CPE instalada."
fi

# ── FASE 6: Base de datos y semillas ──────────────────────────────────────────
step "FASE 6/8 — Base de Datos y Semillas"

mkdir -p "$DATA_DIR" "$PROJECT_DIR/evidence" "$PROJECT_DIR/reports"

cd "$PROJECT_DIR"
info "Inicializando base de datos SQLite..."
"$PYBIN" - << 'PYEOF'
import sys, os, csv
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath('.')), 'src'))
sys.path.insert(0, 'src')
try:
    from auris.db import init_db, Vendor
    session = init_db('data/auris.db')

    vendors_csv = 'data/seed/vendors.csv'
    if os.path.isfile(vendors_csv):
        count = 0
        with open(vendors_csv, newline='', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                if not session.query(Vendor).filter_by(oui=row['oui']).first():
                    session.add(Vendor(**{k: v for k, v in row.items() if v}))
                    count += 1
        session.commit()
        print(f"  Vendors cargados: {count}")
    print("  Base de datos lista: data/auris.db")
except Exception as e:
    print(f"  WARN: {e}")
    print("  La BD se inicializará al primer uso de 'auris db-init'")
PYEOF
success "Base de datos lista."

# ── FASE 7: Configuración de scope ────────────────────────────────────────────
step "FASE 7/8 — Configuración de Scope"

mkdir -p "$CONFIG_DIR"

# Auto-detectar interfaces WiFi disponibles
WIFI_IFACES=()
if command -v iw &>/dev/null; then
    while IFS= read -r iface; do
        WIFI_IFACES+=("$iface")
    done < <(iw dev 2>/dev/null | grep "Interface" | awk '{print $2}')
fi

if [[ ${#WIFI_IFACES[@]} -eq 0 ]]; then
    # Fallback: listar interfaces de red que no sean lo o eth
    while IFS= read -r iface; do
        [[ "$iface" =~ ^(lo|eth|enp|docker) ]] && continue
        WIFI_IFACES+=("$iface")
    done < <(ls /sys/class/net/ 2>/dev/null)
fi

IFACE_RED="${WIFI_IFACES[0]:-wlan0}"
IFACE_BLUE="${WIFI_IFACES[1]:-wlan1}"

if [[ ${#WIFI_IFACES[@]} -gt 0 ]]; then
    info "Interfaces WiFi detectadas: ${WIFI_IFACES[*]}"
    info "  Red Team (ofensiva): $IFACE_RED"
    info "  Blue Team (WIDS):    $IFACE_BLUE"
else
    warn "No se detectaron interfaces WiFi. Usando nombres por defecto (wlan0/wlan1)."
fi

# Crear scope.yml solo si no existe ya uno personalizado
SCOPE_FILE="$CONFIG_DIR/scope.yml"
SCOPE_EXAMPLE="$CONFIG_DIR/scope.example.yml"

if [[ ! -f "$SCOPE_FILE" ]]; then
    if [[ -f "$SCOPE_EXAMPLE" ]]; then
        # Copiar y reemplazar las interfaces detectadas
        sed \
            -e "s|iface_red_team: \"wlan0\"|iface_red_team: \"$IFACE_RED\"|g" \
            -e "s|iface_blue_team: \"wlan1\"|iface_blue_team: \"$IFACE_BLUE\"|g" \
            "$SCOPE_EXAMPLE" > "$SCOPE_FILE"
        success "scope.yml creado con interfaces auto-detectadas."
    else
        # Generar scope mínimo funcional
        cat > "$SCOPE_FILE" << EOF
study_title: "AURIS v2 — Auditoría de laboratorio"
institution: "Configurar"
lab_owned: true
authorization: "verbal"

allowed_bssids: []   # Vacío = auditar todo (modo laboratorio)

iface_red_team: "$IFACE_RED"
iface_blue_team: "$IFACE_BLUE"

wordlist_rockyou: "/usr/share/wordlists/rockyou.txt"
db_path: "data/auris.db"

disclosure:
  embargo_days: 90
EOF
        success "scope.yml mínimo generado."
    fi
    warn "IMPORTANTE: Editar $SCOPE_FILE con los BSSID autorizados antes de auditar."
else
    success "scope.yml ya existe — no se sobreescribe."
    # Validar que el scope heredado no venga con placeholders ni ventana vencida
    if grep -qE "\[universidad\]|\[docente\]|\[nombre\]|aa:bb:cc:dd:ee:ff" "$SCOPE_FILE" 2>/dev/null; then
        warn "scope.yml aún tiene valores de ejemplo (institución/BSSIDs). Edítalo antes de auditar."
    fi
    TW_END=$(grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' "$SCOPE_FILE" 2>/dev/null | tail -1 || true)
    if [[ -z "$TW_END" ]]; then
        warn "scope.yml sin time_window válida — run-all se bloqueará (RoE)."
    elif [[ "$TW_END" < "$(date +%F)" ]]; then
        warn "time_window vencida ($TW_END, hoy $(date +%F)) — run-all se bloqueará. Actualiza el rango en $SCOPE_FILE."
    fi
fi

# ── FASE 8: Comando global 'auris' ────────────────────────────────────────────
step "FASE 8/8 — Instalando comando global 'auris'"

cat > "$WRAPPER" << EOF
#!/usr/bin/env bash
# AURIS v2 — Wrapper global autogenerado por setup.sh
# Uso: sudo auris [comando] [opciones]
# Sin argumentos: ejecuta auditoría completa automática

AURIS_DIR="$PROJECT_DIR"
AURIS_VENV="$VENV_DIR"
AURIS_PY="$PYBIN"
AURIS_SCOPE="$SCOPE_FILE"

# Entorno Python (venv si existe, sistema en modo sin-venv)
if [[ -f "\$AURIS_VENV/bin/activate" ]]; then
    source "\$AURIS_VENV/bin/activate"
    AURIS_PY="\$AURIS_VENV/bin/python"
fi

# Verificar DB
if [[ ! -f "\$AURIS_DIR/data/auris.db" ]]; then
    echo "[INFO] Primera ejecución — Inicializando base de datos..."
    "\$AURIS_PY" "\$AURIS_DIR/auris.py" db-init
fi

# Lanzar AURIS
cd "\$AURIS_DIR"
if [[ "\$#" -eq 0 ]]; then
    # Comportamiento por defecto: ejecución totalmente automática
    exec "\$AURIS_PY" "\$AURIS_DIR/auris.py" run-all \\
        --iface "\$(python3 -c "import yaml; d=yaml.safe_load(open('$SCOPE_FILE')); print(d.get('iface_red_team','wlan0'))" 2>/dev/null || echo 'wlan0')" \\
        --scope-file "$SCOPE_FILE"
else
    exec "\$AURIS_PY" "\$AURIS_DIR/auris.py" "\$@"
fi
EOF
chmod +x "$WRAPPER"
success "Comando global instalado: $WRAPPER"

# ── Verificación final (doctor) ────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}── Verificación final del entorno ──────────────────────${RESET}"
cd "$PROJECT_DIR"
"$PYBIN" auris.py doctor 2>>"$LOG_FILE" || true

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║      AURIS v2 instalado correctamente       ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Para ejecutar (modo completo automático):${RESET}"
echo -e "  ${BOLD}${CYAN}sudo auris${RESET}"
echo ""
echo -e "  ${BOLD}Comandos disponibles:${RESET}"
echo -e "  ${CYAN}sudo auris doctor${RESET}          — Verificar entorno"
echo -e "  ${CYAN}sudo auris db-init${RESET}         — Reinicializar base de datos"
echo -e "  ${CYAN}sudo auris run-all${RESET}         — Ejecución completa"
echo -e "  ${CYAN}sudo auris run-all --dry-run${RESET}  — Solo mostrar paths"
echo ""
echo -e "  ${BOLD}Scope (BSSID autorizados):${RESET}"
echo -e "  ${DIM}$SCOPE_FILE${RESET}"
echo ""
echo -e "  ${BOLD}Log de instalación:${RESET}"
echo -e "  ${DIM}$LOG_FILE${RESET}"
echo ""
echo "=== Setup finalizado: $(date --iso-8601=seconds) ===" >> "$LOG_FILE"
