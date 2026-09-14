#!/usr/bin/env bash
# =============================================================================
# AURIS v2 — install.sh
# Instalación OFFLINE en el equipo de campo.
# El equipo NO necesita conexión a internet.
#
# Prerequisito: haber descomprimido auris-bundle.tar.gz
# Uso: sudo bash scripts/install.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUNDLE_DIR="$PROJECT_DIR/offline_bundle"
APT_DIR="$BUNDLE_DIR/apt_packages"
WHEELS_DIR="$BUNDLE_DIR/wheels"
WORDLIST_DIR="$BUNDLE_DIR/wordlists"
VENV_DIR="$PROJECT_DIR/venv"
DB_PATH="$PROJECT_DIR/data/auris.db"
LOG_FILE="$PROJECT_DIR/install.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
success() { echo -e "${GREEN}[ OK ]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error()   { echo -e "${RED}[ERR ]${RESET} $*"; exit 1; }
step()    { echo -e "\n${BOLD}▶ $*${RESET}"; }

# ─── Comprobaciones previas ───────────────────────────────────────────────────
clear 2>/dev/null || true  # sin TTY/TERM no debe matar la instalación (set -e)
echo -e "${BOLD}${CYAN}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║     AURIS v2 — Instalador Offline     ║"
echo "  ║   Red/Blue Team WiFi Analysis Suite   ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${RESET}"

if [[ "$EUID" -ne 0 ]]; then
    error "Debe ejecutarse como root: sudo bash scripts/install.sh"
fi

# Detectar distro
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
    info "Distribución detectada: $PRETTY_NAME"
else
    DISTRO="unknown"
    warn "No se pudo detectar la distribución. Asumiendo Debian-based."
fi

# Verificar que el bundle existe
if [[ ! -d "$BUNDLE_DIR" ]]; then
    error "Bundle no encontrado en: $BUNDLE_DIR
  Asegúrate de haber descomprimido auris-bundle.tar.gz completo."
fi

# ─── PASO 1: Instalar paquetes del sistema desde .deb ─────────────────────────
step "Paso 1/5 — Instalando paquetes del sistema (offline)"

if [[ -d "$APT_DIR" ]] && ls "$APT_DIR"/*.deb &>/dev/null 2>&1; then
    info "Instalando $(ls "$APT_DIR"/*.deb | wc -l) paquetes .deb del bundle..."

    # Filtrar por glibc antes de tocar dpkg (un .deb con libc6 más nueva deja
    # el paquete a medias y traba dpkg)
    GLIBC_VER=$(ldd --version 2>/dev/null | head -1 | awk '{print $NF}')
    DEB_LIST=(); DEB_INCOMPAT=()
    for deb in "$APT_DIR"/*.deb; do
        need=$(dpkg-deb -f "$deb" Depends 2>/dev/null \
               | grep -oE 'libc6 \(>= [0-9]+\.[0-9]+[0-9.]*\)' \
               | sed -E 's/.*\(>= ([0-9.]+)\)/\1/' | sort -V | tail -1)
        if [[ -n "$need" && -n "$GLIBC_VER" ]] && \
           ! dpkg --compare-versions "$need" le "$GLIBC_VER" 2>/dev/null; then
            DEB_INCOMPAT+=("$(basename "$deb")")
            continue
        fi
        DEB_LIST+=("$deb")
    done
    if [[ ${#DEB_INCOMPAT[@]} -gt 0 ]]; then
        warn "glibc $GLIBC_VER — ${#DEB_INCOMPAT[@]} .deb omitidos (exigen libc6 mayor)"
    fi
    if [[ ${#DEB_LIST[@]} -eq 0 ]]; then
        warn "Ningún .deb del bundle es compatible con glibc $GLIBC_VER."
        warn "Bundle generado para Kali 2024.2 — instala con red: sudo apt install"
        warn "hcxdumptool hcxtools aircrack-ng reaver iw macchanger wireless-tools"
    fi

    # Instalar en un solo lote (dpkg ordena las dependencias internas)
    if dpkg -i "${DEB_LIST[@]}" 2>>"$LOG_FILE"; then
        success "Paquetes del sistema instalados."
    else
        warn "Algunos .deb no se instalaron (versiones ya presentes o base distinta)."
    fi

    # Configurar y reparar dependencias usando SOLO archivos locales
    dpkg --configure -a 2>>"$LOG_FILE" || true
    apt-get -f install -y --no-download 2>>"$LOG_FILE" || true

    # Verificación real de binarios
    TOOLS_OK=(); TOOLS_NO=()
    for t in hcxdumptool hcxpcapngtool aircrack-ng reaver wash iw macchanger; do
        if command -v "$t" >/dev/null 2>&1; then TOOLS_OK+=("$t"); else TOOLS_NO+=("$t"); fi
    done
    [[ ${#TOOLS_OK[@]} -gt 0 ]] && success "Disponibles: ${TOOLS_OK[*]}"
    [[ ${#TOOLS_NO[@]} -gt 0 ]] && warn "Aún ausentes: ${TOOLS_NO[*]}"
else
    warn "No se encontraron paquetes .deb en $APT_DIR"
    warn "Intentando instalar desde repositorios del sistema (si hay red)..."
    
    PKGS=(aircrack-ng hcxdumptool hcxtools reaver hashcat iw wireless-tools python3 python3-pip python3-venv)
    for pkg in "${PKGS[@]}"; do
        if ! dpkg -s "$pkg" &>/dev/null; then
            warn "  Falta: $pkg (instalar manualmente)"
        fi
    done
fi

# ─── PASO 2: Crear entorno virtual Python ─────────────────────────────────────
step "Paso 2/5 — Entorno virtual Python"

PYTHON_BIN=""
for py in python3.12 python3.11 python3.10 python3; do
    if command -v "$py" &>/dev/null; then
        PYTHON_BIN="$py"
        break
    fi
done

[[ -z "$PYTHON_BIN" ]] && error "Python3 no encontrado. Verifica la instalación de paquetes."

PY_VERSION=$($PYTHON_BIN --version 2>&1)
info "Usando: $PY_VERSION ($PYTHON_BIN)"

if [[ -d "$VENV_DIR" && -f "$VENV_DIR/bin/activate" ]]; then
    warn "Entorno virtual ya existe en $VENV_DIR — reutilizando."
    VENV_MODE="venv"
else
    rm -rf "$VENV_DIR"
    if "$PYTHON_BIN" -m venv --system-site-packages "$VENV_DIR" 2>/dev/null; then
        success "Entorno virtual creado: $VENV_DIR"
        VENV_MODE="venv"
    else
        warn "python3-venv no disponible (Kali mínima) — modo sistema sin-venv."
        warn "Se usará el Python del sistema con los wheels del bundle."
        VENV_MODE="system"
    fi
fi

# Intérprete y pip efectivos según modo (idéntico criterio que setup.sh)
if [[ "$VENV_MODE" == "venv" ]]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    PYBIN="$VENV_DIR/bin/python"
    PIP_INSTALL=(pip install --quiet)
else
    PYBIN="$PYTHON_BIN"
    PIP_WHL=$(ls "$WHEELS_DIR"/pip-*.whl 2>/dev/null | head -1 || true)
    if [[ -n "$PIP_WHL" ]] && ! command -v pip3 &>/dev/null; then
        export PYTHONPATH="$PIP_WHL${PYTHONPATH:+:$PYTHONPATH}"
    fi
    if "$PYBIN" -m pip --version &>/dev/null 2>&1; then
        PIP_INSTALL=("$PYBIN" -m pip install --quiet --break-system-packages)
    elif [[ -n "$PIP_WHL" ]]; then
        PIP_INSTALL=("$PYBIN" -m pip install --quiet --break-system-packages)
    else
        error "Sin pip disponible y sin wheel de pip en el bundle. Regenera con bootstrap.sh."
    fi
fi

# ─── PASO 3: Instalar dependencias Python offline ─────────────────────────────
step "Paso 3/5 — Dependencias Python (offline)"

if [[ -d "$WHEELS_DIR" ]] && ls "$WHEELS_DIR"/*.whl &>/dev/null 2>&1; then
    WHEEL_COUNT=$(ls "$WHEELS_DIR"/*.whl 2>/dev/null | wc -l)
    info "Instalando $WHEEL_COUNT wheels Python sin conexión..."
    "${PIP_INSTALL[@]}" \
        --no-index \
        --find-links="$WHEELS_DIR" \
        typer pydantic sqlalchemy pytest rich pyyaml
    success "Dependencias Python instaladas."
else
    warn "No se encontraron wheels en $WHEELS_DIR"
    info "Verificando si el Python del sistema ya trae las dependencias (sin red)..."
    SYS_MISSING=()
    for spec in "typer:typer" "pydantic:pydantic" "sqlalchemy:sqlalchemy" "pytest:pytest" "rich:rich" "pyyaml:yaml"; do
        pkg="${spec%%:*}"; mod="${spec##*:}"
        if ! "$PYBIN" -c "import $mod" &>/dev/null; then
            SYS_MISSING+=("$pkg")
        fi
    done
    if [[ ${#SYS_MISSING[@]} -eq 0 ]]; then
        success "Dependencias resueltas desde el sistema (venv con --system-site-packages). Modo degradado OK."
    else
        error "Faltan paquetes Python (${SYS_MISSING[*]}) y no hay wheels offline. En máquina CON internet ejecuta: bash scripts/bootstrap.sh ; luego re-copiar offline_bundle/ y repetir la instalación. (Este instalador nunca descarga solo: el campo es offline.)"
    fi
fi

# ─── PASO 4: Configurar wordlists ─────────────────────────────────────────────
step "Paso 4/5 — Wordlists"

SYSTEM_ROCKYOU="/usr/share/wordlists/rockyou.txt"
BUNDLE_ROCKYOU="$WORDLIST_DIR/rockyou.txt"
BUNDLE_ROCKYOU_GZ="$WORDLIST_DIR/rockyou.txt.gz"

if [[ -f "$SYSTEM_ROCKYOU" ]]; then
    success "rockyou.txt ya presente en el sistema: $SYSTEM_ROCKYOU"
elif [[ -f "$BUNDLE_ROCKYOU" ]]; then
    info "Instalando rockyou.txt desde bundle..."
    mkdir -p /usr/share/wordlists
    if cp "$BUNDLE_ROCKYOU" "$SYSTEM_ROCKYOU"; then
        success "rockyou.txt instalado en $SYSTEM_ROCKYOU"
    else
        warn "No se pudo copiar rockyou (¿disco lleno?) — se usará el bundle in-situ."
    fi
elif [[ -f "$BUNDLE_ROCKYOU_GZ" ]]; then
    info "Descomprimiendo rockyou.txt.gz desde bundle..."
    mkdir -p /usr/share/wordlists
    if gunzip -c "$BUNDLE_ROCKYOU_GZ" > "$SYSTEM_ROCKYOU"; then
        success "rockyou.txt instalado desde .gz"
    else
        warn "Descompresión fallida (¿disco lleno?) — se usará el bundle in-situ."
        rm -f "$SYSTEM_ROCKYOU"
    fi
elif [[ -f "/usr/share/wordlists/rockyou.txt.gz" ]]; then
    info "Descomprimiendo rockyou.txt.gz del sistema..."
    if gunzip -k /usr/share/wordlists/rockyou.txt.gz; then
        success "rockyou.txt descomprimido."
    else
        warn "Descompresión del sistema fallida — continúa sin rockyou del sistema."
    fi
else
    warn "rockyou.txt no disponible. El path PSK_ROCKYOU quedará degradado."
    warn "Instálala manualmente en /usr/share/wordlists/rockyou.txt"
fi

# ─── PASO 5: Inicializar base de datos y semillas ─────────────────────────────
step "Paso 5/5 — Base de datos y semillas"

mkdir -p "$PROJECT_DIR/data" "$PROJECT_DIR/evidence" "$PROJECT_DIR/reports"

cd "$PROJECT_DIR"
info "Inicializando base de datos SQLite..."
"$PYBIN" - <<'PYEOF'
import sys
sys.path.insert(0, 'src')
from auris.db import init_db
import csv, os

session = init_db('data/auris.db')

# Cargar semillas vendors
vendors_csv = 'data/seed/vendors.csv'
if os.path.isfile(vendors_csv):
    from auris.db import Vendor
    with open(vendors_csv, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            exists = session.query(Vendor).filter_by(oui=row['oui']).first()
            if not exists:
                session.add(Vendor(**{k: v for k, v in row.items() if v}))
    session.commit()
    print("[OK]   Vendors semilla cargados.")

print("[OK]   Base de datos auris.db lista.")
PYEOF

# Copiar scope de ejemplo si no existe
if [[ ! -f "$PROJECT_DIR/config/scope.yml" ]]; then
    mkdir -p "$PROJECT_DIR/config"
    cp "$PROJECT_DIR/config/scope.example.yml" "$PROJECT_DIR/config/scope.yml" 2>/dev/null || true
    warn "Recuerda editar config/scope.yml con tus BSSID autorizados."
fi

# ─── PASO 6: Crear wrapper global (comando "auris") ───────────────────────────
step "Paso 6/6 — Crear comando global 'auris'"

WRAPPER_PATH="/usr/local/bin/auris"
cat > "$WRAPPER_PATH" << EOF
#!/usr/bin/env bash
# Wrapper autogenerado para AURIS v2 (venv si existe, sistema si no)
AURIS_DIR="$PROJECT_DIR"
AURIS_VENV="$VENV_DIR"
AURIS_PY="$PYBIN"
AURIS_SCOPE="$PROJECT_DIR/config/scope.yml"
if [[ -f "\$AURIS_VENV/bin/activate" ]]; then
    source "\$AURIS_VENV/bin/activate"
    AURIS_PY="\$AURIS_VENV/bin/python"
fi
if [[ ! -f "\$AURIS_DIR/data/auris.db" ]]; then
    echo "[INFO] Primera ejecución — Inicializando base de datos..."
    "\$AURIS_PY" "\$AURIS_DIR/auris.py" db-init
fi
cd "\$AURIS_DIR"
if [ "\$#" -eq 0 ]; then
    # Por defecto, ejecución completamente automatizada (como wifite)
    exec "\$AURIS_PY" "\$AURIS_DIR/auris.py" run-all --scope-file "\$AURIS_SCOPE"
else
    # Si se pasan parámetros, respetarlos (ej. auris doctor)
    exec "\$AURIS_PY" "\$AURIS_DIR/auris.py" "\$@"
fi
EOF
chmod +x "$WRAPPER_PATH"
success "Comando global creado. Ahora puedes escribir 'auris' desde cualquier lugar."

# ─── Resumen ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Instalación completada exitosamente${RESET}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
echo ""
echo -e "  Para ejecutar el sistema completo de forma automática:"
echo -e "  ${CYAN}${BOLD}sudo auris${RESET}"
echo ""
echo -e "  Para verificar el entorno:"
echo -e "  ${CYAN}sudo auris doctor${RESET}"
echo ""
echo -e "${YELLOW}  IMPORTANTE: Editar ${BOLD}$PROJECT_DIR/config/scope.yml${RESET}${YELLOW} antes de auditar.${RESET}"
echo ""
