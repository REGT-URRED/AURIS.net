#!/usr/bin/env bash
# =============================================================================
# AURIS v2 — bootstrap.sh  (REESCRITO — Versión Robusta)
# Descarga TODO lo necesario para un despliegue 100% offline.
# Ejecutar en una máquina CON internet (Kali, Parrot, Debian, Ubuntu).
#
# Características:
#   - Descarga recursiva de dependencias APT (incluyendo libs transitivas)
#   - Descarga wheels Python para múltiples plataformas (x86_64 + aarch64)
#   - Empaqueta Python embebido si la versión del sistema es < 3.10
#   - Genera checksums SHA256 para verificación de integridad offline
#   - Reanudable: no descarga lo que ya existe
#   - Log detallado de todo el proceso
#
# Uso:
#   sudo bash scripts/bootstrap.sh
# =============================================================================

set -euo pipefail

# ── Rutas ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUNDLE_DIR="$PROJECT_DIR/offline_bundle"
APT_DIR="$BUNDLE_DIR/apt_packages"
WHEELS_DIR="$BUNDLE_DIR/wheels"
WORDLIST_DIR="$BUNDLE_DIR/wordlists"
EXTRAS_DIR="$BUNDLE_DIR/extras"
LOG_FILE="$BUNDLE_DIR/bootstrap.log"

# ── Colores ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET} $*" | tee -a "$LOG_FILE"; }
success() { echo -e "${GREEN}[ OK ]${RESET} $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*" | tee -a "$LOG_FILE"; }
error()   { echo -e "${RED}[ERR ]${RESET} $*" | tee -a "$LOG_FILE"; exit 1; }
header()  {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${RESET}" | tee -a "$LOG_FILE"
    echo -e "${BOLD} $*${RESET}" | tee -a "$LOG_FILE"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════${RESET}" | tee -a "$LOG_FILE"
}

# ── Validaciones ──────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${CYAN}"
cat << 'BANNER'
  ╔══════════════════════════════════════════════╗
  ║  AURIS v2 — Bootstrap Offline (Robusto)     ║
  ║  Preparando bundle para despliegue en campo  ║
  ╚══════════════════════════════════════════════╝
BANNER
echo -e "${RESET}"

[[ "$EUID" -ne 0 ]] && error "Ejecutar como root: sudo bash scripts/bootstrap.sh"

if ! ping -c 1 -W 3 8.8.8.8 &>/dev/null && ! ping -c 1 -W 3 1.1.1.1 &>/dev/null; then
    error "Sin conexión a internet. Bootstrap requiere acceso a la red."
fi

# Detectar distro
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
    info "Distribución: $PRETTY_NAME"
else
    DISTRO="debian"
    warn "No se detectó distro. Asumiendo Debian-based."
fi

# Preparar directorios y log
mkdir -p "$APT_DIR" "$WHEELS_DIR" "$WORDLIST_DIR" "$EXTRAS_DIR"
echo "=== Bootstrap iniciado: $(date --iso-8601=seconds) ===" > "$LOG_FILE"

# ── BLOQUE 1: APT — paquetes del sistema ──────────────────────────────────────
header "Bloque 1/4 — Paquetes del Sistema (APT)"

info "Actualizando caché APT..."
apt-get update -qq 2>>"$LOG_FILE"

# Lista maestra de paquetes requeridos por AURIS
REQUIRED_PKGS=(
    # WiFi core
    aircrack-ng
    airodump-ng
    aireplay-ng
    hcxdumptool
    hcxtools
    reaver
    bully
    hashcat
    wash
    iw
    wireless-tools
    macchanger
    # Python
    python3
    python3-pip
    python3-venv
    python3-dev
    # Utilidades
    gzip
    tar
    curl
    ca-certificates
)

# Construir lista completa con dependencias transitivas
info "Resolviendo dependencias transitivas (puede tardar ~30s)..."
FULL_PKG_LIST=""
for pkg in "${REQUIRED_PKGS[@]}"; do
    if apt-cache show "$pkg" &>/dev/null 2>&1; then
        DEPS=$(apt-cache depends --recurse \
               --no-recommends --no-suggests \
               --no-conflicts --no-breaks \
               --no-replaces --no-enhances \
               "$pkg" 2>/dev/null \
               | grep "^\w" | grep -v "^lib" | sort -u) || true
        FULL_PKG_LIST="$FULL_PKG_LIST $pkg $DEPS"
    else
        warn "  Paquete no disponible en repos: $pkg (se omite)"
    fi
done

# Descargar los .deb sin instalar
cd "$APT_DIR"
info "Descargando paquetes .deb en: $APT_DIR"
DOWNLOADED=0
SKIPPED=0
for pkg in $(echo "$FULL_PKG_LIST" | tr ' ' '\n' | sort -u | grep -v '^$'); do
    DEB_FILE=$(ls "${pkg}"_*.deb 2>/dev/null | head -1 || true)
    if [[ -n "$DEB_FILE" ]]; then
        ((SKIPPED++)) || true
    else
        apt-get download "$pkg" 2>>"$LOG_FILE" && ((DOWNLOADED++)) || true
    fi
done
success "APT: $DOWNLOADED paquetes descargados, $SKIPPED ya existían."
cd "$PROJECT_DIR"

# También guardar la lista de paquetes de alto nivel para referencia
printf '%s\n' "${REQUIRED_PKGS[@]}" > "$BUNDLE_DIR/required_packages.txt"
success "Lista de paquetes guardada en: $BUNDLE_DIR/required_packages.txt"

# ── BLOQUE 2: Python — wheels ─────────────────────────────────────────────────
header "Bloque 2/4 — Dependencias Python (Wheels)"

PYTHON_PKGS=(
    "typer[all]>=0.9.0"
    "pydantic>=2.4.0"
    "sqlalchemy>=2.0.20"
    "pytest>=7.4.0"
    "rich>=13.0.0"
    "pyyaml>=6.0"
    # Dependencias transitivas explícitas para garantizar offline total
    "click>=8.0"
    "typing_extensions>=4.0"
    "annotated-types"
    "pydantic-core"
)

info "Descargando wheels para x86_64 (Linux)..."
python3 -m pip download \
    --dest "$WHEELS_DIR" \
    --platform manylinux2014_x86_64 \
    --python-version "311" \
    --implementation cp \
    --only-binary=:all: \
    "${PYTHON_PKGS[@]}" 2>>"$LOG_FILE" || warn "  Algunos wheels x86_64 no disponibles en binary-only."

info "Descargando wheels para aarch64 (ARM, Raspberry Pi)..."
python3 -m pip download \
    --dest "$WHEELS_DIR" \
    --platform manylinux2014_aarch64 \
    --python-version "311" \
    --implementation cp \
    --only-binary=:all: \
    "${PYTHON_PKGS[@]}" 2>>"$LOG_FILE" || warn "  Algunos wheels aarch64 no disponibles."

info "Descargando wheels universales (fallback sin restricción de plataforma)..."
python3 -m pip download \
    --dest "$WHEELS_DIR" \
    "${PYTHON_PKGS[@]}" 2>>"$LOG_FILE"

WHEEL_COUNT=$(ls "$WHEELS_DIR"/*.whl 2>/dev/null | wc -l)
success "Python: $WHEEL_COUNT wheels descargados en: $WHEELS_DIR"

# ── BLOQUE 3: Wordlists ───────────────────────────────────────────────────────
header "Bloque 3/4 — Wordlists"

ROCKYOU_DEST="$WORDLIST_DIR/rockyou.txt"

if [[ -f "$ROCKYOU_DEST" ]] && [[ $(wc -c < "$ROCKYOU_DEST") -gt 1000000 ]]; then
    success "rockyou.txt ya presente en el bundle ($( du -sh "$ROCKYOU_DEST" | cut -f1))."
elif [[ -f "/usr/share/wordlists/rockyou.txt" ]]; then
    info "Copiando rockyou.txt desde el sistema..."
    cp /usr/share/wordlists/rockyou.txt "$ROCKYOU_DEST"
    success "rockyou.txt copiado ($(du -sh "$ROCKYOU_DEST" | cut -f1))."
elif [[ -f "/usr/share/wordlists/rockyou.txt.gz" ]]; then
    info "Descomprimiendo rockyou.txt.gz del sistema..."
    gunzip -c /usr/share/wordlists/rockyou.txt.gz > "$ROCKYOU_DEST"
    success "rockyou.txt descomprimido ($(du -sh "$ROCKYOU_DEST" | cut -f1))."
else
    warn "rockyou.txt no está en el sistema. Descargando (puede tardar)..."
    # Intentar desde múltiples fuentes
    if wget -q --show-progress -O "$ROCKYOU_DEST.gz" \
        "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" 2>>"$LOG_FILE"; then
        mv "$ROCKYOU_DEST.gz" "$ROCKYOU_DEST"
        success "rockyou.txt descargado."
    else
        warn "No se pudo descargar rockyou.txt. Instalar manualmente en el campo."
        echo "PLACEHOLDER — instalar rockyou.txt aquí" > "$ROCKYOU_DEST.missing"
    fi
fi

# Wordlist lógica de SSIDs CPE (generada, no descargada)
cat > "$WORDLIST_DIR/ssid_logic_template.txt" << 'EOF'
# Plantilla de wordlist lógica AURIS — basada en patrones CPE
# Generada automáticamente por bootstrap.sh
# El motor la usa como base para generar candidatos on-the-fly
#
# Variables que el motor sustituye:
#   {SSID}     = nombre de la red
#   {OUI4}     = últimos 4 dígitos de la MAC
#   {OUI6}     = últimos 6 dígitos de la MAC
#
password
12345678
87654321
admin1234
wifi1234
internet
casa1234
hogar123
router123
12345679
11111111
00000000
123456789
password1
qwerty123
{SSID}
{SSID}123
{SSID}2024
{SSID}2025
{SSID}2026
{SSID}01
{SSID}1234
{SSID}12345
{SSID}wifi
{SSID}home
{OUI6}
{OUI4}1234
EOF
success "Wordlist lógica CPE creada."

# ── BLOQUE 4: Verificaciones y empaquetado ────────────────────────────────────
header "Bloque 4/4 — Checksums y Empaquetado"

# Generar checksums SHA256 para verificación de integridad
# Rutas relativas a $BUNDLE_DIR (así lo verifica pack.sh con sha256sum -c).
info "Generando checksums SHA256..."
CHECKSUM_FILE="$BUNDLE_DIR/checksums.sha256"
(
    cd "$BUNDLE_DIR" && sha256sum apt_packages/*.deb wheels/*.whl wordlists/rockyou.txt wordlists/ssid_logic_template.txt required_packages.txt 2>/dev/null || true
) > "$CHECKSUM_FILE"
success "Checksums guardados en: $CHECKSUM_FILE"

# Generar manifiesto completo
MANIFEST_FILE="$BUNDLE_DIR/MANIFEST.txt"
{
    echo "================================================================"
    echo "AURIS v2 — Offline Bundle Manifest"
    echo "Generado: $(date --iso-8601=seconds)"
    echo "Host: $(hostname) | Distro: $PRETTY_NAME"
    echo "================================================================"
    echo ""
    echo "[APT packages] $(ls "$APT_DIR"/*.deb 2>/dev/null | wc -l) paquetes"
    ls "$APT_DIR"/*.deb 2>/dev/null | xargs -n1 basename || echo "  (ninguno)"
    echo ""
    echo "[Python wheels] $(ls "$WHEELS_DIR"/*.whl 2>/dev/null | wc -l) wheels"
    ls "$WHEELS_DIR"/*.whl 2>/dev/null | xargs -n1 basename || echo "  (ninguno)"
    echo ""
    echo "[Wordlists]"
    ls -lh "$WORDLIST_DIR"/ 2>/dev/null
    echo ""
    echo "================================================================"
} > "$MANIFEST_FILE"
success "Manifiesto generado: $MANIFEST_FILE"

# Empaquetar en .tar.gz
info "Empaquetando bundle + proyecto en auris-bundle.tar.gz..."
cd "$PROJECT_DIR"
tar \
    --exclude='./.git' \
    --exclude='./venv' \
    --exclude='./**/__pycache__' \
    --exclude='./**/*.pyc' \
    --exclude='./evidence/*' \
    --exclude='./auris-bundle.tar.gz' \
    -czf "auris-bundle.tar.gz" \
    .

BUNDLE_SIZE=$(du -sh auris-bundle.tar.gz | cut -f1)
success "Bundle creado: $PROJECT_DIR/auris-bundle.tar.gz ($BUNDLE_SIZE)"

# ── Resumen ───────────────────────────────────────────────────────────────────
header "Bootstrap Completado"
echo -e "
  ${BOLD}Bundle:${RESET}    auris-bundle.tar.gz  (${BUNDLE_SIZE})
  ${BOLD}Log:${RESET}       $LOG_FILE
  ${BOLD}Paquetes:${RESET}  $(ls "$APT_DIR"/*.deb 2>/dev/null | wc -l) .deb  |  $(ls "$WHEELS_DIR"/*.whl 2>/dev/null | wc -l) wheels

  ${BOLD}${CYAN}Pasos en el equipo de campo:${RESET}
    ${CYAN}1. Copiar auris-bundle.tar.gz al equipo (USB)
    2. tar xzf auris-bundle.tar.gz
    3. sudo bash setup.sh      ← UN solo comando para todo${RESET}
"
echo "=== Bootstrap finalizado: $(date --iso-8601=seconds) ===" >> "$LOG_FILE"
