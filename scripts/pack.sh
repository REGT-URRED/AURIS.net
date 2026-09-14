#!/usr/bin/env bash
# =============================================================================
# AURIS v2 — pack.sh
# Genera el archivo .tar.gz final portable para llevar en USB.
#
# Uso: bash scripts/pack.sh [--solo-codigo] [nombre_salida]
#   --solo-codigo: empaqueta sin offline_bundle (transporte ligero 2 MB).
#     En la Kali CON internet: bootstrap.sh + verify-rockyou + pack.sh (full).
# =============================================================================

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODE_ONLY=0
if [[ "${1:-}" == "--solo-codigo" ]]; then
    CODE_ONLY=1
    shift
fi
OUTPUT_NAME="${1:-auris-bundle}"
[[ "$CODE_ONLY" -eq 1 && "$OUTPUT_NAME" == "auris-bundle" ]] && OUTPUT_NAME="auris-codigo"
OUTPUT_FILE="$PROJECT_DIR/${OUTPUT_NAME}.tar.gz"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET} $*"; }
success() { echo -e "${GREEN}[ OK ]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error()   { echo -e "${RED}[ERR ]${RESET} $*"; exit 1; }

echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════╗"
echo "  ║   AURIS v2 — Empaquetador offline   ║"
echo "  ╚══════════════════════════════════════╝"
echo -e "${RESET}"

cd "$PROJECT_DIR"

# Verificar que el bundle offline existe (solo en modo full)
if [[ "$CODE_ONLY" -eq 0 && ! -d "offline_bundle" ]]; then
    error "offline_bundle/ no encontrado. Opciones: bash scripts/pack.sh --solo-codigo (transporte) o scripts/bootstrap.sh (generar bundle con internet)"
fi
if [[ "$CODE_ONLY" -eq 1 ]]; then
    warn "Modo --solo-codigo: SIN offline_bundle. No sirve para campo offline directo."
    warn "Flujo: USB -> Kali con internet -> bootstrap.sh -> pack.sh (full) -> USB campo."
fi

# Verificar que setup.sh existe
if [[ ! -f "setup.sh" ]]; then
    error "setup.sh no encontrado en la raíz del proyecto."
fi

# Verificar checksums del bundle (integridad)
if [[ -f "offline_bundle/checksums.sha256" ]]; then
    info "Verificando integridad del bundle (checksums)..."
    cd offline_bundle
    if sha256sum -c checksums.sha256 --quiet 2>/dev/null; then
        success "Checksums verificados: bundle íntegro."
    else
        warn "Algunos checksums no coinciden. El bundle puede estar incompleto."
        warn "Considera ejecutar bootstrap.sh de nuevo."
    fi
    cd "$PROJECT_DIR"
fi

# Mostrar qué se va a empaquetar
if [[ -d "offline_bundle" ]]; then
    APT_COUNT=$(ls offline_bundle/apt_packages/*.deb 2>/dev/null | wc -l || true)
    WHL_COUNT=$(ls offline_bundle/wheels/*.whl 2>/dev/null | wc -l || true)
    info "Bundle: $APT_COUNT paquetes .deb | $WHL_COUNT wheels Python"
else
    info "Sin bundle (modo código)."
fi
info "Empaquetando en: $OUTPUT_FILE"

# Lista explícita: código + datos de ejemplo; fuera venv, basura y estado local
PACK_ITEMS=(./setup.sh ./auris.py ./requirements.txt ./LEEME-USB.txt
            ./src ./config ./scripts ./tests)
if [[ -f ./README.md ]]; then PACK_ITEMS+=(./README.md); fi
if [[ -f ./CHANGELOG.md ]]; then PACK_ITEMS+=(./CHANGELOG.md); fi
if [[ -d ./data ]]; then PACK_ITEMS+=(./data); fi
if [[ "$CODE_ONLY" -eq 0 && -d ./offline_bundle ]]; then PACK_ITEMS+=(./offline_bundle); fi

tar \
    --mtime='2026-01-01' \
    --exclude='./.git' \
    --exclude='./venv' \
    --exclude='./**/__pycache__' \
    --exclude='./**/*.pyc' \
    --exclude='./evidence/*' \
    --exclude='./reports/*' \
    --exclude='./data/sessions' \
    --exclude='./data/sessions/*' \
    --exclude='./data/*.db' \
    --exclude="./$OUTPUT_NAME.tar.gz" \
    -czf "$OUTPUT_FILE" \
    "${PACK_ITEMS[@]}"

BUNDLE_SIZE=$(du -sh "$OUTPUT_FILE" | cut -f1)
success "Bundle creado: $OUTPUT_FILE ($BUNDLE_SIZE)"

# Mostrar instrucciones de uso en campo
echo ""
echo -e "${BOLD}  ┌─ Cómo usar en el equipo de campo ──────────────────────────┐${RESET}"
echo -e "  │                                                              │"
echo -e "  │  1. ${CYAN}cp $OUTPUT_NAME.tar.gz /media/usb/${RESET} + LEEME-USB.txt"
echo -e "  │  2. En el equipo: ${CYAN}mkdir -p ~/auris && tar xzf $OUTPUT_NAME.tar.gz -C ~/auris && cd ~/auris${RESET}"
echo -e "  │  3. ${BOLD}${CYAN}sudo bash setup.sh${RESET}   ← instala todo automáticamente"
echo -e "  │  4. Editar ${CYAN}config/scope.yml${RESET} (BSSIDs + ventana) ← obligatorio"
echo -e "  │  5. ${BOLD}${CYAN}sudo auris doctor && sudo auris${RESET}"
echo -e "  │     Detalle paso a paso: ${CYAN}cat LEEME-USB.txt${RESET}"
echo -e "  │                                                              │"
echo -e "${BOLD}  └──────────────────────────────────────────────────────────────┘${RESET}"
echo ""
