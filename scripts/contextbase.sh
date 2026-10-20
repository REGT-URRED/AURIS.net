#!/usr/bin/env bash
# =============================================================================
# AURIS.net — contextbase.sh
# Wrapper del CLI ContextBase vendorizado en tools/contextbase.
# No requiere npm ni red: sólo Node.js >= 18 (paquete `nodejs` de la distro).
#
# Uso:
#   bash scripts/contextbase.sh status
#   bash scripts/contextbase.sh log "mensaje del cambio"
#   bash scripts/contextbase.sh task add "nueva tarea"
#   bash scripts/contextbase.sh task done "parte del texto"
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CLI="$PROJECT_DIR/tools/contextbase/bin/contextbase.js"

if [[ ! -f "$CLI" ]]; then
    echo "[ERR ] contextbase no encontrado en: $CLI" >&2
    echo "       Restaura el repositorio o ejecuta: git checkout -- tools/contextbase" >&2
    exit 1
fi

if ! command -v node >/dev/null 2>&1; then
    echo "[ERR ] Node.js no encontrado (contextbase lo necesita)." >&2
    echo "       Debian/Kali/Ubuntu: sudo apt install nodejs" >&2
    exit 1
fi

NODE_MAJOR="$(node -p "process.versions.node.split('.')[0]")"
if [[ "$NODE_MAJOR" -lt 18 ]]; then
    echo "[ERR ] Node.js $(node --version) es demasiado antiguo (se requiere >= 18)." >&2
    echo "       Actualiza: sudo apt install nodejs" >&2
    exit 1
fi

# contextbase resuelve rutas contra process.cwd(): siempre desde la raíz.
cd "$PROJECT_DIR"
exec node "$CLI" "$@"
