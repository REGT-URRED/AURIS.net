"""
AURIS v2 — doctor.py
Verifica que el entorno de ejecución tiene todas las herramientas,
permisos y configuración necesarios antes de iniciar una auditoría.

No requiere internet. Funciona 100% offline.
"""
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional

# ─── Colores ANSI para terminal ────────────────────────────────────────────────
class C:
    OK    = "\033[92m"
    WARN  = "\033[93m"
    ERR   = "\033[91m"
    CYAN  = "\033[96m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    RESET = "\033[0m"

def ok(msg):   print(f"  {C.OK}[OK ]{C.RESET}  {msg}")
def warn(msg): print(f"  {C.WARN}[WARN]{C.RESET} {msg}")
def err(msg):  print(f"  {C.ERR}[ERR ]{C.RESET} {msg}")
def header(msg): print(f"\n{C.BOLD}{C.CYAN}── {msg} {C.RESET}")


@dataclass
class CheckResult:
    name: str
    status: str  # "ok" | "warn" | "error"
    detail: str


def check_binary(name: str, version_flag: str = "--version") -> CheckResult:
    """Verifica si un binario está disponible en el PATH."""
    path = shutil.which(name)
    if path is None:
        return CheckResult(name, "error", f"No encontrado en PATH")
    try:
        out = subprocess.run(
            [name, version_flag], capture_output=True, text=True, timeout=5
        )
        version_line = (out.stdout or out.stderr or "").splitlines()[0] if (out.stdout or out.stderr) else "v?"
        return CheckResult(name, "ok", f"{path} — {version_line[:60]}")
    except Exception as e:
        return CheckResult(name, "warn", f"Encontrado en {path} pero no responde: {e}")


def check_python_package(package: str) -> CheckResult:
    """Verifica si un paquete Python está instalado en el entorno activo."""
    try:
        __import__(package.replace("-", "_").split(">=")[0])
        return CheckResult(package, "ok", "Importado correctamente")
    except ImportError:
        return CheckResult(package, "error", "No disponible — ejecutar setup.sh")


def check_wifi_interfaces() -> List[CheckResult]:
    """Detecta interfaces WiFi y si soportan modo monitor."""
    results = []
    
    # Intentar con iw
    iw_path = shutil.which("iw")
    if not iw_path:
        results.append(CheckResult("WiFi Interface", "warn",
            "iw no encontrado — no se puede verificar adaptadores"))
        return results

    try:
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        lines = out.stdout.splitlines()
        ifaces = [l.strip().split()[1] for l in lines if "Interface" in l]
        
        if not ifaces:
            results.append(CheckResult("WiFi Interface", "error",
                "No se encontraron interfaces WiFi activas"))
        else:
            for iface in ifaces:
                # Verificar soporte de modo monitor
                phy_out = subprocess.run(
                    ["iw", iface, "info"], capture_output=True, text=True, timeout=5
                )
                
                cap_out = subprocess.run(
                    ["iw", "phy"], capture_output=True, text=True, timeout=5
                )
                monitor_supported = "monitor" in cap_out.stdout.lower()
                
                if monitor_supported:
                    results.append(CheckResult(f"  {iface}", "ok",
                        "Modo monitor soportado"))
                else:
                    results.append(CheckResult(f"  {iface}", "warn",
                        "Modo monitor no confirmado — verificar manualmente"))
    except Exception as e:
        results.append(CheckResult("WiFi Interface", "error", str(e)))

    return results


def check_wordlist(path: str) -> CheckResult:
    """Verifica rockyou contra su huella conocida (rápido, por tamaño)."""
    from .wordlists import quick_check
    r = quick_check(path)
    if r["status"] == "ok":
        return CheckResult("rockyou.txt", "ok", r["msg"])
    if r["status"] == "missing":
        if os.path.isfile(path + ".gz"):
            return CheckResult("rockyou.txt", "warn",
                f"Encontrada comprimida: {path}.gz — descomprimir con: gunzip -k {path}.gz")
        return CheckResult("rockyou.txt", "warn",
            f"No encontrada en {path} — path PSK_ROCKYOU quedará degradado")
    return CheckResult("rockyou.txt", "warn", r["msg"])


def check_scope(project_dir: str) -> CheckResult:
    """Verifica que existe un scope.yml configurado."""
    scope_path = os.path.join(project_dir, "config", "scope.yml")
    example_path = os.path.join(project_dir, "config", "scope.example.yml")
    
    if os.path.isfile(scope_path):
        # Verificar que no es el ejemplo sin editar
        with open(scope_path) as f:
            content = f.read()
        if "[universidad]" in content or "[docente]" in content:
            return CheckResult("scope.yml", "warn",
                "scope.yml existe pero aún tiene valores de ejemplo — edítalo antes de auditar")
        return CheckResult("scope.yml", "ok", scope_path)
    elif os.path.isfile(example_path):
        return CheckResult("scope.yml", "warn",
            f"Falta scope.yml — copiar y editar: cp {example_path} {scope_path}")
    else:
        return CheckResult("scope.yml", "error",
            "config/scope.yml no encontrado. Requerido antes de cualquier auditoría.")


def check_db(project_dir: str) -> CheckResult:
    """Verifica que la base de datos está inicializada."""
    db_path = os.path.join(project_dir, "data", "auris.db")
    if os.path.isfile(db_path) and os.path.getsize(db_path) > 0:
        return CheckResult("auris.db", "ok", f"{db_path}")
    else:
        return CheckResult("auris.db", "warn",
            "Base de datos no inicializada — ejecutar: python3 auris.py db-init")


def check_root() -> CheckResult:
    """Verifica si se está ejecutando con privilegios necesarios."""
    if os.geteuid() == 0:
        return CheckResult("root/sudo", "ok", "Ejecutando como root")
    else:
        return CheckResult("root/sudo", "warn",
            "No es root — hcxdumptool y cambio de canal requieren privilegios")


def run_doctor(project_dir: Optional[str] = None) -> bool:
    """
    Ejecuta todos los checks y retorna True si el entorno está listo.
    Retorna False si hay errores críticos.
    """
    if project_dir is None:
        project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

    print(f"\n{C.BOLD}{C.CYAN}╔══════════════════════════════════════════╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}║    AURIS v2 — Verificación de Entorno    ║{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}╚══════════════════════════════════════════╝{C.RESET}")
    
    results: List[CheckResult] = []
    has_errors = False

    # ── 1. Privilegios ────────────────────────────────────────────────────────
    header("Privilegios")
    r = check_root()
    results.append(r)

    # ── 2. Interfaces WiFi ────────────────────────────────────────────────────
    header("Interfaces WiFi")
    wifi_results = check_wifi_interfaces()
    results.extend(wifi_results)

    # ── 3. Herramientas del sistema ───────────────────────────────────────────
    header("Herramientas del sistema")
    tools = [
        ("hcxdumptool", "--version"),
        ("hcxpcapngtool", "--version"),
        ("hashcat",      "--version"),
        ("aircrack-ng",  "--version"),
        ("reaver",       "--version"),
        ("bully",        "--version"),
        ("wash",         "--help"),
        ("iw",           "--version"),
        ("macchanger",   "--version"),
    ]
    for tool, flag in tools:
        r = check_binary(tool, flag)
        results.append(r)

    # ── 4. Python y paquetes ──────────────────────────────────────────────────
    header("Python y dependencias")
    results.append(CheckResult("Python",
        "ok" if sys.version_info >= (3, 10) else "warn",
        f"{sys.version.split()[0]} en {sys.executable}"
    ))
    for pkg in ["typer", "pydantic", "sqlalchemy"]:
        results.append(check_python_package(pkg))

    # ── 5. Wordlists ──────────────────────────────────────────────────────────
    header("Wordlists")
    rockyou_paths = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        os.path.join(project_dir, "offline_bundle/wordlists/rockyou.txt"),
    ]
    found_rockyou = False
    for p in rockyou_paths:
        if os.path.isfile(p):
            results.append(check_wordlist(p.replace(".gz", "")))
            found_rockyou = True
            break
    if not found_rockyou:
        results.append(CheckResult("rockyou.txt", "warn",
            "No encontrada — path PSK_ROCKYOU degradado"))

    # ── 6. Configuración del proyecto ─────────────────────────────────────────
    header("Configuración del proyecto")
    results.append(check_scope(project_dir))
    results.append(check_db(project_dir))

    # ── Imprimir tabla de resultados ──────────────────────────────────────────
    print("")
    for r in results:
        if r.status == "ok":
            ok(f"{C.BOLD}{r.name:<22}{C.RESET}  {C.DIM}{r.detail}{C.RESET}")
        elif r.status == "warn":
            warn(f"{C.BOLD}{r.name:<22}{C.RESET}  {r.detail}")
        else:
            err(f"{C.BOLD}{r.name:<22}{C.RESET}  {r.detail}")
            has_errors = True

    # ── Resumen ───────────────────────────────────────────────────────────────
    errors  = sum(1 for r in results if r.status == "error")
    warnings = sum(1 for r in results if r.status == "warn")
    oks     = sum(1 for r in results if r.status == "ok")

    print(f"\n  {C.BOLD}Resumen:{C.RESET}  "
          f"{C.OK}{oks} OK{C.RESET}  "
          f"{C.WARN}{warnings} WARN{C.RESET}  "
          f"{C.ERR}{errors} ERROR{C.RESET}")

    if errors > 0:
        print(f"\n  {C.ERR}{C.BOLD}El entorno tiene errores críticos.{C.RESET}")
        print(f"  Ejecuta {C.CYAN}sudo bash setup.sh{C.RESET} para resolver.")
        return False
    elif warnings > 0:
        print(f"\n  {C.WARN}{C.BOLD}El entorno tiene advertencias — puede funcionar en modo degradado.{C.RESET}")
        return True
    else:
        print(f"\n  {C.OK}{C.BOLD}Entorno completamente listo.{C.RESET}"
              f" Edita config/scope.yml y ejecuta: python3 auris.py run-all --dry-run")
        return True
