"""
AURIS v2 — cli.py
Interfaz de línea de comandos. 100% terminal, sin servidor web.

Flujo principal (un solo comando):
    sudo auris

Lo que hace internamente:
    wlan0 → MONITOR MODE (wlan0mon)
    → Scan (airodump-ng + wash)
    → Por cada red: PROFILE → STRIDE → EXEC secuencial
    → Informe Markdown + JSON en reports/
    → Restaurar wlan0
"""
import os
import csv
import time
import json
from typing import Dict, Optional

import typer
from rich.rule import Rule

from .models import TargetInfo, Profile
from .decision_engine import decide_path
from .terminal import banner, print_targets_table, print_summary_table, spinner, console
from .terminal import prompt_target_selection, parse_target_selection
from .runner import run_single_target, extract_reusable_psk
from .vendor_profiles import intel_for
from .monitor import enable_monitor_mode, disable_monitor_mode
from .scanner import scan_networks
from .report_writer import generate_markdown_report, generate_json_report

app = typer.Typer(
    help="AURIS v2 — Auditoría WiFi Secuencial (terminal)",
    no_args_is_help=True,
)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _load_scope(scope_path: str) -> dict:
    """Carga y valida scope.yml. YAML corrupto = error limpio, nunca traceback."""
    import yaml  # intento dinámico; si no hay pyyaml, fallback manual
    try:
        import yaml as _yaml
        with open(scope_path) as f:
            return _yaml.safe_load(f) or {}
    except ImportError:
        # Fallback: leer claves simples sin yaml
        scope = {}
        with open(scope_path) as f:
            for line in f:
                line = line.strip()
                if ":" in line and not line.startswith("#"):
                    k, _, v = line.partition(":")
                    scope[k.strip()] = v.strip()
        return scope
    except Exception as e:
        console.print(f"[red][ERR][/red] scope.yml corrupto ({e}) — revísalo con: python3 -c \"import yaml; yaml.safe_load(open('{scope_path}'))\"")
        raise typer.Exit(1)


def _apply_scope_filter(raw_targets: list, scope: dict) -> tuple:
    """Filtra por listas blancas BSSID+SSID. Retorna (targets, dropped, lab_mode).
    Sin lista blanca (vacía o placeholder) = modo wifite: pasa todo y la
    autorización la da el marcado posterior. Lanza typer.Exit(1) si con scope
    real no queda nada auditable."""
    allowed_bssids = scope.get("allowed_bssids", []) or []
    allowed_ssids = scope.get("allowed_ssids", []) or []
    lab_mode = not allowed_bssids or allowed_bssids == ["aa:bb:cc:dd:ee:ff"]
    if lab_mode:
        return raw_targets, 0, True
    filtered = [t for t in raw_targets if t["bssid"] in allowed_bssids]
    if allowed_ssids:
        filtered = [t for t in filtered if t.get("ssid") in allowed_ssids]
    if not filtered:
        console.print("[yellow][WARN][/yellow] Ninguna red encontrada en scope.")
        console.print(f"       Encontradas: {[t['bssid'] for t in raw_targets]}")
        raise typer.Exit(1)
    return filtered, len(raw_targets) - len(filtered), False


def _mock_scan_targets(iface: str, duration: int) -> list[dict]:
    """
    En Linux real: llama a hcxdumptool / wash / airodump-ng para escanear.
    En modo demo / sin herramientas: devuelve datos de prueba de laboratorio.
    """
    import shutil

    if shutil.which("wash"):
        console.print(f"  [dim]wash -i {iface} --scan ...[/dim]")
        import subprocess
        try:
            proc = subprocess.run(
                ["wash", "-i", iface, "--scan"],
                capture_output=True, text=True, timeout=duration
            )
            lines = [l for l in proc.stdout.splitlines() if ":" in l and len(l) > 20]
            targets = []
            for line in lines[1:]:  # skip header
                parts = line.split()
                if len(parts) >= 5:
                    targets.append({
                        "bssid": parts[0], "ssid": parts[4] if len(parts) > 4 else "?",
                        "channel": int(parts[1]) if parts[1].isdigit() else 6,
                        "encryption": "WPA2", "wps_enabled": True,
                        "wps_version": parts[3] if len(parts) > 3 else "?",
                        "oui": parts[0][:8], "signal_strength": -60, "brand": "?",
                    })
            if targets:
                return targets
        except Exception:
            pass

    # Demo/fallback para laboratorio — flota del laboratorio (5 routers)
    console.print("  [yellow]Modo demo — usando datos de laboratorio (no hay herramientas o iface)[/yellow]")
    return [
        {
            "bssid": "00:1C:DF:AA:BB:CC", "ssid": "MOVISTAR_AB12",
            "channel": 6, "encryption": "WPA2",
            "wps_enabled": True, "wps_version": "1.0", "wps_locked": False,
            "wpa3_supported": False, "dpp_supported": False,
            "oui": "00:1C:DF", "signal_strength": -55, "brand": "Askey",
        },
        {
            "bssid": "28:6C:07:11:22:33", "ssid": "MOVISTAR_PLUS_2",
            "channel": 1, "encryption": "WPA2",
            "wps_enabled": True, "wps_version": "2.0", "wps_locked": True,
            "wpa3_supported": False, "dpp_supported": False,
            "oui": "28:6C:07", "signal_strength": -62, "brand": "MitraStar",
        },
        {
            "bssid": "9C:C7:A6:44:55:66", "ssid": "HUAWEI-5GHT",
            "channel": 11, "encryption": "WPA2",
            "wps_enabled": True, "wps_version": "2.0", "wps_locked": False,
            "wpa3_supported": False, "dpp_supported": False,
            "oui": "9C:C7:A6", "signal_strength": -58, "brand": "Huawei",
        },
        {
            "bssid": "D4:CA:6D:DE:AD:BE", "ssid": "TP-Link_F845",
            "channel": 3, "encryption": "WPA2",
            "wps_enabled": False, "wps_version": None, "wps_locked": False,
            "wpa3_supported": True, "dpp_supported": True,
            "oui": "D4:CA:6D", "signal_strength": -48, "brand": "TP-Link",
        },
        {
            "bssid": "02:0F:B5:77:88:99", "ssid": "WLAN_9XQ2",
            "channel": 9, "encryption": "WPA",
            "wps_enabled": True, "wps_version": "1.0", "wps_locked": False,
            "wpa3_supported": False, "dpp_supported": False,
            "oui": "02:0F:B5", "signal_strength": -71, "brand": "Unknown",
        },
    ]


def _build_profile(target: dict) -> Profile:
    """Construye un perfil desde la BD (simplificado) o por heurística."""
    oui_raw = target.get("oui", "") or ""
    oui = oui_raw.replace(":", "").replace("-", "").upper()

    # Resolución de marca: OUI verificado > escaneo > patrón SSID de flota
    from .vendor_profiles import resolve_brand
    brand = resolve_brand(oui_raw, target.get("ssid", ""), target.get("brand", "Unknown"))

    # Heurísticas de clase de PIN por OUI conocido (formato normalizado sin ':')
    pin_class = "unknown"
    isp_locked = False

    askey_ouis = {"001CDF", "001F9F", "ACCC8A"}
    if oui in askey_ouis:
        pin_class = "generic_pin_family"
        isp_locked = True

    return Profile(
        brand=brand,
        model=None,
        pin_class=pin_class,
        isp_locked_fw=isp_locked,
        last_fw_known=None,
    )


# ─── Comandos ─────────────────────────────────────────────────────────────────

@app.command()
def doctor():
    """
    Verifica herramientas, adaptadores WiFi, wordlists y configuración.
    Ejecutar SIEMPRE antes de la primera auditoría.
    """
    from .doctor import run_doctor
    project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    ok = run_doctor(project_dir)
    raise typer.Exit(code=0 if ok else 1)


@app.command(name="db-init")
def db_init():
    """
    Inicializa la base de datos SQLite y carga semillas (OUI, catálogo CWE).
    """
    from .db import init_db, Vendor
    project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    db_path = os.path.join(project_dir, "data", "auris.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    console.print("[*] Inicializando base de datos...")
    session = init_db(db_path)

    vendors_csv = os.path.join(project_dir, "data", "seed", "vendors.csv")
    if os.path.isfile(vendors_csv):
        with open(vendors_csv, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                exists = session.query(Vendor).filter_by(oui=row["oui"]).first()
                if not exists:
                    session.add(Vendor(**{k: v for k, v in row.items() if v}))
                    count += 1
        session.commit()
        console.print(f"[green][+][/green] {count} vendors semilla cargados.")
    else:
        console.print("[yellow][WARN][/yellow] data/seed/vendors.csv no encontrado.")

    console.print(f"[green][+][/green] Base de datos lista: {db_path}")


@app.command(name="verify-rockyou")
def verify_rockyou(
    wordlist: str = typer.Option("", help="Ruta a rockyou.txt (auto-detecta si vacío)"),
):
    """
    Conteo profundo de rockyou.txt contra su huella canónica (~14.34M líneas).
    Tarda ~20 s. Ejecutar en la máquina con internet antes de empaquetar el bundle.
    """
    from .wordlists import find_rockyou, deep_count, quick_check
    project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    path = find_rockyou(project_dir, wordlist)
    if not path:
        console.print("[red][ERR][/red] rockyou.txt no encontrada (Kali: /usr/share/wordlists/, bundle, data/)")
        raise typer.Exit(1)
    console.print(f"  [dim]Rápido:[/dim] {quick_check(path)['msg']}")
    with console.status("[cyan]Contando líneas (14M, ~20 s)...[/cyan]"):
        r = deep_count(path)
    style = "green" if r["status"] == "ok" else "yellow"
    console.print(f"  [{style}]{r['msg']}[/{style}]")
    if r["status"] != "ok":
        raise typer.Exit(1)


@app.command(name="hal")
def hal_command():
    """
    Muestra información de la capa de abstracción de hardware (HAL Wifite4):
    chipsets reconocidos (Atheros, Realtek, Mediatek, Ralink, Intel) y adaptadores detectados.
    """
    from rich.table import Table
    from .hal import detect_adapters, CHIPSET_REGISTRY

    console.print(Rule("[bold cyan]HAL — Hardware Abstraction Layer (Wifite4)[/bold cyan]", style="cyan"))

    # 1. Adaptadores detectados
    adapters = detect_adapters()
    console.print(f"\n[bold]Adaptadores detectados:[/bold] {len(adapters)}")
    if adapters:
        table_adapters = Table(show_header=True, header_style="bold cyan")
        table_adapters.add_column("ID USB", style="dim")
        table_adapters.add_column("Fabricante")
        table_adapters.add_column("Producto")
        table_adapters.add_column("Chipset")
        table_adapters.add_column("Bandas")
        table_adapters.add_column("Monitor", justify="center")
        table_adapters.add_column("Inyección", justify="center")
        for a in adapters:
            mon = "[green]SÍ[/green]" if a.supports_monitor else "[red]NO[/red]"
            inj = "[green]SÍ[/green]" if a.supports_injection else "[red]NO[/red]"
            table_adapters.add_row(
                a.usb_id,
                a.manufacturer,
                a.product_name,
                a.chipset,
                "/".join(a.bands),
                mon,
                inj,
            )
        console.print(table_adapters)
    else:
        console.print("  [dim]Sin adaptadores USB wireless detectados activamente.[/dim]")

    # 2. Catálogo de chipsets soportados
    console.print(f"\n[bold]Catálogo de Chipsets Soportados ({len(CHIPSET_REGISTRY)} modelos):[/bold]")
    table_chipsets = Table(show_header=True, header_style="bold cyan")
    table_chipsets.add_column("USB ID", style="dim")
    table_chipsets.add_column("Chipset", style="bold")
    table_chipsets.add_column("Fabricante")
    table_chipsets.add_column("Producto Conocido")
    table_chipsets.add_column("Bandas")
    table_chipsets.add_column("Inyección", justify="center")
    for (vid, pid), c in CHIPSET_REGISTRY.items():
        inj = "[green]SÍ[/green]" if c.supports_injection else "[red]NO[/red]"
        bands = "/".join(c.bands)
        table_chipsets.add_row(
            c.usb_id,
            c.chipset,
            c.manufacturer,
            c.product_name,
            bands,
            inj,
        )
    console.print(table_chipsets)


@app.command(name="candidates")
def candidates_command(
    ssid: str = typer.Argument(..., help="SSID para generar candidatos"),
    bssid: str = typer.Option("00:11:22:33:44:55", help="BSSID de referencia"),
    brand: Optional[str] = typer.Option(None, help="Fabricante del AP (opcional)"),
    limit: int = typer.Option(30, help="Límite de candidatos a mostrar"),
):
    """
    Genera candidatos heurísticos de clave WiFi para investigación (Wifite4).
    """
    from rich.table import Table
    from .generator import generate_candidates

    console.print(Rule(f"[bold cyan]Generador Heurístico — {ssid}[/bold cyan]", style="cyan"))
    cset = generate_candidates(ssid=ssid, bssid=bssid, brand=brand, max_candidates=limit)

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Candidato", style="bold green")
    table.add_column("Longitud", justify="right")

    cand_list = list(cset.all_candidates())[:limit]
    for i, cand in enumerate(cand_list, 1):
        table.add_row(str(i), cand, str(len(cand)))

    console.print(table)
    gen_time = cset.meta.get("generation_timestamp", "?")
    console.print(f"\n  [dim]Total generados: {cset.total} | SSID: {cset.ssid} | Semillas: {gen_time}[/dim]")


@app.command(name="run-all")
def run_all(
    iface: str = typer.Option("wlan0", help="Interfaz WiFi (modo monitor) para Red Team"),
    wids_iface: Optional[str] = typer.Option(None, help="Segunda interfaz para WIDS (Blue Team). Opcional."),
    scan_duration: int = typer.Option(25, help="Segundos de escaneo inicial de redes (estilo wifite: 20-30s)"),
    scope_file: str = typer.Option("config/scope.yml", help="Archivo de scope RoE"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Mostrar path sin ejecutar fases aéreas"),
    target_bssid: Optional[str] = typer.Option(None, help="Auditar solo este BSSID (omitir scan)"),
    force_roe: bool = typer.Option(False, "--force-roe", help="Saltar dry_run_default del scope (firma RoE requerida)"),
    allow_lan: bool = typer.Option(False, "--allow-lan", help="Permitir sondeo LAN del gateway (solo lectura, requiere lab_lan_gateway)"),
    resume_last: bool = typer.Option(False, "--resume-last", help="Continuar la última sesión (omite BSSIDs ya completados)"),
    resume_file: str = typer.Option("", help="Continuar una sesión concreta (data/sessions/sesion_<ts>.json)"),
    select: bool = typer.Option(True, "--select/--no-select", help="Pausar tras el scan para marcar redes (estilo wifite). --no-select = todas automático."),
    targets: str = typer.Option("", help="Selección no interactiva: '1,3-5,all' (para scripts/offline auto)"),
    all_targets: bool = typer.Option(False, "--all", help="Auditar todas sin preguntar (atajo de --no-select)"),
):
    """
    Automatización completa estilo wifite: escanea, deja marcar y audita en secuencia.

    Flujo secuencial automático:
      1. Escanear redes en el aire (20-30s, el escáner se detiene solo)
      2. Marcar redes objetivo (prompt interactivo o --targets/--all/--no-select)
      3. Por cada red marcada: PROFILE → STRIDE → DECIDE → EXEC → REPORT
      4. Resumen final de toda la sesión
    """
    project_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    banner()

    # ── Verificar scope ────────────────────────────────────────────────────────
    scope_path = os.path.join(project_dir, scope_file)
    if not os.path.isfile(scope_path):
        console.print(f"[red][ERR][/red] scope.yml no encontrado: {scope_path}")
        console.print(f"       cp config/scope.example.yml config/scope.yml")
        raise typer.Exit(1)

    scope = _load_scope(scope_path)

    # ── Puerta RoE fase A: la ventana temporal se exige SIEMPRE, antes del
    # scan. La firma (dry_run/--force-roe/selección) se resuelve en fase B,
    # tras marcar objetivos — flujo wifite: no hay que saber BSSIDs antes.
    from .roe import enforce_scope, verify_mac_stable, RoEError
    try:
        roe_ctx = enforce_scope(scope, dry_run=True, force_roe=force_roe)
    except RoEError as e:
        console.print(f"[red][RoE BLOQUEO][/red] {e}")
        raise typer.Exit(2)
    session_mac = roe_ctx.get("iface_mac")
    if roe_ctx.get("window_bypassed"):
        console.print(f"  [bold red][RoE][/bold red] [red]{roe_ctx.get('window')}[/red]")
    else:
        console.print(f"  [green][RoE][/green] [dim]{roe_ctx.get('window')}[/dim]")

    # ── Sesión reanudable ────────────────────────────────────────────────────
    from .session import new_session, save_progress, load_session, latest_session
    resumed: Dict[str, dict] = {}
    rpath = resume_file or (latest_session(project_dir) if resume_last else None)
    if (resume_file or resume_last) and not rpath:
        console.print("[yellow][Resume][/yellow] no hay sesión previa que continuar")
    if rpath:
        prev = load_session(rpath)
        if prev:
            for r in prev.get("completed", []):
                r["resumed"] = True
                resumed[(r.get("bssid") or "").upper()] = r
            console.print(f"  [cyan][Resume][/cyan] {len(resumed)} APs recuperados de {rpath}")
    sess = new_session(project_dir)
    console.print(f"  [dim]Sesión: {sess['path']}[/dim]")

    # ── PASO 1: Activar modo monitor ───────────────────────────────────────────
    console.print(Rule("[bold cyan]Paso 1/4 — Modo Monitor[/bold cyan]", style="cyan"))
    mon_iface = None
    nm_touched = False

    try:
        if not dry_run:
            res = enable_monitor_mode(iface, kill_procs=True)
            # Compat: enable ahora retorna (mon, nm_tocado); fallback si alguien
            # llama desde test con mock que retorna string.
            if isinstance(res, tuple):
                mon_iface, nm_touched = res
            else:
                mon_iface = res  # type: ignore
            if mon_iface is None:
                from .monitor import list_wireless_ifaces
                hw = list_wireless_ifaces()
                if not hw:
                    console.print("  [yellow][WARN] Sin hardware wireless — modo demo (sin monitor).[/yellow]")
                    mon_iface = iface
                else:
                    console.print(f"  [red][ERR] Modo monitor falló con hardware presente — ver diagnóstico arriba.[/red]")
                    console.print("  [dim]Abortando sin escanear un interfaz muerto. "
                                  "Recupera con: sudo airmon-ng stop wlan0mon; "
                                  "sudo systemctl restart NetworkManager[/dim]")
                    raise typer.Exit(2)
        else:
            mon_iface = iface
            console.print(f"  [dim][DRY RUN] Modo monitor omitido (iface: {iface})[/dim]")

        scan_iface = mon_iface

        # ── PASO 2: Escanear redes ─────────────────────────────────────────────
        console.print(Rule("[bold cyan]Paso 2/4 — Escaneo de Redes[/bold cyan]", style="cyan"))

        if target_bssid:
            console.print(f"  [dim]Target fijo: {target_bssid}[/dim]")
            raw_targets = [{
                "bssid": target_bssid, "ssid": "TARGET", "channel": 6,
                "encryption": "WPA2", "wps_enabled": True, "wps_version": "1.0",
                "wps_locked": False, "wpa3_supported": False, "dpp_supported": False,
                "oui": target_bssid.replace(":", "")[:6], "signal_strength": -60,
                "brand": "?", "clients": 0, "beacons": 0, "data_frames": 0,
            }]
        else:
            console.print(f"  Escaneando en [cyan]{scan_iface}[/cyan] durante [cyan]{scan_duration}s[/cyan]...")
            raw_targets = scan_networks(scan_iface, scan_duration)

        # Filtrar por scope (BSSID y SSID; modo lab solo avisa)
        raw_targets, dropped, lab_mode = _apply_scope_filter(raw_targets, scope)
        if lab_mode:
            console.print("[yellow][SELECT][/yellow] modo wifite — sin lista blanca previa: TÚ autorizas marcando tras el scan.")
        elif dropped:
            console.print(f"  [dim]Scope: {dropped} red(es) fuera de lista blanca omitidas[/dim]")

        print_targets_table(raw_targets)

        # ── PASO 2b: Selección estilo wifite (el escáner ya se detuvo) ───────
        # Pase libre: el usuario marca qué redes auditar y el resto corre solo.
        # Esa marca explícita ES la firma RoE (no hacen falta BSSIDs previos).
        consent_explicit = False
        if target_bssid:
            pass  # target fijo: sin selección
            consent_explicit = True  # BSSID nombrado explícitamente = firma
        elif targets.strip():
            picked = parse_target_selection(targets, len(raw_targets))
            if not picked:
                console.print(f"  [yellow][SELECT] '--targets {targets}' no matchea 1-{len(raw_targets)}. Abortando.[/yellow]")
                return
            console.print(f"  [cyan][SELECT][/cyan] {len(picked)}/{len(raw_targets)} marcadas vía --targets: {picked}")
            raw_targets = [raw_targets[i - 1] for i in picked]
            consent_explicit = True
        elif all_targets or not select:
            console.print(f"  [dim][SELECT] modo automático — {len(raw_targets)} redes (todas)[/dim]")
        else:
            picked, consent_explicit = prompt_target_selection(len(raw_targets))
            if not picked:
                console.print("  [yellow][SELECT] sin objetivos marcados. Abortando sin tocar el aire.[/yellow]")
                return
            console.print(f"  [cyan][SELECT][/cyan] {len(picked)}/{len(raw_targets)} marcadas: {picked}")
            raw_targets = [raw_targets[i - 1] for i in picked]

        # ── Puerta RoE fase B: firma de sesión ──────────────────────────────
        # Vale cualquiera: --dry-run, --force-roe, o selección explícita
        # (prompt tecleado / --targets / --target-bssid). El modo automático
        # total (--all/--no-select/sin TTY) sin flag sigue bloqueado.
        if not dry_run and not force_roe:
            if consent_explicit:
                try:
                    roe_ctx = enforce_scope(scope, dry_run=False,
                                            force_roe=False,
                                            selection_consent=True)
                except RoEError as e:
                    console.print(f"[red][RoE BLOQUEO][/red] {e}")
                    raise typer.Exit(2)
                session_mac = roe_ctx.get("iface_mac")
                console.print(f"  [green][RoE][/green] [dim]firma de sesión: {len(raw_targets)} objetivo(s) marcado(s) explícitamente[/dim]")
            else:
                console.print("[red][RoE BLOQUEO][/red] RoE: auditoría automática total sin firma — "
                              "marca objetivos explícitos (prompt/--targets/--target-bssid) o usa --force-roe")
                raise typer.Exit(2)

        console.print(f"\n  [bold]{len(raw_targets)}[/bold] redes a auditar. Iniciando secuencia...\n")
        time.sleep(1)

        # ── PASO 3: Ejecución secuencial — una red a la vez ───────────────────
        console.print(Rule("[bold cyan]Paso 3/4 — Ejecución Secuencial[/bold cyan]", style="cyan"))
        all_results = []
        session_keys: Dict[str, str] = {}  # {ssid: psk} para reutilización entre APs hermanos

        for idx, raw in enumerate(raw_targets, 1):
            console.print(Rule(
                f"[bold]Red {idx}/{len(raw_targets)}[/bold]  "
                f"[cyan]{raw['ssid']}[/cyan]  [dim]({raw['bssid']})[/dim]",
                style="blue",
            ))

            target = TargetInfo(
                bssid=raw["bssid"], ssid=raw["ssid"], channel=raw["channel"],
                encryption=raw["encryption"],
                wps_enabled=raw.get("wps_enabled", False),
                wps_version=raw.get("wps_version"),
                wps_locked=raw.get("wps_locked", False),
                oui=raw["oui"], signal_strength=raw["signal_strength"],
                wpa3_supported=raw.get("wpa3_supported", False),
                dpp_supported=raw.get("dpp_supported", False),
            )
            if raw["bssid"].upper() in resumed:
                console.print(f"  [cyan]↩ reanudado[/cyan] [dim]resultado previo reincorporado sin re-auditar[/dim]")
                all_results.append(resumed[raw["bssid"].upper()])
                # Re-alimentar claves de sesión para la reutilización entre hermanos
                psk0 = extract_reusable_psk(resumed[raw["bssid"].upper()].get("recovered_key"))
                if psk0:
                    session_keys[raw["ssid"]] = psk0
                continue
            profile = _build_profile(raw)

            locked_color = "red" if profile.isp_locked_fw else "green"
            console.print(
                f"  Brand: [cyan]{profile.brand}[/cyan]  "
                f"PIN class: [magenta]{profile.pin_class}[/magenta]  "
                f"ISP-locked fw: [{locked_color}]{profile.isp_locked_fw}[/{locked_color}]"
            )

            if dry_run:
                path = decide_path(target, profile,
                                   wids_enabled=wids_iface is not None, dry_run=True)
                console.print(f"  [dim]DRY RUN — path: {' -> '.join(path)}[/dim]")
                raw["path"] = path
                raw["result"] = "dry_run"
                raw["recovered_key"] = None
                raw["key_type"] = None
                raw["wids_alerts"] = 0
                raw["wids_simulated"] = False
                raw["elapsed_sec"] = 0
                raw["lan_surface"] = None
                raw["dpp_assessment"] = None
                raw["vendor_intel"] = intel_for(
                    ssid=raw.get("ssid", ""), bssid=raw.get("bssid", ""),
                    brand=profile.brand,
                )
                save_progress(sess["path"], raw)
                all_results.append(raw)
                continue

            result = run_single_target(
                target=target, profile=profile,
                iface=scan_iface, wids_iface=wids_iface, scope=scope,
                known_keys=session_keys, allow_lan=allow_lan,
            )
            result["ssid"]          = raw["ssid"]
            result["brand"]         = raw.get("brand", "?")
            result["wps_enabled"]   = raw.get("wps_enabled", False)
            result["wps_locked"]    = raw.get("wps_locked", False)
            result["wpa3_supported"]= raw.get("wpa3_supported", False)
            result["encryption"]    = raw.get("encryption", "?")
            result["vendor_intel"]  = intel_for(
                ssid=raw.get("ssid", ""), bssid=raw.get("bssid", ""),
                brand=profile.brand,
            )
            save_progress(sess["path"], result)
            all_results.append(result)

            # Alimentar reutilización: la PSK de X se prueba (y muta) en X2, X_5G...
            psk = extract_reusable_psk(result.get("recovered_key"))
            if psk:
                session_keys[raw["ssid"]] = psk

            console.print(f"\n  [dim]Completada en {result.get('elapsed_sec', '?')}s[/dim]\n")
            time.sleep(0.5)

        # ── PASO 4: Generar informes ───────────────────────────────────────────
        console.print(Rule("[bold cyan]Paso 4/4 — Generando Informes[/bold cyan]", style="cyan"))

        print_summary_table(all_results)

        ts = int(time.time())
        reports_dir = os.path.join(project_dir, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        from .session import _unique_path as _uniq_report
        try:
            json_path = _uniq_report(os.path.join(reports_dir, f"auris_{ts}.json"))
            generate_json_report(all_results, scope, json_path)
            console.print(f"  [green][OK][/green] JSON:     [cyan]{json_path}[/cyan]")

            md_path = _uniq_report(os.path.join(reports_dir, f"auris_{ts}_informe.md"))
            generate_markdown_report(all_results, scope, md_path)
            console.print(f"  [green][OK][/green] Informe:  [cyan]{md_path}[/cyan]")
        except OSError as e:
            console.print(f"[red][ERR][/red] No se pudieron escribir informes ({e}) — ¿disco lleno o solo lectura?")
            raise typer.Exit(1)

        console.print(f"\n  [bold]Para leer el informe:[/bold]")
        console.print(f"  [cyan]less {md_path}[/cyan]")

        # ── Cierre RoE: verificar MAC estable si el scope lo exige ─────────────
        if scope.get("forbid_mac_rotation", False):
            mac_ok, mac_msg = verify_mac_stable(scope.get("iface_red_team", iface), session_mac)
            style = "green" if mac_ok else "red"
            console.print(f"  [{style}][RoE][/{style}] {mac_msg}")
            if not mac_ok:
                raise typer.Exit(3)

    finally:
        # Siempre restaurar la interfaz y NetworkManager, incluso si enable
        # falló a medias (nm_touched=True pero mon_iface=None).
        if not dry_run and (mon_iface or nm_touched):
            console.print(Rule("Restaurando interfaz", style="dim"))
            # Si el monitor nunca se creó, mon_iface será el original o None;
            # disable se encarga de ser idempotente y de verificar NM.
            disable_monitor_mode(mon_iface or iface, original_iface=iface,
                                 ensure_nm=True)


if __name__ == "__main__":
    app()

