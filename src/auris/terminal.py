"""
AURIS v2 — terminal.py
Funciones de visualización para la terminal. Sin HTML, sin web.
Usa Rich para tablas, paneles y progreso en la terminal.
"""
import time
from contextlib import contextmanager
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, BarColumn
from rich.rule import Rule
from rich import box

console = Console(highlight=False)


def banner():
    console.print(Panel.fit(
        "[bold cyan]AURIS v2[/bold cyan]  [dim]Auditoría WiFi Secuencial[/dim]\n"
        "[dim]Red Team + Blue Team — Solo terminal, 100% offline[/dim]",
        border_style="cyan",
        padding=(1, 4),
    ))


def print_targets_table(targets: List[Dict[str, Any]]):
    """Imprime la tabla de redes encontradas en el scan."""
    table = Table(
        title="[bold]Redes detectadas[/bold]",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("#",       style="dim",        width=4)
    table.add_column("BSSID",   style="bold white",  width=20)
    table.add_column("SSID",    style="green",       width=22)
    table.add_column("CH",      style="yellow",      width=4)
    table.add_column("Cifrado", style="magenta",     width=10)
    table.add_column("WPS",     style="red",         width=6)
    table.add_column("Señal",   style="cyan",        width=8)
    table.add_column("OUI/Brand", style="dim",       width=22)

    for i, t in enumerate(targets, 1):
        wps_str = "[red]ON[/red]" if t.get("wps_enabled") else "[green]OFF[/green]"
        enc = t.get("encryption", "?")
        enc_color = "red" if enc in ("Open", "WEP") else ("yellow" if enc == "WPA" else "green")
        table.add_row(
            str(i),
            t.get("bssid", "?"),
            t.get("ssid", "?"),
            str(t.get("channel", "?")),
            f"[{enc_color}]{enc}[/{enc_color}]",
            wps_str,
            f"{t.get('signal_strength', 0)} dBm",
            t.get("brand", "?"),
        )

    console.print(table)


def parse_target_selection(selection: str, total: int) -> List[int]:
    """Parsea '1,3-5,all' → índices 1-based validados y dedupados. 'all'/'' = todos."""
    s = (selection or "").strip().lower()
    if s in ("", "all", "a", "todas", "todos"):
        return list(range(1, total + 1))
    if s in ("q", "quit", "exit", "none", "0", "n"):
        return []
    picked: List[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a_s, b_s = part.split("-", 1)
                a, b = int(a_s.strip()), int(b_s.strip())
            except ValueError:
                continue
            if a > b:
                a, b = b, a
            for n in range(a, b + 1):
                if 1 <= n <= total and n not in picked:
                    picked.append(n)
        else:
            try:
                n = int(part)
            except ValueError:
                continue
            if 1 <= n <= total and n not in picked:
                picked.append(n)
    return sorted(picked)


def prompt_target_selection(total: int) -> tuple:
    """Pregunta interactiva estilo wifite: qué redes auditar tras el scan.

    El escaneo ya se detuvo antes de llamar aquí (pase libre para marcar).
    Retorna (índices 1-based, consentimiento_explícito). Vacío = abortar.
    Consentimiento explícito = el usuario TECLEÓ su elección (incluye 'all'
    escrito); Enter vacío o auto sin TTY no cuentan como explícito.
    """
    import sys
    if total <= 0:
        return [], False
    if not sys.stdin.isatty():
        # Sin TTY (pipe/cron): comportamiento automático = todas, sin firma
        console.print("  [dim][SELECT] sin TTY — seleccionando todas las redes[/dim]")
        return list(range(1, total + 1)), False
    console.print(
        f"\n  [bold cyan]Marca objetivos[/bold cyan] [dim](ej: 1,3-5 · 'all' = todas · Enter = todas · 'q' = abortar)[/dim]"
    )
    try:
        answer = console.input("  [bold]Selección > [/bold]").strip()
    except (EOFError, KeyboardInterrupt):
        console.print("\n  [yellow]Selección cancelada por el usuario.[/yellow]")
        return [], False
    if answer == "":
        return list(range(1, total + 1)), False
    picked = parse_target_selection(answer, total)
    # Entrada inválida (ej: 'xyz', '99') → no abortar, reintentar una vez
    if not picked and answer.lower() not in ("q", "quit", "exit", "none", "0", "n"):
        console.print(f"  [yellow]Selección '{answer}' inválida para 1-{total}. Intenta de nuevo.[/yellow]")
        try:
            answer2 = console.input("  [bold]Selección > [/bold]").strip()
        except (EOFError, KeyboardInterrupt):
            return [], False
        if answer2 == "":
            return list(range(1, total + 1)), False
        picked = parse_target_selection(answer2, total)
    explicit = bool(picked)
    return picked, explicit


def print_phase_start(phase: str, target_bssid: str, target_ssid: str):
    console.print(Rule(f"[bold yellow]{phase}[/bold yellow]  [dim]{target_ssid} ({target_bssid})[/dim]", style="yellow"))


def print_phase_result(phase: str, result: str, detail: str = ""):
    icons = {
        "cracked":          ("[bold red][CRACKED][/bold red]",      "red"),
        "class_confirmed":  ("[bold red][CLASE WPS][/bold red]",    "red"),
        "locked":           ("[yellow][LOCKOUT][/yellow]",          "yellow"),
        "not_found":        ("[green][SEGURO][/green]",             "green"),
        "exhausted":        ("[green][WORDLIST OK][/green]",        "green"),
        "timeout":          ("[dim][TIMEOUT][/dim]",                "dim"),
        "error":            ("[dim][ERROR][/dim]",                  "dim"),
        "eol_confirmed":    ("[bold red][FIRMWARE EOL][/bold red]", "red"),
        "skipped":          ("[dim][OMITIDO][/dim]",                "dim"),
    }
    label, _ = icons.get(result, (f"[cyan]{result}[/cyan]", "cyan"))
    msg = f"  {label}"
    if detail:
        msg += f"  [dim]{detail}[/dim]"
    console.print(msg)


def print_wids_alert(alert: Dict[str, Any]):
    sev = alert.get('severity', '')
    sev_str = '[red]HIGH[/red]' if sev == 'High' else ('[yellow]MED[/yellow]' if sev == 'Medium' else '[green]LOW[/green]')
    console.print(
        f"  [bold blue][WIDS][/bold blue] "
        f"[yellow]{alert.get('alert_type','?')}[/yellow]  "
        f"[dim]{alert.get('timestamp','')}[/dim]  "
        f"{sev_str}"
    )


def print_summary_table(results: List[Dict[str, Any]]):
    """Imprime tabla resumen de todas las redes auditadas con valores de contraseña."""
    console.print(Rule("[bold cyan]Resumen de la sesión — Evidencia de Compromiso[/bold cyan]", style="cyan"))

    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("SSID",              style="green",       width=18)
    table.add_column("BSSID",             style="dim",         width=18)
    table.add_column("Resultado",         style="bold",        width=16)
    table.add_column("Contraseña / Clave",style="bold yellow", width=26)
    table.add_column("Tipo",              style="dim",         width=14)
    table.add_column("WIDS",              style="yellow",      width=6)
    table.add_column("Tiempo",            style="cyan",        width=8)

    for r in results:
        res = r.get("result", "?")
        res_text = {
            "cracked":        "[bold red]COMPROMETIDO[/bold red]",
            "class_confirmed":"[bold red]CLASE WPS[/bold red]",
            "locked":         "[yellow]LOCKOUT[/yellow]",
            "exhausted":      "[green]SEGURO[/green]",
            "not_found":      "[green]SEGURO[/green]",
            "eol_confirmed":  "[bold red]EOL/NO PARCHE[/bold red]",
            "timeout":        "[dim]TIMEOUT[/dim]",
            "error":          "[dim]ERROR[/dim]",
            "dry_run":        "[dim]DRY RUN[/dim]",
        }.get(res, f"[dim]{res}[/dim]")

        rec_key = r.get("recovered_key")
        if rec_key:
            key_display = f"[bold white on red] {rec_key} [/bold white on red]"
            key_type = r.get("key_type") or "Clave"
        elif res == "cracked":
            key_display = "[bold red]Comprometida[/bold red]"
            key_type = r.get("key_type") or "Cifrado"
        elif res == "dry_run":
            key_display = "[dim]Simulación[/dim]"
            key_type = "-"
        else:
            key_display = "[dim]No obtenida[/dim]"
            key_type = "-"

        table.add_row(
            r.get("ssid", "?"),
            r.get("bssid", "?"),
            res_text,
            key_display,
            key_type,
            str(r.get("wids_alerts", 0)),
            f"{r.get('elapsed_sec', 0)}s",
        )

    console.print(table)


def spinner(msg: str, seconds: float):
    """Muestra un spinner en terminal durante N segundos."""
    with Progress(
        SpinnerColumn(),
        TextColumn(f"[cyan]{msg}[/cyan]"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task("", total=None)
        time.sleep(seconds)


@contextmanager
def live_task(desc: str, total: float):
    """Barra de carga minimalista y transitoria. Yields tick(avance)."""
    progress = Progress(
        SpinnerColumn(style="cyan"),
        TextColumn(f"[cyan]{desc}[/cyan]"),
        BarColumn(bar_width=None, style="dim", complete_style="cyan"),
        TextColumn("[dim]{task.percentage:>3.0f}%[/dim]"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    )
    task = progress.add_task(desc, total=total)
    with progress:
        yield lambda advance=1.0: progress.update(task, advance=advance)


def countdown(desc: str, seconds: int):
    """Espera N segundos mostrando solo la barra."""
    with live_task(desc, max(seconds, 1)) as tick:
        for _ in range(seconds):
            time.sleep(1)
            tick(1)
