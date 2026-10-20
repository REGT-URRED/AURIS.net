"""
Integración de ContextBase (memoria técnica persistente) en AURIS.net.

Verifica que el CLI vendorizado funciona sin npm, que los documentos y las
reglas para agentes están versionados, y que la instalación Linux los expone.
No requiere red ni hardware.
"""

import os
import shutil
import subprocess

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = os.path.join(ROOT, "tools", "contextbase", "bin", "contextbase.js")
NODE = shutil.which("node")

DOCS = ("fundamentos.md", "changelog.md", "tasklist.md")


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_cli_vendorizado_presente():
    assert os.path.isfile(CLI), "falta tools/contextbase/bin/contextbase.js"
    pkg = _read("tools/contextbase/package.json")
    assert '"type": "module"' in pkg
    assert '"dependencies"' not in pkg, "contextbase debe seguir sin dependencias npm"


def test_documentos_de_memoria():
    for name in DOCS:
        path = os.path.join(ROOT, "contextbase", name)
        assert os.path.isfile(path), f"falta contextbase/{name}"
        assert os.path.getsize(path) > 500, f"contextbase/{name} parece vacío"
    assert "## Cambios Realizados" in _read("contextbase/changelog.md")
    assert "## Tareas Pendientes / En Progreso" in _read("contextbase/tasklist.md")


def test_reglas_inyectadas_para_agentes():
    for rel in ("AGENTS.md", "CLAUDE.md", ".cursorrules", ".windsurfrules"):
        content = _read(rel)
        assert "<!-- CONTEXTBASE:START -->" in content, f"{rel} sin bloque contextbase"
        assert "<!-- CONTEXTBASE:END -->" in content, f"{rel} con bloque incompleto"


def test_instalacion_linux_expone_contextbase():
    setup = _read("setup.sh")
    assert "/usr/local/bin/contextbase" in setup
    assert "scripts/contextbase.sh" in setup
    assert "./contextbase" in _read("scripts/pack.sh")
    assert "./tools" in _read("scripts/pack.sh")
    assert "nodejs" in _read("scripts/bootstrap.sh")


@pytest.mark.skipif(
    NODE is None or os.name == "nt",
    reason="el wrapper es POSIX (en Windows el bash disponible es WSL y no resuelve rutas D:)",
)
def test_wrapper_ejecuta_status(tmp_path):
    wrapper = os.path.join(ROOT, "scripts", "contextbase.sh")
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash no disponible")
    r = subprocess.run(
        [bash, wrapper, "status"], capture_output=True, text=True, timeout=60
    )
    assert r.returncode == 0, r.stderr
    assert "fundamentos.md" in r.stdout


@pytest.mark.skipif(NODE is None, reason="Node.js no instalado en este entorno")
def test_task_done_mueve_la_tarea(tmp_path):
    """Regresión: 'task done' lanzaba ReferenceError por variables sin declarar."""
    project = tmp_path / "proj"
    (project / "contextbase").mkdir(parents=True)
    for name in DOCS:
        (project / "contextbase" / name).write_text("# doc\n", encoding="utf-8")

    def run(*args):
        r = subprocess.run(
            [NODE, CLI, *args], cwd=project, capture_output=True, text=True, timeout=60
        )
        assert r.returncode == 0, r.stderr
        return r.stdout

    run("task", "add", "tarea de prueba")
    run("task", "done", "prueba")

    tasklist = (project / "contextbase" / "tasklist.md").read_text(encoding="utf-8")
    assert "- [x] tarea de prueba" in tasklist
    assert "- [ ] tarea de prueba" not in tasklist
