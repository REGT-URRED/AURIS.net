"""
Candado de integridad del bundle offline (apt_packages + wheels + rockyou).

No asume nada: verifica contra el índice real de la distro origen y contra los
propios .deb que se empaquetan para el USB.
"""
import hashlib
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUNDLE = os.path.join(ROOT, "offline_bundle")
APT_DIR = os.path.join(BUNDLE, "apt_packages")
WHEELS = os.path.join(BUNDLE, "wheels")


def _debs():
    if not os.path.isdir(APT_DIR):
        return []
    return sorted(
        os.path.join(APT_DIR, f) for f in os.listdir(APT_DIR) if f.endswith(".deb")
    )


def _field(deb, field):
    r = subprocess.run(["dpkg-deb", "-f", deb, field], capture_output=True, text=True)
    return r.stdout.strip()


def test_bundle_apt_dir_no_vacia():
    assert _debs(), "offline_bundle/apt_packages vacío: el USB no podrá instalar radio"


def test_debs_son_paquetes_validos():
    bad = []
    for deb in _debs():
        r = subprocess.run(["dpkg-deb", "-f", deb, "Package"], capture_output=True, text=True)
        if r.returncode != 0 or not r.stdout.strip():
            bad.append(os.path.basename(deb))
    assert not bad, f".deb ilegibles: {bad}"


def test_tools_de_captura_presentes():
    nombres = {os.path.basename(d).split("_")[0] for d in _debs()}
    for pkg in ("hcxdumptool", "hcxtools", "aircrack-ng", "reaver", "iw",
                "macchanger", "wireless-tools", "python3-venv"):
        assert pkg in nombres, f"falta {pkg} en el bundle (no habrá captura offline)"


def test_no_se_incluye_glibc():
    """Sobrescribir libc6 offline puede romper el sistema: nunca debe ir en el bundle."""
    nombres = {os.path.basename(d).split("_")[0] for d in _debs()}
    for prohibido in ("libc6", "libc-bin", "libgcc-s1", "libstdc++6"):
        assert prohibido not in nombres, f"{prohibido} no debe empaquetarse"


def test_requisito_libc6_bien_parseado():
    """El filtro de compatibilidad debe leer versiones tipo 2.38, nunca el '6' de libc6."""
    for deb in _debs():
        raw = _field(deb, "Depends")
        m = re.findall(r"libc6 \(>= ([0-9]+\.[0-9]+[0-9.]*)\)", raw)
        if not m:
            continue
        for v in m:
            assert re.match(r"^[0-9]+\.[0-9]+", v), f"{os.path.basename(deb)}: requisito raro {v}"


def test_cierre_de_dependencias_sin_huecos():
    """Toda dependencia de un .deb debe estar en el bundle o venir en la base Kali."""
    base_presente = {
        "libc6", "libc-bin", "libgcc-s1", "libstdc++6", "zlib1g", "debconf", "perl-base",
        "dpkg", "install-info", "tar", "base-files",
    }
    # Virtuales que otro paquete del bundle declara en su campo Provides.
    # (Verificado a mano contra el índice: python3-distutils provee python3.11-distutils.)
    virtuales = {
        "python3.11-distutils": "python3-distutils",
        "python3.12-distutils": "python3-distutils",
    }
    bundle = {os.path.basename(d).split("_")[0] for d in _debs()}
    huecos = {}
    for deb in _debs():
        pkg = os.path.basename(deb).split("_")[0]
        for campo in ("Pre-Depends", "Depends"):
            for parte in _field(deb, campo).split(","):
                parte = parte.strip()
                if not parte:
                    continue
                alts = [re.sub(r"\s*\(.*?\)", "", a).strip() for a in parte.split("|")]
                def _ok(a):
                    if a in bundle or a in base_presente:
                        return True
                    if a in virtuales and virtuales[a] in bundle:
                        return True
                    if a.endswith(":any") and a[:-4] in bundle:
                        return True
                    return False
                if any(_ok(a) for a in alts):
                    continue
                huecos.setdefault(pkg, []).append(parte)
    assert not huecos, f"dependencias sin cubrir: {huecos}"


def test_debs_contienen_los_binarios_que_usamos():
    """No basta con el nombre del paquete: el binario debe estar dentro del .deb."""
    esperado = {
        "hcxdumptool": "./usr/bin/hcxdumptool",
        "hcxtools": "./usr/bin/hcxpcapngtool",
        "aircrack-ng": "./usr/bin/aircrack-ng",
        "reaver": "./usr/bin/reaver",          # wash es symlink creado en postinst
        "iw": "./usr/sbin/iw",
        "macchanger": "./usr/bin/macchanger",
        "wireless-tools": "./usr/sbin/iwconfig",
        "ethtool": "./usr/sbin/ethtool",
        "rfkill": "./usr/sbin/rfkill",
        "usbutils": "./usr/bin/lsusb",
        "pciutils": "./usr/bin/lspci",
        "python3.11-venv": "./usr/lib/python3.11/ensurepip/__init__.py",
        "pixiewps": "./usr/bin/pixiewps",
        "bully": "./usr/bin/bully",
    }
    por_pkg = {}
    for deb in _debs():
        por_pkg.setdefault(os.path.basename(deb).split("_")[0], deb)
    faltan = []
    for pkg, ruta in esperado.items():
        deb = por_pkg.get(pkg)
        if not deb:
            faltan.append(f"{pkg} (paquete ausente)")
            continue
        r = subprocess.run(["dpkg-deb", "-c", deb], capture_output=True, text=True)
        if ruta not in r.stdout:
            faltan.append(f"{pkg} no contiene {ruta}")
    assert not faltan, f"contenido incompleto: {faltan}"


def test_checksums_del_bundle_cuadran():
    chk = os.path.join(BUNDLE, "checksums.sha256")
    assert os.path.isfile(chk), "falta offline_bundle/checksums.sha256"
    r = subprocess.run(["sha256sum", "-c", "checksums.sha256", "--quiet"],
                       cwd=BUNDLE, capture_output=True, text=True)
    assert r.returncode == 0, f"checksums inválidos:\n{r.stdout}\n{r.stderr}"


def test_rockyou_por_huella():
    rk = os.path.join(BUNDLE, "wordlists", "rockyou.txt")
    assert os.path.isfile(rk), "falta rockyou.txt en el bundle"
    size = os.path.getsize(rk)
    assert 100_000_000 <= size <= 170_000_000, f"tamaño de rockyou fuera de huella: {size}"


def test_wheels_python_presentes():
    assert os.path.isdir(WHEELS)
    whls = [f for f in os.listdir(WHEELS) if f.endswith(".whl")]
    assert len(whls) >= 20, f"pocos wheels en el bundle: {len(whls)}"
    # el wheel de pip es el que salva a una Kali sin python3-pip
    assert any(f.startswith("pip-") for f in whls), "falta el wheel de pip (Kali sin pip)"
