"""Selección de objetivos estilo wifite: parseo '1,3-5,all' y prompt."""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris.terminal import parse_target_selection, prompt_target_selection


def test_all_variants():
    assert parse_target_selection("all", 5) == [1, 2, 3, 4, 5]
    assert parse_target_selection("", 3) == [1, 2, 3]
    assert parse_target_selection("ALL", 2) == [1, 2]


def test_list_and_ranges():
    assert parse_target_selection("1,3", 5) == [1, 3]
    assert parse_target_selection("1-3", 5) == [1, 2, 3]
    assert parse_target_selection("3-1", 5) == [1, 2, 3]
    assert parse_target_selection("1,2-4,5", 5) == [1, 2, 3, 4, 5]
    # dedup + orden
    assert parse_target_selection("3,1,3,2", 5) == [1, 2, 3]


def test_invalid_and_bounds():
    assert parse_target_selection("q", 5) == []
    assert parse_target_selection("0", 5) == []
    assert parse_target_selection("99", 5) == []
    assert parse_target_selection("xyz", 5) == []
    # mezcla válida/inválida: conserva lo válido
    assert parse_target_selection("1,xyz,99,2", 5) == [1, 2]
    assert parse_target_selection("0", 0) == []


def test_prompt_marks_explicit_consent(monkeypatch):
    import auris.terminal as t
    # TTY + tecleado explícito = firma
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(t.console, "input", lambda *a, **k: "1,3")
    picked, explicit = prompt_target_selection(5)
    assert picked == [1, 3] and explicit is True
    # TTY + Enter vacío = todas pero SIN firma explícita
    monkeypatch.setattr(t.console, "input", lambda *a, **k: "")
    picked2, explicit2 = prompt_target_selection(5)
    assert picked2 == [1, 2, 3, 4, 5] and explicit2 is False
    # TTY + q = abortar
    monkeypatch.setattr(t.console, "input", lambda *a, **k: "q")
    picked3, explicit3 = prompt_target_selection(5)
    assert picked3 == [] and explicit3 is False


def test_prompt_nontty_auto_without_consent(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    picked, explicit = prompt_target_selection(4)
    assert picked == [1, 2, 3, 4] and explicit is False
    assert prompt_target_selection(0) == ([], False)
