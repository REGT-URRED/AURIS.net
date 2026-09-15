"""Selección de objetivos estilo wifite: parseo '1,3-5,all' y prompt."""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from auris.terminal import parse_target_selection


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
