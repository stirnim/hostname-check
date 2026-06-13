"""Shared test fixtures.

The tool lives in ``hostname-check.py`` (a hyphenated, non-importable name),
so it is loaded once here by path and exposed to tests via the ``hc`` fixture.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent.parent / "hostname-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("hostname_check", _MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def hc():
    """The loaded hostname-check module under test."""
    return _load_module()
