"""Shared pytest fixtures for the SWIFT CSCF conformance suite.

Adds the gate module to the import path and discovers the OPA binary. Tests are
skipped (not failed) when OPA is unavailable, so the suite is safe to collect on a
machine without OPA while still gating CI (where OPA is installed).
"""
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))


@pytest.fixture(autouse=True)
def _no_repository_exceptions(monkeypatch, tmp_path_factory):
    """Keep the suite's verdicts independent of an institution's own exceptions file.

    Following the adoption guide adds exceptions/exceptions.toml; the gate loads
    it by default, which would change the fixtures' verdicts (and make them
    depend on the date). Tests that exercise exceptions pass a file explicitly.
    """
    import gate

    absent = tmp_path_factory.getbasetemp() / "no-exceptions" / "exceptions.toml"
    monkeypatch.setattr(gate, "DEFAULT_EXCEPTIONS", absent)


@pytest.fixture(scope="session")
def opa():
    exe = shutil.which("opa")
    if not exe:
        pytest.skip("opa binary not on PATH")
    return exe
