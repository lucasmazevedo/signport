# SPDX-License-Identifier: AGPL-3.0-or-later
"""Explicit environment check (REV-14): the interpreter is the pinned, uv-managed CPython patch."""

import platform
import sys
from pathlib import Path

from conftest import ENGINE_ROOT


def test_interpreter_matches_pinned_patch() -> None:
    pinned = (ENGINE_ROOT / ".python-version").read_text().strip()
    assert pinned.count(".") == 2, "pin an exact patch version"
    assert platform.python_implementation() == "CPython"
    assert ".".join(map(str, sys.version_info[:3])) == pinned


def test_interpreter_is_uv_managed() -> None:
    """uv-managed CPython lives in '<uv data>/python/cpython-<patch>-<platform>' (never /usr)."""
    pinned = (ENGINE_ROOT / ".python-version").read_text().strip()
    base = Path(sys.base_prefix).resolve()
    assert base.name.startswith(f"cpython-{pinned}-"), base
    assert base.parent.name == "python"
    assert "uv" in base.parts
    assert sys.prefix != sys.base_prefix  # running inside the project's virtualenv
