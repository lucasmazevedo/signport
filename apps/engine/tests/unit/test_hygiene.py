# SPDX-License-Identifier: AGPL-3.0-or-later
"""Repository hygiene for the Engine: no private material, no unsafe deserialization.

Scans the working tree (not only tracked files) so that new, uncommitted files are
also covered; excludes only the virtualenv and tool caches.
"""

import re
from pathlib import Path

from conftest import ENGINE_ROOT

FORBIDDEN_SUFFIXES = (".pem", ".key", ".pfx", ".p12", ".jks", ".der", ".crt", ".cer", ".pdf")
EXCLUDED_DIRS = {".venv", ".pytest_cache", ".ruff_cache", "__pycache__"}
UNSAFE = re.compile(r"^\s*(import|from)\s+(pickle|marshal|shelve|dill|cloudpickle)\b|\beval\(|\bexec\(", re.M)


def _files(root: Path) -> list[Path]:
    return [
        p
        for p in root.rglob("*")
        if p.is_file() and not EXCLUDED_DIRS.intersection(p.relative_to(root).parts)
    ]


def test_no_private_or_document_material_in_the_engine_tree() -> None:
    offenders = [p for p in _files(ENGINE_ROOT) if p.name.lower().endswith(FORBIDDEN_SUFFIXES)]
    assert offenders == []


def test_no_unsafe_deserialization_in_source() -> None:
    offenders = [p for p in (ENGINE_ROOT / "src").rglob("*.py") if UNSAFE.search(p.read_text())]
    assert offenders == []
