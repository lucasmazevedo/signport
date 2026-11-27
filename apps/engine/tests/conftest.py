# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio
import sys
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509

sys.path.insert(0, str(Path(__file__).parent))

from support.pdfs import synthetic_pdf
from support.pki import LabPki, build_lab_pki, make_crl

from signport_engine.pdf.external_signing import (
    PreparedSignature,
    prepare_external_signature,
    sha256_hex,
)

ENGINE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ENGINE_ROOT.parents[1]
PROTOCOL_ROOT = REPO_ROOT / "packages" / "protocol"


def run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


@pytest.fixture(scope="session")
def pki() -> LabPki:
    return build_lab_pki()


@pytest.fixture(scope="session")
def crls(pki: LabPki) -> list[x509.CertificateRevocationList]:
    return [make_crl(pki.root), make_crl(pki.intermediate)]


@pytest.fixture(scope="session")
def pdf() -> bytes:
    return synthetic_pdf()


@pytest.fixture
def prepare(pki: LabPki, pdf: bytes) -> Callable[..., PreparedSignature]:
    def _prepare(document: bytes = pdf, **overrides: Any) -> PreparedSignature:
        kwargs: dict[str, Any] = {
            "expected_document_sha256": sha256_hex(document),
            "certificate_der": pki.signer.der,
            "chain_der": pki.chain_der,
        }
        kwargs.update(overrides)
        return run(prepare_external_signature(document, **kwargs))

    return _prepare
