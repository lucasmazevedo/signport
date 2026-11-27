# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compatibility of the E2 core with the canonical P0 contracts (packages/protocol, read-only)."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import PROTOCOL_ROOT
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012
from support.pki import LabPki

from signport_engine.cms.raw_signature import SUPPORTED_DIGEST_ALGORITHM, SUPPORTED_SIGNATURE_ALGORITHM
from signport_engine.errors import ErrorCode
from signport_engine.pdf.external_signing import PreparedSignature, b64

BASE = "https://signport.invalid/schemas/v1/"


@pytest.fixture(scope="module")
def registry() -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in sorted((PROTOCOL_ROOT / "schemas").rglob("*.schema.json")):
        schema = json.loads(path.read_text())
        resources.append((schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012)))
    return Registry().with_resources(resources)


def validator(registry: Registry, ref: str) -> Draft202012Validator:
    return Draft202012Validator(
        {"$ref": BASE + ref}, registry=registry, format_checker=Draft202012Validator.FORMAT_CHECKER
    )


def test_protocol_schemas_are_available_locally() -> None:
    assert (PROTOCOL_ROOT / "schemas/v1/engine/api.schema.json").is_file()
    assert isinstance(PROTOCOL_ROOT, Path)


def test_engine_algorithms_match_protocol_enums(registry: Registry) -> None:
    common = json.loads((PROTOCOL_ROOT / "schemas/v1/common.schema.json").read_text())["$defs"]
    assert common["DigestAlgorithm"]["enum"] == [SUPPORTED_DIGEST_ALGORITHM]
    assert common["SignatureAlgorithm"]["enum"] == [SUPPORTED_SIGNATURE_ALGORITHM]


def test_engine_error_codes_belong_to_the_engine_surface() -> None:
    registry = json.loads((PROTOCOL_ROOT / "errors/registry.json").read_text())["errors"]
    engine_codes = {e["code"] for e in registry if "engine" in e["surfaces"]}
    assert {c.value for c in ErrorCode} <= engine_codes


def test_prepared_signature_maps_to_the_p0_preparation_schema(
    registry: Registry, prepare: Callable[..., PreparedSignature]
) -> None:
    p = prepare()
    body = {
        "preparation_id": "01936f3c-0000-7000-8000-000000000005",
        "status": "prepared",
        "document_version_id": "01936f3c-0000-7000-8000-000000000007",
        "document_sha256": p.document_sha256,
        "byte_range_digest_b64": p.byte_range_digest_b64,
        "signed_attributes_digest_b64": p.signed_attributes_digest_b64,
        "digest_algorithm": p.digest_algorithm,
        "signature_algorithm": p.signature_algorithm,
        "certificate_sha256": p.certificate_sha256,
        "policy": "icpbr-pades-rb",  # declared value only; policy attributes arrive in E7
        "created_at": "2026-11-27T12:00:00Z",
        "expires_at": "2026-11-27T12:10:00Z",
    }
    errors = list(validator(registry, "engine/api.schema.json#/$defs/Preparation").iter_errors(body))
    assert errors == []


def test_external_signature_maps_to_the_p0_complete_request(
    registry: Registry, pki: LabPki, prepare: Callable[..., PreparedSignature]
) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, utils

    p = prepare()
    sig = pki.signer.key.sign(
        p.signed_attributes_digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())
    )
    body = {
        "attempt_id": "01936f3c-0000-7000-8000-000000000004",
        "signature_b64": b64(sig),
        "signature_algorithm": SUPPORTED_SIGNATURE_ALGORITHM,
        "certificate_sha256": p.certificate_sha256,
    }
    assert (
        list(
            validator(registry, "engine/api.schema.json#/$defs/CompletePreparationRequest").iter_errors(body)
        )
        == []
    )


def test_signhash_payload_digest_is_the_signed_attributes_digest(
    registry: Registry, prepare: Callable[..., PreparedSignature]
) -> None:
    """The value the Engine exposes is exactly what the native signHash contract carries."""
    p = prepare()
    payload_schema = validator(registry, "native/request.schema.json#/$defs/SignHashPayload")
    payload = {
        "attemptId": "01936f3c-0000-7000-8000-000000000004",
        "signedAttributesDigestB64": p.signed_attributes_digest_b64,
        "digestAlgorithm": p.digest_algorithm,
        "signatureAlgorithm": p.signature_algorithm,
        "certificateSha256": p.certificate_sha256,
        "authorization": "eyJhbGciOiJFUzI1NiJ9.eyJzeW50aGV0aWMiOnRydWV9.c3ludGhldGlj",
    }
    assert list(payload_schema.iter_errors(payload)) == []
    payload["signedAttributesDigestB64"] = p.document_sha256  # PDF hash in the CMS digest field
    assert list(payload_schema.iter_errors(payload)) != []
