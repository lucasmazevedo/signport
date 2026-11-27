# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthetic laboratory PKI (E1). Keys exist only in memory for the test session.

Shape mirrors an ICP-Brasil-like hierarchy (root -> intermediate -> end entity with
digitalSignature + nonRepudiation) but every name and identifier is fictitious.
Nothing here is an ICP-Brasil certificate or implies compliance.
"""

import datetime as dt
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

NOW = dt.datetime.now(dt.UTC).replace(microsecond=0)
# Fictitious ICP-Brasil-style otherName OID for the holder data (2.16.76.1.3.1); synthetic value.
ICP_HOLDER_OID = x509.ObjectIdentifier("2.16.76.1.3.1")
SYNTHETIC_HOLDER_VALUE = b"\x04\x1400000000000SYNTHETIC"


@dataclass(frozen=True)
class Issued:
    cert: x509.Certificate
    key: rsa.RSAPrivateKey = field(repr=False)

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SignPort Synthetic Test PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def new_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _ski(key: rsa.RSAPrivateKey) -> x509.SubjectKeyIdentifier:
    return x509.SubjectKeyIdentifier.from_public_key(key.public_key())


def _crl_dp(issuer_cn: str) -> x509.CRLDistributionPoints:
    """Declared like real ICP-Brasil certificates; '.invalid' URL is never fetched (offline CRLs)."""
    slug = issuer_cn.lower().replace(" ", "-")
    return x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(f"http://crl.signport.invalid/{slug}.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None,
            )
        ]
    )


def _cn(cert: x509.Certificate) -> str:
    return str(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)


def make_root(cn: str = "SYNTHETIC ROOT CA - NOT ICP-BRASIL") -> Issued:
    key = new_key(3072)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=30))
        .not_valid_after(NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
        .add_extension(_ski(key), critical=False)
        .sign(key, hashes.SHA256())
    )
    return Issued(cert, key)


def make_intermediate(root: Issued, cn: str = "SYNTHETIC INTERMEDIATE CA") -> Issued:
    key = new_key(3072)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(root.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=20))
        .not_valid_after(NOW + dt.timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
        .add_extension(_ski(key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root.key.public_key()), critical=False
        )
        .add_extension(_crl_dp(_cn(root.cert)), critical=False)
        .sign(root.key, hashes.SHA256())
    )
    return Issued(cert, key)


def make_end_entity(
    issuer: Issued,
    cn: str = "TITULAR SINTETICO DE TESTE",
    *,
    bits: int = 2048,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    non_repudiation: bool = True,
    digital_signature: bool = True,
    crl_dp: bool = True,
) -> Issued:
    key = new_key(bits)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - dt.timedelta(days=10))
        .not_valid_after(not_after or NOW + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature, non_repudiation, False, False, False, False, False, False, False
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.OtherName(ICP_HOLDER_OID, SYNTHETIC_HOLDER_VALUE)]),
            critical=False,
        )
        .add_extension(_ski(key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False
        )
    )
    if crl_dp:
        builder = builder.add_extension(_crl_dp(_cn(issuer.cert)), critical=False)
    return Issued(builder.sign(issuer.key, hashes.SHA256()), key)


def make_crl(issuer: Issued, revoked: list[x509.Certificate] | None = None) -> x509.CertificateRevocationList:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.cert.subject)
        .last_update(NOW - dt.timedelta(hours=1))
        .next_update(NOW + dt.timedelta(days=7))
        .add_extension(x509.CRLNumber(1), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False
        )
    )
    for cert in revoked or []:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(cert.serial_number)
            .revocation_date(NOW - dt.timedelta(minutes=30))
            .build()
        )
    return builder.sign(issuer.key, hashes.SHA256())


@dataclass(frozen=True)
class LabPki:
    root: Issued
    intermediate: Issued
    signer: Issued
    other_signer: Issued

    @property
    def chain_der(self) -> tuple[bytes, ...]:
        return (self.intermediate.der, self.root.der)


def build_lab_pki() -> LabPki:
    root = make_root()
    intermediate = make_intermediate(root)
    return LabPki(
        root=root,
        intermediate=intermediate,
        signer=make_end_entity(intermediate),
        other_signer=make_end_entity(intermediate, "OUTRO TITULAR SINTETICO"),
    )
