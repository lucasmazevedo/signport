# SPDX-License-Identifier: AGPL-3.0-or-later
"""Independent verification with the OpenSSL CLI (no pyHanko code involved).

Parses /ByteRange and /Contents of the LAST signature directly from the bytes,
extracts the DER CMS (trimming placeholder zero padding by reading the DER
length header) and runs ``openssl cms -verify`` with the covered bytes as
detached content. Test-only helper.
"""

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_BYTE_RANGE = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")


@dataclass(frozen=True)
class ExtractedSignature:
    signed_content: bytes
    cms_der: bytes
    byte_range: tuple[int, int, int, int]


def _der_total_length(der: bytes) -> int:
    if der[0] != 0x30:
        raise ValueError("CMS must start with a SEQUENCE")
    first = der[1]
    if first < 0x80:
        return 2 + first
    n = first & 0x7F
    return 2 + n + int.from_bytes(der[2 : 2 + n], "big")


def extract_last_signature(pdf: bytes) -> ExtractedSignature:
    matches = list(_BYTE_RANGE.finditer(pdf))
    if not matches:
        raise ValueError("no /ByteRange found")
    a, b, c, d = (int(x) for x in matches[-1].groups())
    if a != 0 or b <= 0 or c <= a + b or d <= 0 or c + d != len(pdf):
        raise ValueError("ByteRange must cover the whole file except one gap")
    gap = pdf[a + b : c]
    # The only excluded bytes must be exactly the /Contents hex string "<...>".
    if not (gap.startswith(b"<") and gap.endswith(b">") and re.fullmatch(rb"<[0-9A-Fa-f]*>", gap)):
        raise ValueError("ByteRange gap is not exactly the /Contents hex string")
    raw = bytes.fromhex(gap[1:-1].decode("ascii"))
    length = _der_total_length(raw)
    if length > len(raw) or any(raw[length:]):
        raise ValueError("CMS padding inside /Contents must be zero bytes")
    return ExtractedSignature(pdf[a : a + b] + pdf[c : c + d], raw[:length], (a, b, c, d))


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def openssl_cms_verify(pdf: bytes, ca_pem: bytes, workdir: Path) -> subprocess.CompletedProcess[str]:
    sig = extract_last_signature(pdf)
    (workdir / "sig.der").write_bytes(sig.cms_der)
    (workdir / "content.bin").write_bytes(sig.signed_content)
    (workdir / "ca.pem").write_bytes(ca_pem)
    return subprocess.run(
        [
            "openssl",
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            str(workdir / "sig.der"),
            "-content",
            str(workdir / "content.bin"),
            "-CAfile",
            str(workdir / "ca.pem"),
            "-purpose",
            "any",
            "-out",
            str(workdir / "verified.out"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
