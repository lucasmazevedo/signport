# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthetic PDFs generated in code (E1). No real or clinical documents."""

from io import BytesIO

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.writer import PdfFileWriter


def synthetic_pdf(
    text: str = "SignPort synthetic test document - not a real report", pages: int = 1
) -> bytes:
    writer = PdfFileWriter(stream_xrefs=False)
    font = writer.add_object(
        generic.DictionaryObject(
            {
                pdf_name("/Type"): pdf_name("/Font"),
                pdf_name("/Subtype"): pdf_name("/Type1"),
                pdf_name("/BaseFont"): pdf_name("/Helvetica"),
            }
        )
    )
    for i in range(pages):
        content = f"BT /F1 12 Tf 72 720 Td ({text} - page {i + 1}) Tj ET".encode("ascii")
        stream = writer.add_object(generic.StreamObject(stream_data=content))
        page = generic.DictionaryObject(
            {
                pdf_name("/Type"): pdf_name("/Page"),
                pdf_name("/MediaBox"): generic.ArrayObject(
                    [generic.NumberObject(v) for v in (0, 0, 595, 842)]
                ),
                pdf_name("/Contents"): stream,
                pdf_name("/Resources"): generic.DictionaryObject(
                    {pdf_name("/Font"): generic.DictionaryObject({pdf_name("/F1"): font})}
                ),
            }
        )
        writer.insert_page(page)
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


def encrypted_pdf() -> bytes:
    """Synthetic PDF 2.0 AES-256 encrypted document (public pyHanko API)."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils.writer import copy_into_new_writer

    writer = copy_into_new_writer(PdfFileReader(BytesIO(synthetic_pdf())))
    writer.encrypt("synthetic-owner-password", "synthetic-user-password")
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


MALFORMED_PDF = (
    b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
)
NOT_A_PDF = b"SYNTHETIC: this is not a PDF file"
