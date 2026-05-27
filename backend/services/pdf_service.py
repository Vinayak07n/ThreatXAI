"""pdf_service.py — Lightweight PDF generation for alerts/chat reports."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, List


def _pdf_escape(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _wrap_line(line: str, width: int = 100) -> List[str]:
    if len(line) <= width:
        return [line]
    out = []
    current = line
    while len(current) > width:
        split_at = current.rfind(" ", 0, width)
        if split_at <= 0:
            split_at = width
        out.append(current[:split_at].rstrip())
        current = current[split_at:].lstrip()
    if current:
        out.append(current)
    return out


def _paginate(lines: Iterable[str], max_lines_per_page: int = 52) -> List[List[str]]:
    all_lines: List[str] = []
    for line in lines:
        safe = (line or "").encode("ascii", "replace").decode("ascii")
        all_lines.extend(_wrap_line(safe, 100))
    if not all_lines:
        all_lines = ["(No data)"]
    pages = []
    for i in range(0, len(all_lines), max_lines_per_page):
        pages.append(all_lines[i:i + max_lines_per_page])
    return pages


def build_text_pdf(title: str, lines: Iterable[str]) -> bytes:
    """Create a simple multi-page text PDF using core PDF objects only."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    header_lines = [
        f"{title}",
        f"Generated: {now}",
        "-" * 100,
    ]
    pages_content = _paginate([*header_lines, *list(lines)], max_lines_per_page=52)

    objects = {}
    # Fixed IDs
    catalog_id = 1
    pages_id = 2
    font_id = 3

    next_id = 4
    page_ids = []

    for page_lines in pages_content:
        content_lines = ["BT", "/F1 10 Tf", "50 800 Td", "13 TL"]
        first = True
        for ln in page_lines:
            escaped = _pdf_escape(ln)
            if first:
                content_lines.append(f"({escaped}) Tj")
                first = False
            else:
                content_lines.append("T*")
                content_lines.append(f"({escaped}) Tj")
        content_lines.append("ET")
        content_stream = "\n".join(content_lines).encode("ascii", "replace")
        content_id = next_id
        next_id += 1
        objects[content_id] = (
            f"<< /Length {len(content_stream)} >>\nstream\n".encode("ascii")
            + content_stream
            + b"\nendstream"
        )

        page_id = next_id
        next_id += 1
        page_ids.append(page_id)
        objects[page_id] = (
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
            f"/Contents {content_id} 0 R >>"
        ).encode("ascii")

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[catalog_id] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")
    objects[pages_id] = f"<< /Type /Pages /Kids [ {kids} ] /Count {len(page_ids)} >>".encode("ascii")
    objects[font_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    max_id = max(objects.keys())
    out = bytearray()
    out.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {0: 0}

    for obj_id in range(1, max_id + 1):
        offsets[obj_id] = len(out)
        out.extend(f"{obj_id} 0 obj\n".encode("ascii"))
        out.extend(objects[obj_id])
        out.extend(b"\nendobj\n")

    xref_offset = len(out)
    out.extend(f"xref\n0 {max_id + 1}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for obj_id in range(1, max_id + 1):
        out.extend(f"{offsets[obj_id]:010d} 00000 n \n".encode("ascii"))

    out.extend(
        (
            "trailer\n"
            f"<< /Size {max_id + 1} /Root {catalog_id} 0 R >>\n"
            "startxref\n"
            f"{xref_offset}\n"
            "%%EOF\n"
        ).encode("ascii")
    )

    return bytes(out)
