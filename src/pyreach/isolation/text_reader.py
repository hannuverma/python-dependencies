"""Encoding-safe text input for manifests, lockfiles, and advisory data."""

from __future__ import annotations

from pathlib import Path


def read_text_file(path: Path) -> str:
    """Read text with BOM detection and a controlled cp1252 fallback."""
    raw = path.read_bytes()
    encodings = (
        ("utf-8-sig", b"\xef\xbb\xbf"),
        ("utf-32", b"\xff\xfe\x00\x00"),
        ("utf-32", b"\x00\x00\xfe\xff"),
        ("utf-16", b"\xff\xfe"),
        ("utf-16", b"\xfe\xff"),
    )
    for encoding, bom in encodings:
        if raw.startswith(bom):
            return raw.decode(encoding).replace("\r\n", "\n").replace("\r", "\n")
    try:
        return raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError:
        text = raw.decode("cp1252").replace("\r\n", "\n").replace("\r", "\n")
        if "\x00" in text:
            raise UnicodeDecodeError("text", raw, 0, len(raw), "binary input")
        return text
