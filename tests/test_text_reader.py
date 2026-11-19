from pathlib import Path

import pytest

from pyreach.isolation.text_reader import read_text_file


@pytest.mark.parametrize(
    "encoding",
    [
        "utf-8-sig",
        "utf-16",
        "utf-32",
    ],
)
def test_read_text_file_detects_bom_encodings(
    tmp_path: Path, encoding: str
) -> None:
    path = tmp_path / "input.txt"
    path.write_bytes("name==1.0\r\n".encode(encoding))
    assert read_text_file(path) == "name==1.0\n"


def test_read_text_file_falls_back_to_cp1252(tmp_path: Path) -> None:
    path = tmp_path / "input.txt"
    path.write_bytes("name==1.0 # café\r\n".encode("cp1252"))
    assert read_text_file(path) == "name==1.0 # café\n"


def test_read_text_file_rejects_garbage_binary(tmp_path: Path) -> None:
    path = tmp_path / "input.bin"
    path.write_bytes(b"\x00\x81\x8d\x90")
    with pytest.raises(UnicodeDecodeError):
        read_text_file(path)
