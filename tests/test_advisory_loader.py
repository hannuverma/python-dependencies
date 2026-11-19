import json
from pathlib import Path

import pytest

from pyreach.advisory.loader import load_advisory_input
from pyreach.advisory.osv_client import OfflineOSVClient
from pyreach.models import Advisory


def _client() -> OfflineOSVClient:
    return OfflineOSVClient(
        fixtures={
            "GHSA-one": Advisory(id="GHSA-one", package_name="demo"),
            "GHSA-two": Advisory(id="GHSA-two", package_name="demo"),
        }
    )


def test_loads_comment_aware_id_file(tmp_path: Path) -> None:
    path = tmp_path / "ids.txt"
    path.write_text("# comment\nGHSA-one\n\nGHSA-two # inline\n", encoding="utf-8")
    advisories, source = load_advisory_input(str(path), _client())
    assert source == str(path)
    assert [item.id for item in advisories] == ["GHSA-one", "GHSA-two"]


@pytest.mark.parametrize(
    "payload",
    [
        ["GHSA-one"],
        {"results": [{"vulnerabilities": [{"id": "GHSA-one"}]}]},
        {"dependencies": [{"name": "demo", "version": "1", "vulns": [{"id": "GHSA-one"}]}]},
        {"advisories": [{"id": "GHSA-one", "package": "demo", "version": "1"}]},
    ],
)
def test_loads_common_scanner_json(tmp_path: Path, payload: object) -> None:
    path = tmp_path / "ids.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    advisories, _ = load_advisory_input(str(path), _client())
    assert [item.id for item in advisories] == ["GHSA-one"]


def test_rejects_empty_advisory_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.txt"
    path.write_text("# only comments\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty or unrecognized"):
        load_advisory_input(str(path), _client())
