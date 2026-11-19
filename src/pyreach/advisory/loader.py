"""Advisory input loading for IDs and common scanner JSON formats."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pyreach.advisory.osv_client import OSVClientInterface, parse_osv_json
from pyreach.isolation.text_reader import read_text_file
from pyreach.models import Advisory


def _ids_from_json(data: Any) -> list[str]:
    if isinstance(data, list) and all(isinstance(item, str) for item in data):
        return [item.strip() for item in data if item.strip()]
    if isinstance(data, dict):
        ids: list[str] = []
        if data.get("id"):
            ids.append(str(data["id"]))
        for result in data.get("results", []):
            for vuln in result.get("vulnerabilities", []):
                if vuln.get("id"):
                    ids.append(str(vuln["id"]))
        for dependency in data.get("dependencies", []):
            for vuln in dependency.get("vulns", []):
                if vuln.get("id"):
                    ids.append(str(vuln["id"]))
        if data.get("advisories"):
            for advisory in data["advisories"]:
                if advisory.get("id"):
                    ids.append(str(advisory["id"]))
        return ids
    return []


def load_advisory_input(
    value: str,
    client: OSVClientInterface,
) -> tuple[list[Advisory], str]:
    """Load one advisory CLI value and return advisories plus its source label."""
    path = Path(value)
    if not path.exists():
        ids = [part.strip() for part in value.split(",") if part.strip()]
        return _fetch_ids(ids, client), value

    text = read_text_file(path)
    if path.suffix.lower() == ".json":
        try:
            data: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid advisory JSON in '{path}': {exc}") from exc
        if isinstance(data, dict) and data.get("id"):
            return [parse_osv_json(data)], str(path)
        ids = _ids_from_json(data)
    else:
        ids = [
            line.split("#", 1)[0].strip()
            for line in text.splitlines()
            if line.split("#", 1)[0].strip()
        ]
    if not ids:
        raise ValueError(f"Advisory input '{path}' is empty or unrecognized.")
    advisories = _fetch_ids(ids, client)
    if not advisories:
        raise ValueError(f"No recognized advisories found in '{path}'.")
    return advisories, str(path)


def _fetch_ids(ids: list[str], client: OSVClientInterface) -> list[Advisory]:
    advisories: list[Advisory] = []
    seen: set[str] = set()
    for advisory_id in ids:
        advisory = client.get_advisory(advisory_id)
        if advisory and advisory.id not in seen:
            advisories.append(advisory)
            seen.add(advisory.id)
    return advisories
