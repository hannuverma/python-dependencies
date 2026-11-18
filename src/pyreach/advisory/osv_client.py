"""OSV API client and offline fixture loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

import httpx
from packaging.utils import canonicalize_name

from pyreach.models import Advisory


class OSVClientInterface(Protocol):
    """Protocol for fetching vulnerability advisories from OSV or local fixtures."""

    def get_advisory(self, advisory_id: str) -> Advisory | None:
        """Fetch a specific advisory by ID (e.g. GHSA-xxx or CVE-xxx)."""
        ...

    def query_advisories(self, package_name: str, version: str | None = None) -> list[Advisory]:
        """Fetch all advisories affecting a package, optionally filtered by version."""
        ...


def parse_osv_json(data: dict[str, Any]) -> Advisory:
    """Parse raw OSV JSON schema into the pyreach Advisory model."""
    adv_id = str(data.get("id", ""))
    aliases = [str(a) for a in data.get("aliases", [])]
    summary = data.get("summary")
    details = data.get("details")

    # Extract target package and version constraints from affected list
    affected_list = data.get("affected", [])
    raw_pkg_name = "unknown"
    affected_ranges: list[str] = []
    fixed_versions: list[str] = []

    if affected_list:
        first_affected = affected_list[0]
        pkg_info = first_affected.get("package", {})
        raw_pkg_name = pkg_info.get("name", "unknown")

        for affected_entry in affected_list:
            for r in affected_entry.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(str(event["fixed"]))
                    elif "introduced" in event:
                        affected_ranges.append(f">={event['introduced']}")

    # Extract FIX references
    fix_commits: list[str] = []
    references: list[str] = []
    for ref in data.get("references", []):
        url = ref.get("url", "")
        if not url:
            continue
        references.append(url)
        ref_type = ref.get("type", "").upper()
        if ref_type == "FIX" or "/commit/" in url:
            fix_commits.append(url)

    return Advisory(
        id=adv_id,
        aliases=aliases,
        package_name=canonicalize_name(raw_pkg_name),
        summary=summary,
        details=details,
        affected_ranges=affected_ranges,
        fixed_versions=list(dict.fromkeys(fixed_versions)),
        fix_commits=list(dict.fromkeys(fix_commits)),
        references=references,
    )


class HTTPOSVClient:
    """Live OSV API client with timeout and rate-limit safety."""

    def __init__(self, base_url: str = "https://api.osv.dev/v1", timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get_advisory(self, advisory_id: str) -> Advisory | None:
        url = f"{self.base_url}/vulns/{advisory_id}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url)
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()
                return parse_osv_json(data)
        except Exception:
            return None

    def query_advisories(self, package_name: str, version: str | None = None) -> list[Advisory]:
        url = f"{self.base_url}/query"
        body: dict[str, Any] = {
            "package": {"name": package_name, "ecosystem": "PyPI"}
        }
        if version:
            body["version"] = version
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=body)
                if resp.status_code == 404:
                    return []
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulns", [])
                return [parse_osv_json(v) for v in vulns]
        except Exception:
            return []


class OfflineOSVClient:
    """Offline OSV client reading from pre-loaded fixtures or a directory of JSON files."""

    def __init__(self, fixtures: dict[str, Advisory] | None = None, fixtures_dir: Path | None = None) -> None:
        self.advisories: dict[str, Advisory] = fixtures.copy() if fixtures else {}
        if fixtures_dir and fixtures_dir.exists():
            for p in fixtures_dir.glob("*.json"):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        adv = parse_osv_json(data)
                        self.advisories[adv.id] = adv
                        for alias in adv.aliases:
                            self.advisories[alias] = adv
                except Exception:
                    continue

    def add_advisory(self, advisory: Advisory) -> None:
        self.advisories[advisory.id] = advisory
        for alias in advisory.aliases:
            self.advisories[alias] = advisory

    def get_advisory(self, advisory_id: str) -> Advisory | None:
        return self.advisories.get(advisory_id)

    def query_advisories(self, package_name: str, version: str | None = None) -> list[Advisory]:
        norm = canonicalize_name(package_name)
        results: list[Advisory] = []
        for adv in self.advisories.values():
            if canonicalize_name(adv.package_name) == norm:
                if version is None or adv.is_version_affected(version):
                    if adv not in results:
                        results.append(adv)
        return results
