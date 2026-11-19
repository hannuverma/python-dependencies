"""Manifest and lockfile parser supporting requirements.txt, poetry.lock, Pipfile.lock, uv.lock, and pyproject.toml."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import canonicalize_name

from pyreach.isolation.text_reader import read_text_file


@dataclass(frozen=True)
class PinnedPackage:
    """A pinned dependency version extracted from a manifest or lockfile."""

    name: str  # PEP 503 canonicalized name
    version: str
    hashes: list[str] = field(default_factory=list)
    is_direct: bool = True


REQUIREMENTS_PIN_REGEX = re.compile(
    r"^\s*([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.\+]+)(.*)$"
)
HASH_REGEX = re.compile(r"--hash=sha256:([a-fA-F0-9]{64})")


def parse_requirements_txt(content: str) -> list[PinnedPackage]:
    """Parse standard requirements.txt content for exact package==version pins and SHA256 hashes."""
    packages: list[PinnedPackage] = []
    lines = content.splitlines()
    curr_name: str | None = None
    curr_version: str | None = None
    curr_hashes: list[str] = []

    def flush() -> None:
        nonlocal curr_name, curr_version, curr_hashes
        if curr_name and curr_version:
            packages.append(
                PinnedPackage(
                    name=canonicalize_name(curr_name),
                    version=curr_version,
                    hashes=list(curr_hashes),
                    is_direct=True,
                )
            )
        curr_name = None
        curr_version = None
        curr_hashes = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Skip options
        if line.startswith(("-r", "-i", "--extra-index-url", "-f", "--find-links", "-c")):
            continue

        match = REQUIREMENTS_PIN_REGEX.match(line)
        if match:
            flush()
            curr_name = match.group(1)
            curr_version = match.group(2)
            rest = match.group(3)
            curr_hashes.extend(HASH_REGEX.findall(rest))
        elif line.startswith("--hash=") and curr_name is not None:
            curr_hashes.extend(HASH_REGEX.findall(line))
        elif line.endswith("\\"):
            # Line continuation
            rest = line[:-1].strip()
            curr_hashes.extend(HASH_REGEX.findall(rest))

    flush()
    return packages


def parse_poetry_lock(content: str) -> list[PinnedPackage]:
    """Parse poetry.lock TOML content, including direct and transitive dependencies."""
    data = tomllib.loads(content)
    packages: list[PinnedPackage] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        # Extract file hashes if available
        hashes: list[str] = []
        files = pkg.get("files", [])
        for f in files:
            file_hash = f.get("hash", "")
            if file_hash.startswith("sha256:"):
                hashes.append(file_hash[7:])
            elif len(file_hash) == 64:
                hashes.append(file_hash)
        packages.append(
            PinnedPackage(
                name=canonicalize_name(name),
                version=str(version),
                hashes=hashes,
                is_direct=pkg.get("category") == "main",
            )
        )
    return packages


def parse_pipfile_lock(content: str) -> list[PinnedPackage]:
    """Parse Pipfile.lock JSON content."""
    data = json.loads(content)
    packages: list[PinnedPackage] = []

    sections = [("default", True), ("develop", False)]
    for section_name, is_direct in sections:
        section = data.get(section_name, {})
        for name, details in section.items():
            version_str = str(details.get("version", ""))
            if version_str.startswith("=="):
                version_str = version_str[2:]
            if not version_str:
                continue
            raw_hashes = details.get("hashes", [])
            hashes = [h[7:] if h.startswith("sha256:") else h for h in raw_hashes]
            packages.append(
                PinnedPackage(
                    name=canonicalize_name(name),
                    version=version_str,
                    hashes=hashes,
                    is_direct=is_direct,
                )
            )
    return packages


def parse_uv_lock(content: str) -> list[PinnedPackage]:
    """Parse uv.lock TOML content."""
    data = tomllib.loads(content)
    packages: list[PinnedPackage] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        hashes: list[str] = []
        wheels = pkg.get("wheels", [])
        sdist = pkg.get("sdist")
        if sdist and isinstance(sdist, dict) and "hash" in sdist:
            h = sdist["hash"]
            hashes.append(h[7:] if h.startswith("sha256:") else h)
        for w in wheels:
            if isinstance(w, dict) and "hash" in w:
                h = w["hash"]
                hashes.append(h[7:] if h.startswith("sha256:") else h)
        packages.append(
            PinnedPackage(
                name=canonicalize_name(name),
                version=str(version),
                hashes=hashes,
                is_direct=True,
            )
        )
    return packages


def parse_pyproject_toml(content: str) -> list[PinnedPackage]:
    """Parse PEP 621 dependencies from pyproject.toml."""
    data = tomllib.loads(content)
    packages: list[PinnedPackage] = []
    project_deps = data.get("project", {}).get("dependencies", [])

    for dep_str in project_deps:
        match = REQUIREMENTS_PIN_REGEX.match(dep_str)
        if match:
            packages.append(
                PinnedPackage(
                    name=canonicalize_name(match.group(1)),
                    version=match.group(2),
                    is_direct=True,
                )
            )
    return packages


def parse_project_manifests(project_root: Path) -> list[PinnedPackage]:
    """Auto-detect and parse any manifest/lockfile present in project_root in priority order."""
    # Priority: lockfiles first (poetry.lock, uv.lock, Pipfile.lock) then requirements.txt, pyproject.toml
    poetry_lock = project_root / "poetry.lock"
    if poetry_lock.exists():
        return parse_poetry_lock(read_text_file(poetry_lock))

    uv_lock = project_root / "uv.lock"
    if uv_lock.exists():
        return parse_uv_lock(read_text_file(uv_lock))

    pipfile_lock = project_root / "Pipfile.lock"
    if pipfile_lock.exists():
        return parse_pipfile_lock(read_text_file(pipfile_lock))

    req_txt = project_root / "requirements.txt"
    if req_txt.exists():
        return parse_requirements_txt(read_text_file(req_txt))

    pyproj = project_root / "pyproject.toml"
    if pyproj.exists():
        return parse_pyproject_toml(read_text_file(pyproj))

    return []
