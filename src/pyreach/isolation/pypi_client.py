"""PyPI JSON API client and offline mock for acquiring exact dependency releases."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Protocol

import httpx
from packaging.utils import canonicalize_name


class PyPIClientInterface(Protocol):
    """Protocol for querying PyPI and downloading wheels/sdists."""

    def get_release_info(self, package: str, version: str) -> list[dict[str, Any]]:
        """Return release file descriptors for package==version."""
        ...

    def download_package(
        self,
        package: str,
        version: str,
        dest_dir: Path,
        prefer_wheel: bool = True,
        expected_hashes: list[str] | None = None,
    ) -> Path:
        """Download exact wheel or sdist, verify hash, and return file path."""
        ...


class HTTPPyPIClient:
    """Live PyPI client querying the JSON API and downloading packages with hash validation."""

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    def get_release_info(self, package: str, version: str) -> list[dict[str, Any]]:
        norm_name = canonicalize_name(package)
        url = f"https://pypi.org/pypi/{norm_name}/{version}/json"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url)
                if resp.status_code == 404:
                    return []
                resp.raise_for_status()
                data = resp.json()
                return list(data.get("urls", []))
        except Exception:
            return []

    def download_package(
        self,
        package: str,
        version: str,
        dest_dir: Path,
        prefer_wheel: bool = True,
        expected_hashes: list[str] | None = None,
    ) -> Path:
        urls = self.get_release_info(package, version)
        if not urls:
            raise RuntimeError(f"PyPI release not found for {package}=={version}")

        # Filter by preference: pure Python wheels (py3-none-any) first, then sdist, then platform wheels
        chosen_url: dict[str, Any] | None = None
        dist_type = "sdist"

        # 1. Prioritize pure-python universal wheel if present
        for u in urls:
            fn = str(u.get("filename", "")).lower()
            if u.get("packagetype") == "bdist_wheel" and "none-any.whl" in fn:
                chosen_url = u
                dist_type = "pure_wheel"
                break

        # 2. Prefer sdist if no universal wheel
        if not chosen_url:
            for u in urls:
                if u.get("packagetype") == "sdist":
                    chosen_url = u
                    dist_type = "sdist"
                    break

        # 3. Fall back to platform wheel only if neither universal wheel nor sdist exists
        if not chosen_url and prefer_wheel:
            for u in urls:
                if u.get("packagetype") == "bdist_wheel":
                    chosen_url = u
                    dist_type = "platform_wheel"
                    break

        if not chosen_url and urls:
            chosen_url = urls[0]
            dist_type = "sdist" if chosen_url.get("packagetype") == "sdist" else "platform_wheel"

        if not chosen_url:
            raise RuntimeError(f"No suitable distribution found for {package}=={version}")

        download_url = str(chosen_url["url"])
        filename = str(chosen_url["filename"])
        target_file: Path = dest_dir / filename
        dest_dir.mkdir(parents=True, exist_ok=True)

        # Determine distribution tag
        if filename.endswith(".whl"):
            parts = filename[:-4].split("-")
            dist_tag = "-".join(parts[2:]) if len(parts) >= 3 else "wheel"
        else:
            dist_tag = "sdist"

        with httpx.Client(timeout=self.timeout) as client, client.stream("GET", download_url) as resp:
            resp.raise_for_status()
            hasher = hashlib.sha256()
            with open(target_file, "wb") as f:
                for chunk in resp.iter_bytes(64 * 1024):
                    hasher.update(chunk)
                    f.write(chunk)

        computed_sha = hasher.hexdigest().lower()
        if expected_hashes:
            expected_lower = [h.lower() for h in expected_hashes]
            if computed_sha not in expected_lower:
                target_file.unlink(missing_ok=True)
                raise ValueError(
                    f"Hash mismatch for {filename}: computed {computed_sha}, expected one of {expected_lower}"
                )

        # Write metadata file for distribution tracking
        meta_file = dest_dir / f"{filename}.meta.json"
        import json
        meta_file.write_text(
            json.dumps(
                {
                    "filename": filename,
                    "distribution_type": dist_type,
                    "distribution_tag": dist_tag,
                    "is_platform_wheel": dist_type == "platform_wheel",
                }
            ),
            encoding="utf-8",
        )

        return target_file


class MockPyPIClient:
    """Mock PyPI client serving locally synthesized archives for testing."""

    def __init__(self, package_files: dict[tuple[str, str], Path] | None = None) -> None:
        # (package_name, version) -> Path to archive file on disk
        self.package_files = package_files or {}

    def get_release_info(self, package: str, version: str) -> list[dict[str, Any]]:
        norm = canonicalize_name(package)
        file_path = self.package_files.get((norm, version))
        if not file_path:
            return []
        return [
            {
                "filename": file_path.name,
                "packagetype": "bdist_wheel" if file_path.name.endswith(".whl") else "sdist",
                "url": f"file://{file_path.resolve()}",
            }
        ]

    def download_package(
        self,
        package: str,
        version: str,
        dest_dir: Path,
        prefer_wheel: bool = True,
        expected_hashes: list[str] | None = None,
    ) -> Path:
        norm = canonicalize_name(package)
        src_path = self.package_files.get((norm, version))
        if not src_path or not src_path.exists():
            raise RuntimeError(f"MockPyPIClient: no package registered for {package}=={version}")

        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / src_path.name

        content = src_path.read_bytes()
        computed_sha = hashlib.sha256(content).hexdigest().lower()

        if expected_hashes:
            expected_lower = [h.lower() for h in expected_hashes]
            if computed_sha not in expected_lower:
                raise ValueError(f"MockPyPIClient: Hash mismatch for {src_path.name}")

        dest_file.write_bytes(content)

        import json
        is_wheel = dest_file.name.endswith(".whl")
        is_pure = "none-any.whl" in dest_file.name.lower()
        dist_type = "pure_wheel" if is_pure else ("platform_wheel" if is_wheel else "sdist")
        if is_wheel:
            parts = dest_file.name[:-4].split("-")
            dist_tag = "-".join(parts[2:]) if len(parts) >= 3 else "wheel"
        else:
            dist_tag = "sdist"

        meta_file = dest_dir / f"{dest_file.name}.meta.json"
        meta_file.write_text(
            json.dumps(
                {
                    "filename": dest_file.name,
                    "distribution_type": dist_type,
                    "distribution_tag": dist_tag,
                    "is_platform_wheel": dist_type == "platform_wheel",
                }
            ),
            encoding="utf-8",
        )

        return dest_file
