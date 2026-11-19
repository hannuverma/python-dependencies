"""Unit tests for Stage 3: Safe package acquisition, manifest parsing, archive extraction, and sandboxing."""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from pyreach.engine.verdict import VerdictEngine
from pyreach.isolation.manifest_parser import (
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject_toml,
    parse_requirements_txt,
    parse_uv_lock,
)
from pyreach.isolation.pypi_client import HTTPPyPIClient, MockPyPIClient
from pyreach.isolation.safe_archive import (
    SafeArchiveError,
    extract_archive_safely,
)
from pyreach.isolation.sandbox import DockerSandboxRunner, SandboxConfig
from pyreach.models import (
    Advisory,
    AffectedSymbol,
    CallGraph,
    CallGraphNode,
    ConfidenceLevel,
    EntryPoint,
    EntryPointType,
    SymbolEvidenceSource,
    SymbolType,
    UncertaintyCategory,
    Verdict,
)


def test_requirements_txt_parsing_with_hashes() -> None:
    content = """
# Production dependencies
requests == 2.26.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
urllib3 == 1.26.4 \\
    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
PyYAML==5.4.1
-r other.txt
--extra-index-url https://example.com
"""
    pkgs = parse_requirements_txt(content)
    assert len(pkgs) == 3
    assert pkgs[0].name == "requests"
    assert pkgs[0].version == "2.26.0"
    assert len(pkgs[0].hashes) == 1
    assert pkgs[1].name == "urllib3"
    assert pkgs[1].version == "1.26.4"
    assert pkgs[2].name == "pyyaml"  # PEP 503 normalized
    assert pkgs[2].version == "5.4.1"


def test_poetry_lock_parsing() -> None:
    content = """
[[package]]
name = "Jinja2"
version = "2.11.3"
category = "main"
optional = false
python-versions = ">=2.7, !=3.0.*"
files = [
    {file = "Jinja2-2.11.3-py2.py3-none-any.whl", hash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
]

[[package]]
name = "MarkupSafe"
version = "1.1.1"
category = "main"
files = []
"""
    pkgs = parse_poetry_lock(content)
    assert len(pkgs) == 2
    assert pkgs[0].name == "jinja2"
    assert pkgs[0].version == "2.11.3"
    assert len(pkgs[0].hashes) == 1
    assert pkgs[1].name == "markupsafe"


def test_pipfile_lock_parsing() -> None:
    content = """{
        "default": {
            "requests": {
                "version": "==2.25.1",
                "hashes": ["sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]
            }
        },
        "develop": {}
    }"""
    pkgs = parse_pipfile_lock(content)
    assert len(pkgs) == 1
    assert pkgs[0].name == "requests"
    assert pkgs[0].version == "2.25.1"


def test_uv_lock_parsing() -> None:
    content = """
version = 1
revision = 1

[[package]]
name = "pillow"
version = "9.0.0"
sdist = { url = "https://...", hash = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" }
"""
    pkgs = parse_uv_lock(content)
    assert len(pkgs) == 1
    assert pkgs[0].name == "pillow"
    assert pkgs[0].version == "9.0.0"


def test_pyproject_toml_parsing() -> None:
    content = """
[project]
name = "sample-app"
version = "0.1.0"
dependencies = [
    "requests == 2.28.1",
    "flask == 2.2.2",
]
"""
    pkgs = parse_pyproject_toml(content)
    assert len(pkgs) == 2
    assert pkgs[0].name == "requests"
    assert pkgs[0].version == "2.28.1"
    assert pkgs[1].name == "flask"


# ---------------------------------------------------------------------------
# Safe Archive Defense Tests
# ---------------------------------------------------------------------------


def test_safe_archive_zip_slip_traversal_blocked(tmp_path: Path) -> None:
    """Malicious zip with ../ path traversal must be rejected with SafeArchiveError."""
    malicious_zip = tmp_path / "evil.zip"
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../evil.py", "print('hacked')")

    target_extract = tmp_path / "extracted"
    with pytest.raises(SafeArchiveError, match="Zip-slip path traversal detected"):
        extract_archive_safely(malicious_zip, target_extract)


def test_safe_archive_absolute_path_blocked(tmp_path: Path) -> None:
    """Malicious zip with absolute path must be rejected."""
    malicious_zip = tmp_path / "evil_abs.zip"
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("/etc/passwd", "root:x:0:0")

    target_extract = tmp_path / "extracted"
    with pytest.raises(SafeArchiveError, match="Absolute path in archive"):
        extract_archive_safely(malicious_zip, target_extract)


def test_safe_archive_symlink_escape_blocked(tmp_path: Path) -> None:
    """Malicious tar with symlink pointing outside target directory must be blocked."""
    malicious_tar = tmp_path / "evil_sym.tar"
    with tarfile.open(malicious_tar, "w") as tf:
        ti = tarfile.TarInfo(name="symlink_to_root")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "../../etc/passwd"
        tf.addfile(ti)

    target_extract = tmp_path / "extracted"
    with pytest.raises(SafeArchiveError, match="Symlink escapes target directory"):
        extract_archive_safely(malicious_tar, target_extract)


def test_safe_archive_bomb_file_size_exceeded(tmp_path: Path) -> None:
    """Archive bomb with oversized file must be rejected."""
    bomb_zip = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb_zip, "w") as zf:
        zf.writestr("large.txt", b"A" * 1024)

    target_extract = tmp_path / "extracted"
    # Set limit to 500 bytes to simulate bomb limit trigger
    with pytest.raises(SafeArchiveError, match="Archive bomb protection: Single file"):
        extract_archive_safely(bomb_zip, target_extract, max_file_size=500)


def test_clean_archive_extraction(tmp_path: Path) -> None:
    """Clean zip archive extracts files safely."""
    clean_zip = tmp_path / "pkg-1.0.whl"
    with zipfile.ZipFile(clean_zip, "w") as zf:
        zf.writestr("pkg/__init__.py", "__version__ = '1.0'\n")
        zf.writestr("pkg/core.py", "def run(): pass\n")

    target_extract = tmp_path / "clean_extracted"
    extracted_dir = extract_archive_safely(clean_zip, target_extract)
    assert (extracted_dir / "pkg" / "__init__.py").exists()
    assert (extracted_dir / "pkg" / "core.py").exists()


def test_mock_pypi_client_download_and_hash_verification(tmp_path: Path) -> None:
    """Mock PyPI client verifies hashes and writes package to destination."""
    whl_path = tmp_path / "demo_pkg-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(whl_path, "w") as zf:
        zf.writestr("demo/__init__.py", "x = 1")

    client = MockPyPIClient(package_files={("demo-pkg", "1.0.0"): whl_path})
    dest_dir = tmp_path / "downloads"

    # 1. Download without hash check
    out_file = client.download_package("demo_pkg", "1.0.0", dest_dir)
    assert out_file.exists()

    # 2. Download with wrong expected hash raises ValueError
    with pytest.raises(ValueError, match="Hash mismatch"):
        client.download_package(
            "demo_pkg", "1.0.0", dest_dir, expected_hashes=["0000000000000000000000000000000000000000000000000000000000000000"]
        )


def test_docker_sandbox_runner_command_construction(tmp_path: Path) -> None:
    """Docker runner builds hermetic execution command with --network none, --read-only, and memory limits."""
    runner = DockerSandboxRunner(
        config=SandboxConfig(
            memory_limit="4g",
            cpu_limit="4.0",
            base_image="python:3.11-slim-bookworm",
        )
    )

    proj_dir = tmp_path / "my_project"
    proj_dir.mkdir()
    out_dir = tmp_path / "my_out"
    out_dir.mkdir()

    cmd = runner.build_run_command(
        project_dir=proj_dir,
        advisory_ids=["GHSA-1234", "CVE-5678"],
        output_dir=out_dir,
    )

    assert "docker" == cmd[0]
    assert "run" == cmd[1]
    assert "--network" in cmd and "none" in cmd
    assert "--read-only" in cmd
    assert "--memory" in cmd and "4g" in cmd
    assert "--cpus" in cmd and "4.0" in cmd
    assert "--user" in cmd and "1000:1000" in cmd
    assert f"{proj_dir.resolve()}:/project:ro" in cmd
    assert f"{out_dir.resolve()}:/output:rw" in cmd
    assert "python:3.11-slim-bookworm" in cmd
    assert "pyreach" in cmd
    assert "scan" in cmd
    assert "GHSA-1234" in cmd
    assert "CVE-5678" in cmd


def test_wheel_preference_order_pure_wheel_then_sdist_then_platform(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """PyPI client must prefer py3-none-any universal wheel, then sdist, then platform wheel."""
    client = HTTPPyPIClient()

    releases = [
        {
            "packagetype": "bdist_wheel",
            "filename": "sample-1.0.0-cp310-cp310-manylinux.whl",
            "url": "https://example.com/whl_plat",
            "digests": {"sha256": "abc"},
        },
        {
            "packagetype": "sdist",
            "filename": "sample-1.0.0.tar.gz",
            "url": "https://example.com/sdist",
            "digests": {"sha256": "def"},
        },
        {
            "packagetype": "bdist_wheel",
            "filename": "sample-1.0.0-py3-none-any.whl",
            "url": "https://example.com/whl_pure",
            "digests": {"sha256": "ghi"},
        },
    ]

    captured_url = None

    class DummyStream:
        def __enter__(self) -> DummyStream:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def raise_for_status(self) -> None:
            pass

        def iter_bytes(self, chunk_size: int = 65536) -> Any:
            yield b"dummy content"

    class DummyClient:
        def __init__(self, timeout: float = 30.0) -> None:
            pass

        def __enter__(self) -> DummyClient:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def get(self, url: str) -> object:
            class DummyResponse:
                status_code = 200

                def raise_for_status(self) -> None:
                    pass

                def json(self) -> dict:
                    return {"urls": releases}

            return DummyResponse()

        def stream(self, method: str, url: str) -> DummyStream:
            nonlocal captured_url
            captured_url = url
            return DummyStream()

    monkeypatch.setattr("httpx.Client", DummyClient)

    # 1. Pure wheel should be chosen first
    target = client.download_package(
        "sample", "1.0.0", dest_dir=tmp_path / "d1", prefer_wheel=True
    )
    assert "none-any.whl" in target.name
    assert captured_url == "https://example.com/whl_pure"

    # 2. When pure wheel is absent, sdist should be chosen next
    releases_no_pure = [r for r in releases if "none-any" not in r["filename"]]

    def get_no_pure(url: str) -> object:
        class DummyResponse:
            status_code = 200

            def raise_for_status(self) -> None:
                pass

            def json(self) -> dict:
                return {"urls": releases_no_pure}

        return DummyResponse()

    monkeypatch.setattr(DummyClient, "get", lambda self, url: get_no_pure(url))
    target2 = client.download_package(
        "sample", "1.0.0", dest_dir=tmp_path / "d2", prefer_wheel=True
    )
    assert target2.name.endswith(".tar.gz")
    assert captured_url == "https://example.com/sdist"

    # 3. When neither pure wheel nor sdist exists, fallback to platform wheel
    releases_only_plat = [releases[0]]

    def get_only_plat(url: str) -> object:
        class DummyResponse:
            status_code = 200

            def raise_for_status(self) -> None:
                pass

            def json(self) -> dict:
                return {"urls": releases_only_plat}

        return DummyResponse()

    monkeypatch.setattr(DummyClient, "get", lambda self, url: get_only_plat(url))
    target3 = client.download_package(
        "sample", "1.0.0", dest_dir=tmp_path / "d3", prefer_wheel=True
    )
    assert "cp310" in target3.name
    assert captured_url == "https://example.com/whl_plat"


def test_platform_wheel_with_platform_conditional_code_yields_uncertain() -> None:
    """When only platform wheels exist and package has platform conditionals, verdict must be UNCERTAIN."""
    cg = CallGraph(entry_points_complete=True)
    cg.package_platform_wheels["c-pkg"] = "c_pkg-1.0.0-cp310-cp310-manylinux.whl"
    cg.package_has_platform_conditionals.add("c-pkg")
    cg.package_distribution_filenames["c-pkg"] = "c_pkg-1.0.0-cp310-cp310-manylinux.whl"
    cg.package_distribution_tags["c-pkg"] = "cp310-cp310-manylinux"

    # Add entry point
    ep_node = CallGraphNode(
        node_id="app:run",
        package="app",
        module="app",
        name="run",
        qualified_name="run",
    )
    cg.add_node(ep_node)
    cg.add_entry_point(
        EntryPoint(
            symbol_id="app:run",
            entry_type=EntryPointType.MAIN,
            confidence=ConfidenceLevel.HIGH,
        )
    )

    adv = Advisory(
        id="GHSA-test-platform",
        package_name="c-pkg",
        fixed_versions=["2.0.0"],
        extracted_symbols=[
            AffectedSymbol(
                package="c-pkg",
                module="c_pkg.vuln",
                qualified_name="c_pkg.vuln.bad_func",
                symbol_type=SymbolType.FUNCTION,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
                confidence=ConfidenceLevel.HIGH,
            )
        ],
    )

    engine = VerdictEngine(call_graph=cg)
    finding = engine.evaluate_advisory(adv, installed_version="1.0.0")

    assert finding.verdict == Verdict.UNCERTAIN
    assert finding.confidence == ConfidenceLevel.HIGH
    assert finding.distribution_filename == "c_pkg-1.0.0-cp310-cp310-manylinux.whl"
    assert finding.distribution_tag == "cp310-cp310-manylinux"
    assert any(
        r.category == UncertaintyCategory.PLATFORM_WHEEL
        for r in finding.uncertainty_reasons
    )
