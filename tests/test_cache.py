"""Unit tests for Stage 7: SQLite on-disk package-summary cache."""

from pathlib import Path

from pyreach.isolation.cache import (
    CURRENT_ANALYZER_VERSION,
    CachedPackageSummary,
    PackageSummaryCache,
)


def test_package_summary_cache_hit_and_miss(tmp_path: Path) -> None:
    db_file = tmp_path / "test_cache.db"
    cache = PackageSummaryCache(db_path=db_file)

    # 1. Cache miss on empty database
    res = cache.get("pillow", "10.1.0", "hash123")
    assert res is None

    # 2. Put entry in cache
    summary = CachedPackageSummary(
        package_name="pillow",
        version="10.1.0",
        wheel_hash="hash123",
        analyzer_version=CURRENT_ANALYZER_VERSION,
        nodes=[{"node_id": "PIL.ImageMath:eval", "name": "eval"}],
        edges=[{"caller_id": "PIL:main", "callee_id": "PIL.ImageMath:eval"}],
        native_modules=["PIL._imaging"],
        package_stats={"files_total": 30, "files_parsed": 30, "files_failed": 0},
    )
    cache.put("pillow", "10.1.0", "hash123", summary)

    # 3. Cache hit with identical parameters
    hit = cache.get("pillow", "10.1.0", "hash123")
    assert hit is not None
    assert hit.package_name == "pillow"
    assert hit.version == "10.1.0"
    assert len(hit.nodes) == 1
    assert hit.nodes[0]["node_id"] == "PIL.ImageMath:eval"
    assert hit.native_modules == ["PIL._imaging"]


def test_cache_invalidation_on_analyzer_version_change(tmp_path: Path) -> None:
    db_file = tmp_path / "test_cache.db"
    cache = PackageSummaryCache(db_path=db_file)

    summary = CachedPackageSummary(
        package_name="urllib3",
        version="1.26.5",
        wheel_hash="abc456",
        analyzer_version="0.1.0",
        nodes=[],
        edges=[],
        native_modules=[],
        package_stats={},
    )
    cache.put("urllib3", "1.26.5", "abc456", summary, analyzer_version="0.1.0")

    # Hit on version 0.1.0
    assert cache.get("urllib3", "1.26.5", "abc456", analyzer_version="0.1.0") is not None

    # Miss when analyzer version changes to 0.2.0
    miss = cache.get("urllib3", "1.26.5", "abc456", analyzer_version="0.2.0")
    assert miss is None


def test_cache_invalidation_on_wheel_hash_change(tmp_path: Path) -> None:
    db_file = tmp_path / "test_cache.db"
    cache = PackageSummaryCache(db_path=db_file)

    summary = CachedPackageSummary(
        package_name="jinja2",
        version="3.1.4",
        wheel_hash="oldhash",
        analyzer_version=CURRENT_ANALYZER_VERSION,
        nodes=[],
        edges=[],
        native_modules=[],
        package_stats={},
    )
    cache.put("jinja2", "3.1.4", "oldhash", summary)

    # Hit on oldhash
    assert cache.get("jinja2", "3.1.4", "oldhash") is not None

    # Miss on newhash
    assert cache.get("jinja2", "3.1.4", "newhash") is None
