"""SQLite on-disk package-summary cache for accelerating repeated dependency reachability analysis."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

CURRENT_ANALYZER_VERSION = "0.1.0"


@dataclass
class CachedPackageSummary:
    """Serializable summary of a pre-analyzed package."""

    package_name: str
    version: str
    wheel_hash: str
    analyzer_version: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    native_modules: list[str]
    package_stats: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data_str: str) -> CachedPackageSummary:
        d = json.loads(data_str)
        return cls(**d)


class PackageSummaryCache:
    """Manages an SQLite database storing pre-computed package call graph summaries."""

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            cache_dir = Path.home() / ".cache" / "pyreach"
            cache_dir.mkdir(parents=True, exist_ok=True)
            db_path = cache_dir / "summary_cache.db"
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS package_summaries (
                    cache_key TEXT PRIMARY KEY,
                    package_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    wheel_hash TEXT NOT NULL,
                    analyzer_version TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    summary_json TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pkg_ver ON package_summaries(package_name, version);"
            )
            conn.commit()

    def compute_cache_key(
        self,
        package_name: str,
        version: str,
        wheel_hash: str,
        analyzer_version: str = CURRENT_ANALYZER_VERSION,
    ) -> str:
        norm_pkg = canonicalize_name(package_name)
        raw = f"{norm_pkg}:{version}:{wheel_hash.lower()}:{analyzer_version}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(
        self,
        package_name: str,
        version: str,
        wheel_hash: str,
        analyzer_version: str = CURRENT_ANALYZER_VERSION,
    ) -> CachedPackageSummary | None:
        """Retrieve pre-computed package summary if key matches and version has not changed."""
        key = self.compute_cache_key(package_name, version, wheel_hash, analyzer_version)
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT summary_json FROM package_summaries WHERE cache_key = ?;",
                (key,),
            )
            row = cur.fetchone()
            if row:
                try:
                    return CachedPackageSummary.from_json(row[0])
                except Exception:
                    return None
        return None

    def put(
        self,
        package_name: str,
        version: str,
        wheel_hash: str,
        summary: CachedPackageSummary,
        analyzer_version: str = CURRENT_ANALYZER_VERSION,
    ) -> None:
        """Store package summary in SQLite cache."""
        key = self.compute_cache_key(package_name, version, wheel_hash, analyzer_version)
        summary_json = summary.to_json()
        norm_pkg = canonicalize_name(package_name)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO package_summaries
                (cache_key, package_name, version, wheel_hash, analyzer_version, summary_json)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (key, norm_pkg, version, wheel_hash.lower(), analyzer_version, summary_json),
            )
            conn.commit()

    def clear(self) -> None:
        """Purge all entries from the cache."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM package_summaries;")
            conn.commit()
