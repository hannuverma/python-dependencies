"""Unit tests for Stage 2: Advisory ingestion, diff parsing, and symbol extraction with REAL fixtures."""

import json
from pathlib import Path
from typing import Any

import pytest

from pyreach.advisory.commit_miner import CommitMiner
from pyreach.advisory.diff_parser import parse_unified_diff
from pyreach.advisory.llm_fallback import ASTValidatedLLMExtractor, MockLLMExtractor
from pyreach.advisory.osv_client import HTTPOSVClient, parse_osv_json
from pyreach.advisory.resolver import AdvisorySymbolResolver, MockVCSClient
from pyreach.models import (
    Advisory,
    ConfidenceLevel,
    SymbolEvidenceSource,
    SymbolType,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_osv_json_ingestion() -> None:
    """Verify ingestion of real OSV record for urllib3 CVE-2021-33503."""
    osv_path = FIXTURES_DIR / "advisories" / "urllib3_GHSA-q2q7-5pp4-w6pg.json"
    osv_data = json.loads(osv_path.read_text(encoding="utf-8"))
    adv = parse_osv_json(osv_data)

    assert adv.id == "GHSA-q2q7-5pp4-w6pg"
    assert "CVE-2021-33503" in adv.aliases
    assert adv.package_name == "urllib3"
    assert "1.26.5" in adv.fixed_versions
    assert "https://github.com/urllib3/urllib3/commit/2d4a3fee6de2fa45eb82169361918f759269b4ec" in adv.fix_commits


def test_osv_git_range_ingestion_uses_repository_reference() -> None:
    """GIT range fixed events become usable commit references."""
    adv = parse_osv_json(
        {
            "id": "GHSA-git-range",
            "affected": [
                {
                    "package": {"name": "example"},
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [{"introduced": "0"}, {"fixed": "abc123"}],
                        }
                    ],
                }
            ],
            "references": [{"type": "PACKAGE", "url": "https://github.com/example/project"}],
        }
    )

    assert adv.fix_commits == ["https://github.com/example/project/commit/abc123"]


def test_diff_parser_identifies_native_only_changes() -> None:
    """Native-only commits are distinguishable from Python source fixes."""
    diff_text = """diff --git a/src/native.c b/src/native.c
index 1111111..2222222 100644
--- a/src/native.c
+++ b/src/native.c
@@ -1 +1 @@
-return 0;
+return 1;
"""
    from pyreach.advisory.diff_parser import parse_unified_diff_with_metadata

    parsed = parse_unified_diff_with_metadata(diff_text)
    assert parsed.has_native_changes is True
    assert parsed.has_python_changes is False


def test_diff_parser_distinguishes_mixed_native_and_python_changes() -> None:
    """A mixed commit is not classified as native-only."""
    diff_text = """diff --git a/src/native.c b/src/native.c
index 1111111..2222222 100644
--- a/src/native.c
+++ b/src/native.c
@@ -1 +1 @@
-return 0;
+return 1;
diff --git a/src/module.py b/src/module.py
index 1111111..2222222 100644
--- a/src/module.py
+++ b/src/module.py
@@ -1 +1 @@
-VALUE = 0
+VALUE = 1
"""
    from pyreach.advisory.diff_parser import parse_unified_diff_with_metadata

    parsed = parse_unified_diff_with_metadata(diff_text)
    assert parsed.has_native_changes is True
    assert parsed.has_python_changes is True


def test_osv_client_reloads_cache_without_current_schema_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Old advisory cache entries are discarded so newly supported GIT ranges are fetched."""
    cache_dir = tmp_path / ".cache" / "pyreach" / "advisories"
    cache_dir.mkdir(parents=True)
    cache_file = cache_dir / "GHSA-cache.json"
    cache_file.write_text('{"id": "GHSA-cache"}', encoding="utf-8")
    cache_file.with_suffix(".meta").write_text("1", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    raw = {
        "id": "GHSA-cache",
        "affected": [
            {
                "package": {"name": "example"},
                "ranges": [
                    {
                        "type": "GIT",
                        "repo": "https://github.com/example/project",
                        "events": [{"fixed": "abc123"}],
                    }
                ],
            }
        ],
    }

    class FakeResponse:
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return raw

    class FakeClient:
        def __init__(self, **_: object) -> None:
            pass

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def get(self, _: str) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr("pyreach.advisory.osv_client.httpx.Client", FakeClient)
    advisory = HTTPOSVClient().get_advisory("GHSA-cache")

    assert advisory is not None
    assert advisory.fix_commits == ["https://github.com/example/project/commit/abc123"]
    assert cache_file.with_suffix(".meta").read_text(encoding="utf-8") == "2"


def test_diff_parser_filters_non_code() -> None:
    """Verify unified diff parser filters test files and keeps code files from real patch."""
    diff_text = (FIXTURES_DIR / "diffs" / "urllib3_2d4a3fee.patch").read_text(encoding="utf-8")
    file_diffs = parse_unified_diff(diff_text)

    # test/test_util.py must be filtered out! Only src/urllib3/util/url.py should remain
    assert len(file_diffs) == 1
    assert file_diffs[0].new_path == "src/urllib3/util/url.py"
    # The real patch has 2 hunks in src/urllib3/util/url.py
    assert len(file_diffs[0].hunks) == 2


def test_diff_parser_filters_release_metadata_files() -> None:
    """Release/version metadata changes must not become affected module symbols."""
    diff_text = """diff --git a/src/cryptography/__about__.py b/src/cryptography/__about__.py
index 1111111..2222222 100644
--- a/src/cryptography/__about__.py
+++ b/src/cryptography/__about__.py
@@ -1 +1 @@
-__version__ = "46.0.6"
+__version__ = "46.0.7"
diff --git a/vectors/cryptography_vectors/__about__.py b/vectors/cryptography_vectors/__about__.py
index 1111111..2222222 100644
--- a/vectors/cryptography_vectors/__about__.py
+++ b/vectors/cryptography_vectors/__about__.py
@@ -1 +1 @@
-__version__ = "46.0.6"
+__version__ = "46.0.7"
"""
    assert parse_unified_diff(diff_text) == []


def test_resolver_returns_no_symbols_for_release_only_fix() -> None:
    """A fix containing only release metadata must not invent a module symbol."""
    commit_url = "https://github.com/pyca/cryptography/commit/release"
    diff_text = """diff --git a/src/cryptography/__about__.py b/src/cryptography/__about__.py
index 1111111..2222222 100644
--- a/src/cryptography/__about__.py
+++ b/src/cryptography/__about__.py
@@ -1 +1 @@
-__version__ = "46.0.6"
+__version__ = "46.0.7"
"""
    resolver = AdvisorySymbolResolver(
        vcs_client=MockVCSClient(
            diffs={commit_url: diff_text},
            files={(commit_url, "src/cryptography/__about__.py", True): '__version__ = "46.0.6"\n'},
        )
    )
    advisory = Advisory(
        id="GHSA-version-only",
        package_name="cryptography",
        fix_commits=[commit_url],
    )
    assert resolver.resolve(advisory) == []


def test_resolver_marks_native_fix_changes() -> None:
    commit_url = "https://github.com/example/native/commit/native"
    diff_text = """diff --git a/src/native.c b/src/native.c
index 1111111..2222222 100644
--- a/src/native.c
+++ b/src/native.c
@@ -1 +1 @@
-return 0;
+return 1;
"""
    resolver = AdvisorySymbolResolver(
        vcs_client=MockVCSClient(diffs={commit_url: diff_text})
    )
    advisory = Advisory(
        id="GHSA-native",
        package_name="native-pkg",
        fix_commits=[commit_url],
    )
    resolver.resolve(advisory)
    assert advisory.native_fix_detected is True


def test_real_advisory_urllib3_symbol_extraction() -> None:
    """Verify extracted symbols for urllib3 GHSA-q2q7-5pp4-w6pg (CVE-2021-33503)."""
    commit_url = "https://github.com/urllib3/urllib3/commit/2d4a3fee6de2fa45eb82169361918f759269b4ec"
    diff_text = (FIXTURES_DIR / "diffs" / "urllib3_2d4a3fee.patch").read_text(encoding="utf-8")
    pre_fix_src = (FIXTURES_DIR / "sources" / "urllib3_url_pre.py").read_text(encoding="utf-8")
    osv_data = json.loads((FIXTURES_DIR / "advisories" / "urllib3_GHSA-q2q7-5pp4-w6pg.json").read_text(encoding="utf-8"))

    vcs = MockVCSClient(
        diffs={commit_url: diff_text},
        files={(commit_url, "src/urllib3/util/url.py", True): pre_fix_src},
    )
    resolver = AdvisorySymbolResolver(vcs_client=vcs)
    adv = parse_osv_json(osv_data)

    symbols = resolver.resolve(adv)
    # Real commit changed module-level regexes AND lines within parse_url
    qnames = {s.qualified_name: s for s in symbols}
    assert "urllib3.util.url" in qnames
    assert "urllib3.util.url.parse_url" in qnames

    parse_url_sym = qnames["urllib3.util.url.parse_url"]
    assert parse_url_sym.package == "urllib3"
    assert parse_url_sym.module == "urllib3.util.url"
    assert parse_url_sym.symbol_type == SymbolType.FUNCTION
    assert parse_url_sym.confidence == ConfidenceLevel.HIGH
    assert parse_url_sym.source_of_evidence == SymbolEvidenceSource.FIX_COMMIT_DIFF

    mod_sym = qnames["urllib3.util.url"]
    assert mod_sym.symbol_type == SymbolType.MODULE
    assert mod_sym.confidence == ConfidenceLevel.MEDIUM


def test_real_advisory_jinja2_symbol_extraction() -> None:
    """Verify extracted symbols for jinja2 GHSA-h75v-3vvj-5mfj (CVE-2024-34064)."""
    commit_url = "https://github.com/pallets/jinja/commit/0668239dc6b44ef38e7a6c9f91f312fd4ca581cb"
    diff_text = (FIXTURES_DIR / "diffs" / "jinja2_0668239d.patch").read_text(encoding="utf-8")
    pre_fix_src = (FIXTURES_DIR / "sources" / "jinja2_filters_pre.py").read_text(encoding="utf-8")
    osv_data = json.loads((FIXTURES_DIR / "advisories" / "jinja2_GHSA-h75v-3vvj-5mfj.json").read_text(encoding="utf-8"))

    vcs = MockVCSClient(
        diffs={commit_url: diff_text},
        files={(commit_url, "src/jinja2/filters.py", True): pre_fix_src},
    )
    resolver = AdvisorySymbolResolver(vcs_client=vcs)
    adv = parse_osv_json(osv_data)

    symbols = resolver.resolve(adv)
    qnames = {s.qualified_name: s for s in symbols}
    # CHANGES.rst and tests/test_filters.py were filtered out.
    # src/jinja2/filters.py changes _attr_key_re at module level and do_xmlattr function.
    assert "jinja2.filters" in qnames
    assert "jinja2.filters.do_xmlattr" in qnames

    xmlattr_sym = qnames["jinja2.filters.do_xmlattr"]
    assert xmlattr_sym.package == "jinja2"
    assert xmlattr_sym.module == "jinja2.filters"
    assert xmlattr_sym.symbol_type == SymbolType.FUNCTION
    assert xmlattr_sym.confidence == ConfidenceLevel.HIGH


def test_real_advisory_pillow_symbol_extraction() -> None:
    """Verify extracted symbols for Pillow GHSA-3f63-hfp8-52jq (CVE-2023-50447 ImageMath.eval)."""
    commit_url = "https://github.com/python-pillow/Pillow/commit/45c726fd4daa63236a8f3653530f297dc87b160a"
    diff_text = (FIXTURES_DIR / "diffs" / "pillow_45c726fd.patch").read_text(encoding="utf-8")
    pre_fix_src = (FIXTURES_DIR / "sources" / "pillow_imagemath_pre.py").read_text(encoding="utf-8")
    osv_data = json.loads((FIXTURES_DIR / "advisories" / "pillow_GHSA-3f63-hfp8-52jq.json").read_text(encoding="utf-8"))

    vcs = MockVCSClient(
        diffs={commit_url: diff_text},
        files={(commit_url, "src/PIL/ImageMath.py", True): pre_fix_src},
    )
    resolver = AdvisorySymbolResolver(vcs_client=vcs)
    adv = parse_osv_json(osv_data)

    symbols = resolver.resolve(adv)
    assert len(symbols) == 1
    sym = symbols[0]
    assert sym.package == "pillow"
    assert sym.module == "PIL.ImageMath"
    assert sym.qualified_name == "PIL.ImageMath.eval"
    assert sym.symbol_type == SymbolType.FUNCTION
    assert sym.confidence == ConfidenceLevel.HIGH
    assert sym.source_of_evidence == SymbolEvidenceSource.FIX_COMMIT_DIFF
    assert sym.is_public_api is True


def test_commit_miner_handles_module_level_change() -> None:
    """Module-level code changes outside functions/classes report MODULE at MEDIUM confidence."""
    module_code = '''"""Config module."""
TIMEOUT = 30
VERSION = "1.0.0"
'''
    module_diff = """diff --git a/src/mypkg/config.py b/src/mypkg/config.py
index 1111..2222 100644
--- a/src/mypkg/config.py
+++ b/src/mypkg/config.py
@@ -2,2 +2,2 @@
-TIMEOUT = 30
+TIMEOUT = 10
"""
    file_diffs = parse_unified_diff(module_diff)
    miner = CommitMiner(package_name="mypkg")
    symbols = miner.mine_file_diff(file_diffs[0], module_code)

    assert len(symbols) == 1
    sym = symbols[0]
    assert sym.symbol_type == SymbolType.MODULE
    assert sym.confidence == ConfidenceLevel.MEDIUM
    assert sym.qualified_name == "mypkg.config"


def test_llm_fallback_with_ast_validation() -> None:
    """LLM fallback extracts candidate symbols, but discards any hallucinated symbol not in AST."""
    sources = {
        "src/auth/service.py": '''"""Auth service."""
def verify_token(token):
    return True

class TokenManager:
    def refresh(self):
        pass
'''
    }
    # LLM returns one real symbol and one hallucinated symbol
    mock_llm_response = json.dumps({
        "symbols": [
            {
                "module": "auth.service",
                "qualified_name": "auth.service.verify_token",
                "symbol_type": "function",
                "reason": "Token validation flaw",
            },
            {
                "module": "auth.service",
                "qualified_name": "auth.service.hallucinated_backdoor",
                "symbol_type": "function",
                "reason": "Imaginary function not in source",
            },
        ]
    })

    mock_llm = MockLLMExtractor(responses={"Advisory ID": mock_llm_response})
    extractor = ASTValidatedLLMExtractor(mock_llm)

    adv = Advisory(
        id="GHSA-fake-auth",
        package_name="auth",
        summary="Auth vulnerability with no fix commit",
    )

    symbols = extractor.extract_symbols(adv, sources)
    # The hallucinated symbol MUST be discarded!
    assert len(symbols) == 1
    assert symbols[0].qualified_name == "auth.service.verify_token"
    assert symbols[0].source_of_evidence == SymbolEvidenceSource.LLM_FALLBACK
    assert symbols[0].confidence == ConfidenceLevel.LOW
