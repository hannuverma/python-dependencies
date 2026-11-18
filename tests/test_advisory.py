"""Unit tests for Stage 2: Advisory ingestion, diff parsing, and symbol extraction."""

import json

from pyreach.advisory.commit_miner import CommitMiner
from pyreach.advisory.diff_parser import parse_unified_diff
from pyreach.advisory.llm_fallback import ASTValidatedLLMExtractor, MockLLMExtractor
from pyreach.advisory.osv_client import parse_osv_json
from pyreach.advisory.resolver import AdvisorySymbolResolver, MockVCSClient
from pyreach.models import (
    Advisory,
    ConfidenceLevel,
    SymbolEvidenceSource,
    SymbolType,
)

# ---------------------------------------------------------------------------
# Real Advisory Fixture 1: GHSA-r64q-w8jr-g9qp (urllib3: parse_url ReDoS)
# ---------------------------------------------------------------------------
URLLIB3_OSV_JSON = {
    "id": "GHSA-r64q-w8jr-g9qp",
    "aliases": ["CVE-2021-33503"],
    "summary": "Catastrophic backtracking in URL parsing regex",
    "details": "urllib3 before 1.26.5 contains a regex ReDoS in parse_url.",
    "affected": [
        {
            "package": {"name": "urllib3", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "1.26.5"}],
                }
            ],
        }
    ],
    "references": [
        {"type": "FIX", "url": "https://github.com/urllib3/urllib3/commit/2d4a89f64b433356e350620a539026abb4f0f15e"}
    ],
}

URLLIB3_PRE_FIX_URL_PY = '''"""URL helper functions for urllib3."""
import re

SUBAUTHORITY_PAT = r"^([^@]+@)?"

def parse_url(url):
    """Parse a given url into its components."""
    if not url:
        return None
    # Vulnerable catastrophic regex
    match = re.match(SUBAUTHORITY_PAT, url)
    return match

def get_host(url):
    """Extract host."""
    return "example.com"
'''

URLLIB3_DIFF = """diff --git a/src/urllib3/util/url.py b/src/urllib3/util/url.py
index a1b2c3d..e4f5g6h 100644
--- a/src/urllib3/util/url.py
+++ b/src/urllib3/util/url.py
@@ -10,3 +10,3 @@ def parse_url(url):
     # Vulnerable catastrophic regex
-    match = re.match(SUBAUTHORITY_PAT, url)
+    match = re.match(r"^safe", url)
     return match
diff --git a/test/test_url.py b/test/test_url.py
index 1111..2222 100644
--- a/test/test_url.py
+++ b/test/test_url.py
@@ -1,2 +1,3 @@
 def test_parse():
+    pass
"""

# ---------------------------------------------------------------------------
# Real Advisory Fixture 2: GHSA-m58g-v84x-8972 (jinja2: is_internal_attribute)
# ---------------------------------------------------------------------------
JINJA2_OSV_JSON = {
    "id": "GHSA-m58g-v84x-8972",
    "aliases": ["CVE-2020-28493"],
    "summary": "Sandbox breakout via string format internal attributes",
    "affected": [
        {
            "package": {"name": "jinja2", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.11.3"}],
                }
            ],
        }
    ],
    "references": [
        {"type": "FIX", "url": "https://github.com/pallets/jinja/commit/a6c278972e3914a27a5796068eb1a1be2eec4c39"}
    ],
}

JINJA2_PRE_FIX_SANDBOX_PY = '''"""Jinja sandbox implementation."""

class SandboxedEnvironment:
    def __init__(self):
        pass

    def is_safe_attribute(self, obj, attr, value):
        return True

def is_internal_attribute(obj, attr):
    """Check if attribute is private."""
    if attr.startswith("_"):
        return True
    return False
'''

JINJA2_DIFF = """diff --git a/src/jinja2/sandbox.py b/src/jinja2/sandbox.py
index 1234..5678 100644
--- a/src/jinja2/sandbox.py
+++ b/src/jinja2/sandbox.py
@@ -12,2 +12,4 @@ def is_internal_attribute(obj, attr):
     if attr.startswith("_"):
+        return True
+    if attr == "format":
         return True
"""

# ---------------------------------------------------------------------------
# Real Advisory Fixture 3: GHSA-wqvq-5pcm-5x3q (pillow: Path.py _path)
# ---------------------------------------------------------------------------
PILLOW_OSV_JSON = {
    "id": "GHSA-wqvq-5pcm-5x3q",
    "aliases": ["CVE-2022-24303"],
    "summary": "Pillow temporary file path vulnerability",
    "affected": [
        {
            "package": {"name": "pillow", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "9.0.1"}],
                }
            ],
        }
    ],
    "references": [
        {"type": "FIX", "url": "https://github.com/python-pillow/Pillow/commit/40775d7105a5b512534a6fb70d29792ee5a2a901"}
    ],
}

PILLOW_PRE_FIX_PATH_PY = '''"""Pillow Path helper."""

def _path(path):
    """Normalize path."""
    import tempfile
    return tempfile.mktemp()
'''

PILLOW_DIFF = """diff --git a/src/PIL/Path.py b/src/PIL/Path.py
index aaaa..bbbb 100644
--- a/src/PIL/Path.py
+++ b/src/PIL/Path.py
@@ -4,2 +4,2 @@ def _path(path):
-    import tempfile
-    return tempfile.mktemp()
+    import tempfile
+    return tempfile.NamedTemporaryFile().name
"""


def test_osv_json_ingestion() -> None:
    adv = parse_osv_json(URLLIB3_OSV_JSON)
    assert adv.id == "GHSA-r64q-w8jr-g9qp"
    assert "CVE-2021-33503" in adv.aliases
    assert adv.package_name == "urllib3"
    assert "1.26.5" in adv.fixed_versions
    assert len(adv.fix_commits) == 1


def test_diff_parser_filters_non_code() -> None:
    file_diffs = parse_unified_diff(URLLIB3_DIFF)
    # test/test_url.py must be filtered out! Only src/urllib3/util/url.py should remain
    assert len(file_diffs) == 1
    assert file_diffs[0].old_path == "src/urllib3/util/url.py"
    assert len(file_diffs[0].hunks) == 1
    assert 11 in file_diffs[0].hunks[0].changed_pre_lines


def test_real_advisory_urllib3_symbol_extraction() -> None:
    """Verify extracted function for urllib3 GHSA-r64q-w8jr-g9qp is parse_url."""
    commit_url = "https://github.com/urllib3/urllib3/commit/2d4a89f64b433356e350620a539026abb4f0f15e"
    vcs = MockVCSClient(
        diffs={commit_url: URLLIB3_DIFF},
        files={(commit_url, "src/urllib3/util/url.py", True): URLLIB3_PRE_FIX_URL_PY},
    )
    resolver = AdvisorySymbolResolver(vcs_client=vcs)
    adv = parse_osv_json(URLLIB3_OSV_JSON)

    symbols = resolver.resolve(adv)
    assert len(symbols) == 1
    sym = symbols[0]
    assert sym.package == "urllib3"
    assert sym.module == "urllib3.util.url"
    assert sym.qualified_name == "urllib3.util.url.parse_url"
    assert sym.symbol_type == SymbolType.FUNCTION
    assert sym.confidence == ConfidenceLevel.HIGH
    assert sym.source_of_evidence == SymbolEvidenceSource.FIX_COMMIT_DIFF
    assert sym.file_path == "src/urllib3/util/url.py"
    assert sym.diff_hunk is not None
    assert "re.match(SUBAUTHORITY_PAT, url)" in sym.diff_hunk


def test_real_advisory_jinja2_symbol_extraction() -> None:
    """Verify extracted function for jinja2 GHSA-m58g-v84x-8972 is is_internal_attribute."""
    commit_url = "https://github.com/pallets/jinja/commit/a6c278972e3914a27a5796068eb1a1be2eec4c39"
    vcs = MockVCSClient(
        diffs={commit_url: JINJA2_DIFF},
        files={(commit_url, "src/jinja2/sandbox.py", True): JINJA2_PRE_FIX_SANDBOX_PY},
    )
    resolver = AdvisorySymbolResolver(vcs_client=vcs)
    adv = parse_osv_json(JINJA2_OSV_JSON)

    symbols = resolver.resolve(adv)
    assert len(symbols) == 1
    sym = symbols[0]
    assert sym.package == "jinja2"
    assert sym.module == "jinja2.sandbox"
    assert sym.qualified_name == "jinja2.sandbox.is_internal_attribute"
    assert sym.symbol_type == SymbolType.FUNCTION
    assert sym.confidence == ConfidenceLevel.HIGH


def test_real_advisory_pillow_symbol_extraction() -> None:
    """Verify extracted function for pillow GHSA-wqvq-5pcm-5x3q is _path."""
    commit_url = "https://github.com/python-pillow/Pillow/commit/40775d7105a5b512534a6fb70d29792ee5a2a901"
    vcs = MockVCSClient(
        diffs={commit_url: PILLOW_DIFF},
        files={(commit_url, "src/PIL/Path.py", True): PILLOW_PRE_FIX_PATH_PY},
    )
    resolver = AdvisorySymbolResolver(vcs_client=vcs)
    adv = parse_osv_json(PILLOW_OSV_JSON)

    symbols = resolver.resolve(adv)
    assert len(symbols) == 1
    sym = symbols[0]
    assert sym.package == "pillow"
    assert sym.qualified_name == "pillow.PIL.Path._path"
    assert sym.is_public_api is False  # Starts with underscore


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
