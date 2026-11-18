"""Unit tests for Stage 4: Call graph construction, entry-point detection, and reachability."""

from pyreach.analysis.callgraph_builder import CallGraphBuilder
from pyreach.analysis.entry_points import EntryPointDetector
from pyreach.analysis.reachability import ReachabilityEngine
from pyreach.models import (
    AffectedSymbol,
    AnalysisMode,
    ConfidenceLevel,
    SymbolEvidenceSource,
    SymbolType,
)


def test_direct_call_reachability() -> None:
    """Project directly imports and calls vulnerable function."""
    project_sources = {
        "app/main.py": """from vuln_lib import vulnerable_func

def run():
    vulnerable_func()

if __name__ == '__main__':
    run()
"""
    }
    dep_sources = {
        "vuln-lib": {
            "vuln_lib/__init__.py": """def vulnerable_func():
    return 'exploited'
"""
        }
    }

    builder = CallGraphBuilder()
    cg = builder.build_graph("my-app", project_sources, dep_sources)

    detector = EntryPointDetector(mode=AnalysisMode.APP)
    assert detector.detect_and_register(cg, project_sources) is True

    sym = AffectedSymbol(
        package="vuln-lib",
        module="vuln_lib",
        qualified_name="vuln_lib.vulnerable_func",
        symbol_type=SymbolType.FUNCTION,
        source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
        confidence=ConfidenceLevel.HIGH,
    )

    engine = ReachabilityEngine(cg)
    path, conf = engine.find_reachability_evidence(sym)
    assert path is not None
    assert len(path) >= 1
    assert any(h.symbol == "vuln_lib.vulnerable_func" for h in path)
    assert conf == ConfidenceLevel.HIGH


def test_transitive_call_reachability() -> None:
    """Project -> intermediate library (requests-like) -> vulnerable dependency (urllib3-like)."""
    project_sources = {
        "app/worker.py": """import requests_like

def process_job():
    requests_like.get('https://example.com')

if __name__ == '__main__':
    process_job()
"""
    }
    dep_sources = {
        "requests-like": {
            "requests_like/__init__.py": """import urllib3_like

def get(url):
    urllib3_like.parse_url(url)
"""
        },
        "urllib3-like": {
            "urllib3_like/__init__.py": """def parse_url(url):
    return url
"""
        },
    }

    builder = CallGraphBuilder()
    cg = builder.build_graph("my-app", project_sources, dep_sources)

    detector = EntryPointDetector(mode=AnalysisMode.APP)
    detector.detect_and_register(cg, project_sources)

    sym = AffectedSymbol(
        package="urllib3-like",
        module="urllib3_like",
        qualified_name="urllib3_like.parse_url",
        symbol_type=SymbolType.FUNCTION,
        source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
        confidence=ConfidenceLevel.HIGH,
    )

    engine = ReachabilityEngine(cg)
    path, conf = engine.find_reachability_evidence(sym)
    assert path is not None
    assert len(path) == 3
    assert path[0].symbol == "my_app.app.worker.process_job"
    assert path[1].symbol == "requests_like.get"
    assert path[2].symbol == "urllib3_like.parse_url"
    assert conf == ConfidenceLevel.HIGH


def test_aliased_import_reachability() -> None:
    """Project calls vulnerable function through an imported alias."""
    project_sources = {
        "app/runner.py": """from secure_pkg.core import dangerous_sink as my_sink

def execute():
    my_sink()

if __name__ == '__main__':
    execute()
"""
    }
    dep_sources = {
        "secure-pkg": {
            "secure_pkg/core.py": """def dangerous_sink():
    pass
"""
        }
    }

    builder = CallGraphBuilder()
    cg = builder.build_graph("my-app", project_sources, dep_sources)

    detector = EntryPointDetector(mode=AnalysisMode.APP)
    detector.detect_and_register(cg, project_sources)

    sym = AffectedSymbol(
        package="secure-pkg",
        module="secure_pkg.core",
        qualified_name="secure_pkg.core.dangerous_sink",
        symbol_type=SymbolType.FUNCTION,
        source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
        confidence=ConfidenceLevel.HIGH,
    )

    engine = ReachabilityEngine(cg)
    path, _ = engine.find_reachability_evidence(sym)
    assert path is not None
    assert any(h.symbol == "secure_pkg.core.dangerous_sink" for h in path)


def test_subclass_override_and_class_hierarchy_analysis() -> None:
    """Over-approximation via Class Hierarchy Analysis checks all candidate methods."""
    project_sources = {
        "app/handlers.py": """from framework.base import BaseHandler

class CustomHandler(BaseHandler):
    def handle(self):
        self.dispatch()

def run_handler(h):
    h.handle()

if __name__ == '__main__':
    run_handler(CustomHandler())
"""
    }
    dep_sources = {
        "framework": {
            "framework/base.py": """class BaseHandler:
    def dispatch(self):
        pass
"""
        }
    }

    builder = CallGraphBuilder()
    cg = builder.build_graph("my-app", project_sources, dep_sources)
    detector = EntryPointDetector(mode=AnalysisMode.APP)
    detector.detect_and_register(cg, project_sources)

    sym = AffectedSymbol(
        package="framework",
        module="framework.base",
        qualified_name="framework.base.BaseHandler.dispatch",
        symbol_type=SymbolType.METHOD,
        source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
        confidence=ConfidenceLevel.HIGH,
    )

    engine = ReachabilityEngine(cg)
    path, _ = engine.find_reachability_evidence(sym)
    assert path is not None
    assert any(h.symbol == "framework.base.BaseHandler.dispatch" for h in path)


def test_imported_but_not_called_returns_none() -> None:
    """Package is imported but the vulnerable function is never invoked."""
    project_sources = {
        "app/service.py": """import crypto_lib

def safe_math():
    return 2 + 2

if __name__ == '__main__':
    safe_math()
"""
    }
    dep_sources = {
        "crypto-lib": {
            "crypto_lib/__init__.py": """def broken_cipher():
    pass
"""
        }
    }

    builder = CallGraphBuilder()
    cg = builder.build_graph("my-app", project_sources, dep_sources)
    detector = EntryPointDetector(mode=AnalysisMode.APP)
    detector.detect_and_register(cg, project_sources)

    sym = AffectedSymbol(
        package="crypto-lib",
        module="crypto_lib",
        qualified_name="crypto_lib.broken_cipher",
        symbol_type=SymbolType.FUNCTION,
        source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
        confidence=ConfidenceLevel.HIGH,
    )

    engine = ReachabilityEngine(cg)
    path, _ = engine.find_reachability_evidence(sym)
    assert path is None  # NOT reachable directly


def test_private_vulnerable_symbol_public_api_expansion() -> None:
    """Private function _unsafe_helper is called by public function send(); reaching send() reaches _unsafe_helper."""
    project_sources = {
        "app/client.py": """import mailer

def notify_user():
    mailer.send_email('hello')

if __name__ == '__main__':
    notify_user()
"""
    }
    dep_sources = {
        "mailer": {
            "mailer/__init__.py": """def send_email(body):
    _unsafe_helper(body)

def _unsafe_helper(body):
    # Vulnerable private helper
    pass
"""
        }
    }

    builder = CallGraphBuilder()
    cg = builder.build_graph("my-app", project_sources, dep_sources)
    detector = EntryPointDetector(mode=AnalysisMode.APP)
    detector.detect_and_register(cg, project_sources)

    private_sym = AffectedSymbol(
        package="mailer",
        module="mailer",
        qualified_name="mailer._unsafe_helper",
        symbol_type=SymbolType.FUNCTION,
        source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
        confidence=ConfidenceLevel.HIGH,
        is_public_api=False,
    )

    # Expand private symbol with public callers
    expanded_syms = builder.expand_private_vulnerable_symbols(cg, [private_sym])
    assert len(expanded_syms) == 1
    assert "mailer.send_email" in expanded_syms[0].exposed_by_public_callers

    engine = ReachabilityEngine(cg)
    path, conf = engine.find_reachability_evidence(expanded_syms[0])
    assert path is not None
    assert any(h.symbol == "mailer.send_email" for h in path)
    assert any(h.symbol == "mailer._unsafe_helper" for h in path)
    assert conf in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM)


def test_framework_entry_points_and_unrecognized_framework() -> None:
    """FastAPI routes registered as HIGH confidence; unrecognized framework marks discovery incomplete."""
    # 1. FastAPI app
    fastapi_sources = {
        "app/api.py": """from fastapi import FastAPI
app = FastAPI()

@app.get('/users')
def list_users():
    return []
"""
    }
    cg1 = CallGraphBuilder().build_graph("api-app", fastapi_sources, {})
    detector1 = EntryPointDetector(mode=AnalysisMode.APP)
    complete1 = detector1.detect_and_register(cg1, fastapi_sources)
    assert complete1 is True
    assert cg1.entry_points_complete is True
    assert len(cg1.entry_points) == 1

    # 2. App with unrecognized web framework (e.g. tornado)
    tornado_sources = {
        "app/server.py": """import tornado.web

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write('hello')
"""
    }
    cg2 = CallGraphBuilder().build_graph("tornado-app", tornado_sources, {})
    detector2 = EntryPointDetector(mode=AnalysisMode.APP)
    complete2 = detector2.detect_and_register(cg2, tornado_sources)
    assert complete2 is False  # Must be incomplete because tornado is unrecognized
    assert cg2.entry_points_complete is False
    assert cg2.has_confident_entry_points() is False
