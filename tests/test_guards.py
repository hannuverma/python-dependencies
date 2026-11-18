"""Comprehensive unit tests for claimed guards, soundness invariants, and C-extension handling."""

from pyreach.analysis.callgraph_builder import CallGraphBuilder
from pyreach.analysis.dynamic import DynamicSite
from pyreach.analysis.entry_points import EntryPointDetector
from pyreach.engine.verdict import VerdictEngine
from pyreach.models import (
    Advisory,
    AffectedSymbol,
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
    ConfidenceLevel,
    EntryPoint,
    EntryPointType,
    SymbolEvidenceSource,
    SymbolType,
    UncertaintyCategory,
    Verdict,
)


def test_guard_import_time_module_execution() -> None:
    """Row 2: Silent import execution at module level triggers REACHABLE via <module_init>."""
    proj_src = {
        "main.py": """import vulnerable_pkg.config

def run():
    pass

if __name__ == '__main__':
    run()
"""
    }
    dep_src = {
        "vulnerable-pkg": {
            "vulnerable_pkg/config.py": """# Module level code executed on import
VULN_REGEX = "bad_regex"
"""
        }
    }
    builder = CallGraphBuilder()
    cg = builder.build_graph("app", proj_src, dep_src)
    detector = EntryPointDetector()
    detector.detect_and_register(cg, proj_src)

    adv = Advisory(
        id="GHSA-import-exec",
        package_name="vulnerable-pkg",
        summary="Module level vulnerability",
        extracted_symbols=[
            AffectedSymbol(
                package="vulnerable-pkg",
                module="vulnerable_pkg.config",
                qualified_name="vulnerable_pkg.config",
                symbol_type=SymbolType.MODULE,
                confidence=ConfidenceLevel.MEDIUM,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
            )
        ],
    )
    engine = VerdictEngine(cg)
    finding = engine.evaluate_advisory(adv, installed_version="1.0.0", required_packages=["vulnerable-pkg"])

    assert finding.verdict == Verdict.REACHABLE
    assert finding.call_path is not None
    assert any("<module_init>" in h.symbol or "vulnerable_pkg.config" in h.symbol for h in finding.call_path)


def test_guard_zero_hop_path() -> None:
    """Zero-hop path: reaching an entry point that is itself the target returns a 1-hop path."""
    cg = CallGraph()
    node = CallGraphNode(
        node_id="app.main:vulnerable_handler",
        package="app",
        module="app.main",
        name="vulnerable_handler",
        qualified_name="app.main.vulnerable_handler",
        file_path="main.py",
        line_number=10,
        is_entry_point=True,
    )
    cg.add_node(node)
    cg.add_entry_point(
        EntryPoint(
            symbol_id="app.main:vulnerable_handler",
            entry_type=EntryPointType.FASTAPI_ROUTE,
            file_path="main.py",
            line_number=10,
            confidence=ConfidenceLevel.HIGH,
        )
    )
    path = cg.find_shortest_call_path_from_any_entry("app", "app.main", "app.main.vulnerable_handler")
    assert path is not None
    assert len(path) == 1
    assert path[0].symbol == "app.main.vulnerable_handler"


def test_guard_multi_source_bfs() -> None:
    """Multi-source BFS finds path starting strictly from the entry point that reaches target."""
    cg = CallGraph()
    # 3 entry points: route_a, route_b, cli_cmd
    ep1 = CallGraphNode(node_id="app:route_a", package="app", module="app", name="route_a", qualified_name="app.route_a", is_entry_point=True)
    ep2 = CallGraphNode(node_id="app:route_b", package="app", module="app", name="route_b", qualified_name="app.route_b", is_entry_point=True)
    ep3 = CallGraphNode(node_id="app:cli_cmd", package="app", module="app", name="cli_cmd", qualified_name="app.cli_cmd", is_entry_point=True)
    target = CallGraphNode(node_id="dep:vuln", package="dep", module="dep", name="vuln", qualified_name="dep.vuln", is_dependency=True)

    for n in (ep1, ep2, ep3, target):
        cg.add_node(n)
    for ep in (ep1, ep2, ep3):
        cg.add_entry_point(
            EntryPoint(
                symbol_id=ep.node_id,
                entry_type=EntryPointType.CLI_COMMAND,
                file_path="main.py",
                line_number=1,
                confidence=ConfidenceLevel.HIGH,
            )
        )

    # Only cli_cmd calls target
    cg.add_edge(CallGraphEdge(caller_id="app:cli_cmd", callee_id="dep:vuln"))

    path = cg.find_shortest_call_path_from_any_entry("dep", "dep", "dep.vuln")
    assert path is not None
    assert len(path) == 1
    assert path[0].symbol == "dep.vuln"
    # Starting caller was cli_cmd
    assert cg.edges[0].caller_id == "app:cli_cmd"


def test_guard_row1_unrecognized_framework_uncertain() -> None:
    """Audit Row 1: Unrecognized web framework triggers FrameworkDiscoveryStatus.UNRECOGNIZED_FRAMEWORK and UNCERTAIN."""
    proj_src = {
        "server.py": """import falcon

app = falcon.App()
def on_get(req, resp):
    pass
"""
    }
    builder = CallGraphBuilder()
    cg = builder.build_graph("app", proj_src, {"safe-lib": {"safe_lib/work.py": "def do_work(): pass"}})
    detector = EntryPointDetector()
    completed = detector.detect_and_register(cg, proj_src)

    assert completed is False
    assert not cg.has_confident_entry_points()

    adv = Advisory(
        id="GHSA-safe-1",
        package_name="safe-lib",
        summary="Safe lib vuln",
        extracted_symbols=[
            AffectedSymbol(
                package="safe-lib",
                module="safe_lib.work",
                qualified_name="safe_lib.work.do_work",
                symbol_type=SymbolType.FUNCTION,
                confidence=ConfidenceLevel.HIGH,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
            )
        ],
    )
    engine = VerdictEngine(cg)
    finding = engine.evaluate_advisory(adv, installed_version="1.0.0", required_packages=["safe-lib"])

    assert finding.verdict == Verdict.UNCERTAIN
    assert any(r.category == UncertaintyCategory.UNRESOLVED_ENTRY_POINTS for r in finding.uncertainty_reasons)


def test_guard_row3_polymorphic_method_overrides_cha() -> None:
    """Audit Row 3: CHA resolves polymorphic method call to subclass override (REACHABLE)."""
    proj_src = {
        "main.py": """from framework.base import BaseHandler
from framework.custom import CustomHandler

def run():
    handler = CustomHandler()
    handler.dispatch()

if __name__ == '__main__':
    run()
"""
    }
    dep_src = {
        "framework": {
            "framework/base.py": """class BaseHandler:
    def dispatch(self):
        pass
""",
            "framework/custom.py": """from framework.base import BaseHandler

class CustomHandler(BaseHandler):
    def dispatch(self):
        self.vulnerable_hook()

    def vulnerable_hook(self):
        pass
""",
        }
    }
    builder = CallGraphBuilder()
    cg = builder.build_graph("app", proj_src, dep_src)
    detector = EntryPointDetector()
    detector.detect_and_register(cg, proj_src)

    adv = Advisory(
        id="GHSA-poly-1",
        package_name="framework",
        summary="Hook vuln",
        extracted_symbols=[
            AffectedSymbol(
                package="framework",
                module="framework.custom",
                qualified_name="framework.custom.CustomHandler.vulnerable_hook",
                symbol_type=SymbolType.METHOD,
                confidence=ConfidenceLevel.HIGH,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
            )
        ],
    )
    engine = VerdictEngine(cg)
    finding = engine.evaluate_advisory(adv, installed_version="1.0.0", required_packages=["framework"])

    assert finding.verdict == Verdict.REACHABLE
    assert finding.call_path is not None


def test_guard_row4_llm_fallback_forbids_not_reachable() -> None:
    """Audit Row 4: Symbols derived from LLM fallback forbid NOT_REACHABLE (caps at UNCERTAIN)."""
    cg = CallGraph()
    cg.entry_points_complete = True
    ep = CallGraphNode(node_id="app:main", package="app", module="app", name="main", qualified_name="app.main", is_entry_point=True)
    cg.add_node(ep)
    cg.add_entry_point(
        EntryPoint(
            symbol_id="app:main",
            entry_type=EntryPointType.MAIN,
            file_path="main.py",
            line_number=1,
            confidence=ConfidenceLevel.HIGH,
        )
    )
    cg.record_package_stats("pkg", files_total=1, files_parsed=1, files_failed=0)
    cg.add_node(
        CallGraphNode(
            node_id="pkg.mod:some_fn",
            package="pkg",
            module="pkg.mod",
            name="some_fn",
            qualified_name="pkg.mod.some_fn",
            is_dependency=True,
        )
    )

    # Symbol from LLM fallback
    adv = Advisory(
        id="GHSA-llm-1",
        package_name="pkg",
        summary="LLM inferred vuln",
        extracted_symbols=[
            AffectedSymbol(
                package="pkg",
                module="pkg.mod",
                qualified_name="pkg.mod.some_fn",
                symbol_type=SymbolType.FUNCTION,
                source_of_evidence=SymbolEvidenceSource.LLM_FALLBACK,
                confidence=ConfidenceLevel.LOW,
            )
        ],
    )
    engine = VerdictEngine(cg)
    finding = engine.evaluate_advisory(adv, installed_version="1.0.0", required_packages=["pkg"])

    # Must NEVER be NOT_REACHABLE!
    assert finding.verdict == Verdict.UNCERTAIN
    assert any(r.category == UncertaintyCategory.IMPRECISE_SYMBOL for r in finding.uncertainty_reasons)


def test_guard_row5_missing_transitive_lockfile_dep_uncertain() -> None:
    """Audit Row 5: Missing transitive dependency in lockfile fails safe to UNCERTAIN."""
    cg = CallGraph()
    cg.entry_points_complete = True
    ep = CallGraphNode(node_id="app:main", package="app", module="app", name="main", qualified_name="app.main", is_entry_point=True)
    cg.add_node(ep)
    cg.add_entry_point(
        EntryPoint(
            symbol_id="app:main",
            entry_type=EntryPointType.MAIN,
            file_path="main.py",
            line_number=1,
            confidence=ConfidenceLevel.HIGH,
        )
    )
    # direct-dep parsed cleanly
    cg.record_package_stats("direct-dep", files_total=2, files_parsed=2, files_failed=0)
    cg.add_node(CallGraphNode(node_id="direct_dep:foo", package="direct-dep", module="direct_dep", name="foo", qualified_name="direct_dep.foo", is_dependency=True))

    adv = Advisory(
        id="GHSA-trans-1",
        package_name="direct-dep",
        summary="Direct vuln",
        extracted_symbols=[
            AffectedSymbol(
                package="direct-dep",
                module="direct_dep",
                qualified_name="direct_dep.foo",
                symbol_type=SymbolType.FUNCTION,
                confidence=ConfidenceLevel.HIGH,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
            )
        ],
    )
    engine = VerdictEngine(cg)
    # Manifest declares both direct-dep and transitive-dep, but transitive-dep is absent from call graph!
    finding = engine.evaluate_advisory(
        adv,
        installed_version="1.0.0",
        required_packages=["direct-dep", "transitive-dep"],
    )

    assert finding.verdict == Verdict.UNCERTAIN
    assert any(r.category == UncertaintyCategory.MISSING_DEPENDENCY_SOURCE for r in finding.uncertainty_reasons)


def test_guard_row6_subtle_reflection_condition_c_uncertain() -> None:
    """Audit Row 6: Non-constant getattr touching target package triggers UNCERTAIN."""
    cg = CallGraph()
    cg.entry_points_complete = True
    ep = CallGraphNode(node_id="app:main", package="app", module="app", name="main", qualified_name="app.main", is_entry_point=True)
    cg.add_node(ep)
    cg.add_entry_point(
        EntryPoint(
            symbol_id="app:main",
            entry_type=EntryPointType.MAIN,
            file_path="main.py",
            line_number=1,
            confidence=ConfidenceLevel.HIGH,
        )
    )
    cg.record_package_stats("target-pkg", files_total=1, files_parsed=1, files_failed=0)
    cg.add_node(CallGraphNode(node_id="target_pkg:eval", package="target-pkg", module="target_pkg", name="eval", qualified_name="target_pkg.eval", is_dependency=True))

    # Dynamic site touching target-pkg
    site = DynamicSite(
        file_path="main.py",
        line_number=20,
        category=UncertaintyCategory.GETATTR_NON_CONSTANT,
        enclosing_module="main",
        receiver_expr="target_pkg",
        attribute_expr="os.environ.get('OP', 'eval')",
        is_constant=False,
        imported_packages_in_scope=("target-pkg",),
    )
    adv = Advisory(
        id="GHSA-dynamic-1",
        package_name="target-pkg",
        summary="Target vuln",
        extracted_symbols=[
            AffectedSymbol(
                package="target-pkg",
                module="target_pkg",
                qualified_name="target_pkg.eval",
                symbol_type=SymbolType.FUNCTION,
                confidence=ConfidenceLevel.HIGH,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
            )
        ],
    )
    engine = VerdictEngine(cg, dynamic_sites=[site])
    finding = engine.evaluate_advisory(adv, installed_version="1.0.0", required_packages=["target-pkg"])

    assert finding.verdict == Verdict.UNCERTAIN
    assert any(r.category == UncertaintyCategory.GETATTR_NON_CONSTANT for r in finding.uncertainty_reasons)


def test_guard_decoy_symbol_in_different_package_not_reachable() -> None:
    """Project calls decoy_pkg.eval(). Target is target_pkg.eval(). Call graph does not confuse them -> NOT_REACHABLE."""
    proj_src = {
        "main.py": """import decoy_pkg

def run():
    decoy_pkg.eval("safe")

if __name__ == '__main__':
    run()
"""
    }
    dep_src = {
        "decoy-pkg": {
            "decoy_pkg/__init__.py": """def eval(expr):
    return expr
"""
        },
        "target-pkg": {
            "target_pkg/__init__.py": """def eval(expr):
    import os
    os.system(expr)
"""
        },
    }
    builder = CallGraphBuilder()
    cg = builder.build_graph("app", proj_src, dep_src)
    detector = EntryPointDetector()
    detector.detect_and_register(cg, proj_src)

    adv = Advisory(
        id="GHSA-target-eval",
        package_name="target-pkg",
        summary="Target eval flaw",
        extracted_symbols=[
            AffectedSymbol(
                package="target-pkg",
                module="target_pkg",
                qualified_name="target_pkg.eval",
                symbol_type=SymbolType.FUNCTION,
                confidence=ConfidenceLevel.HIGH,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
            )
        ],
    )
    engine = VerdictEngine(cg)
    finding = engine.evaluate_advisory(adv, installed_version="1.0.0", required_packages=["decoy-pkg", "target-pkg"])

    # Because target_pkg.eval was never called (only decoy_pkg.eval), verdict must be NOT_REACHABLE!
    assert finding.verdict == Verdict.NOT_REACHABLE
    assert finding.confidence == ConfidenceLevel.HIGH


def test_guard_c_extension_native_symbol_uncertain() -> None:
    """Vulnerable symbol lives in compiled native module (.so/.pyd) -> UNCERTAIN (c_extension)."""
    cg = CallGraph()
    cg.entry_points_complete = True
    ep = CallGraphNode(node_id="app:main", package="app", module="app", name="main", qualified_name="app.main", is_entry_point=True)
    cg.add_node(ep)
    cg.add_entry_point(
        EntryPoint(
            symbol_id="app:main",
            entry_type=EntryPointType.MAIN,
            file_path="main.py",
            line_number=1,
            confidence=ConfidenceLevel.HIGH,
        )
    )
    cg.record_package_stats("pillow", files_total=30, files_parsed=30, files_failed=0)
    cg.add_node(
        CallGraphNode(
            node_id="PIL.Image:open",
            package="pillow",
            module="PIL.Image",
            name="open",
            qualified_name="PIL.Image.open",
            is_dependency=True,
        )
    )

    # Register native module in Pillow
    cg.native_modules.add("PIL._imaging")

    adv = Advisory(
        id="GHSA-native-cve",
        package_name="pillow",
        summary="Native heap overflow",
        extracted_symbols=[
            AffectedSymbol(
                package="pillow",
                module="PIL._imaging",
                qualified_name="PIL._imaging.font_getsize",
                symbol_type=SymbolType.FUNCTION,
                confidence=ConfidenceLevel.HIGH,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
            )
        ],
    )
    engine = VerdictEngine(cg)
    finding = engine.evaluate_advisory(adv, installed_version="10.1.0", required_packages=["pillow"])

    assert finding.verdict == Verdict.UNCERTAIN
    assert any("native extension" in r.details.lower() for r in finding.uncertainty_reasons)


def test_guard_c_extension_pure_python_analyzable() -> None:
    """Package ships native extensions (PIL._imaging), but vulnerable symbol is pure Python (PIL.ImageMath.eval). Analyzable!"""
    proj_safe = {
        "main.py": """import PIL.Image

def run():
    pass

if __name__ == '__main__':
    run()
"""
    }
    dep_src = {
        "pillow": {
            "PIL/Image.py": "def open(fp): pass",
            "PIL/ImageMath.py": "def eval(expr): pass",
        }
    }
    builder = CallGraphBuilder()
    cg = builder.build_graph("app", proj_safe, dep_src)
    detector = EntryPointDetector()
    detector.detect_and_register(cg, proj_safe)

    # Package has native module _imaging
    cg.native_modules.add("PIL._imaging")

    # Target symbol is in pure Python PIL.ImageMath
    adv = Advisory(
        id="GHSA-pure-py-in-native-pkg",
        package_name="pillow",
        summary="ImageMath eval flaw",
        extracted_symbols=[
            AffectedSymbol(
                package="pillow",
                module="PIL.ImageMath",
                qualified_name="PIL.ImageMath.eval",
                symbol_type=SymbolType.FUNCTION,
                confidence=ConfidenceLevel.HIGH,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
            )
        ],
    )
    engine = VerdictEngine(cg)
    finding = engine.evaluate_advisory(adv, installed_version="10.1.0", required_packages=["pillow"])

    # Not called, pure Python symbol in mixed package -> provably NOT_REACHABLE!
    assert finding.verdict == Verdict.NOT_REACHABLE
    assert finding.confidence == ConfidenceLevel.HIGH
