"""Unit tests for Stage 6: Verdict engine, OpenVEX generation, and Typer CLI."""

import json
from pathlib import Path

from typer.testing import CliRunner

from pyreach.analysis.callgraph_builder import CallGraphBuilder
from pyreach.analysis.dynamic import DynamicFeatureClassifier
from pyreach.analysis.entry_points import EntryPointDetector
from pyreach.analysis.imports import extract_module_imports
from pyreach.cli import app
from pyreach.engine.verdict import VerdictEngine
from pyreach.engine.vex import generate_openvex_for_findings
from pyreach.models import (
    Advisory,
    AffectedSymbol,
    ConfidenceLevel,
    Finding,
    SymbolEvidenceSource,
    SymbolType,
    UncertaintyCategory,
    Verdict,
)

runner = CliRunner()


def test_empty_affected_symbols_have_dedicated_uncertainty_category() -> None:
    """No affected symbols must never produce a negative verdict."""
    project_sources = {
        "main.py": """def main():
    pass

if __name__ == '__main__':
    main()
"""
    }
    cg = CallGraphBuilder().build_graph("proj", project_sources, {})
    EntryPointDetector().detect_and_register(cg, project_sources)
    finding = VerdictEngine(cg).evaluate_advisory(
        Advisory(id="GHSA-empty-symbols", package_name="missing-pkg"),
        "1.0.0",
    )
    assert finding.verdict == Verdict.UNCERTAIN
    assert [r.category for r in finding.uncertainty_reasons] == [
        UncertaintyCategory.NO_AFFECTED_SYMBOLS
    ]


def test_finding_validator_rejects_not_reachable_without_symbols() -> None:
    """The model validator independently enforces the no-symbol soundness rule."""
    try:
        Finding(
            advisory_id="GHSA-empty-symbols",
            package_name="pkg",
            installed_version="1.0.0",
            verdict=Verdict.NOT_REACHABLE,
            confidence=ConfidenceLevel.HIGH,
            summary="invalid",
        )
    except ValueError as exc:
        assert "no affected symbols" in str(exc).lower()
    else:
        raise AssertionError("Finding accepted NOT_REACHABLE with no affected symbols")


def test_end_to_end_three_mini_projects_and_openvex(tmp_path: Path) -> None:
    """End-to-end verification of 3 mini-projects: REACHABLE, NOT_REACHABLE, UNCERTAIN."""

    # -----------------------------------------------------------------------
    # Project 1: REACHABLE
    # -----------------------------------------------------------------------
    proj1_sources = {
        "app/main.py": """import vuln_pkg

def run():
    vuln_pkg.vulnerable_function()

if __name__ == '__main__':
    run()
"""
    }
    dep1_sources = {
        "vuln-pkg": {
            "vuln_pkg/__init__.py": """def vulnerable_function():
    return 'exploited'
"""
        }
    }
    cg1 = CallGraphBuilder().build_graph("proj1", proj1_sources, dep1_sources)
    detector1 = EntryPointDetector()
    detector1.detect_and_register(cg1, proj1_sources)

    adv1 = Advisory(
        id="GHSA-reachable-1",
        package_name="vuln-pkg",
        extracted_symbols=[
            AffectedSymbol(
                package="vuln-pkg",
                module="vuln_pkg",
                qualified_name="vuln_pkg.vulnerable_function",
                symbol_type=SymbolType.FUNCTION,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
                confidence=ConfidenceLevel.HIGH,
            )
        ],
    )
    engine1 = VerdictEngine(call_graph=cg1)
    finding1 = engine1.evaluate_advisory(adv1, "1.0.0")
    assert finding1.verdict == Verdict.REACHABLE
    assert finding1.confidence == ConfidenceLevel.HIGH
    assert len(finding1.call_path) >= 1

    # -----------------------------------------------------------------------
    # Project 2: NOT_REACHABLE
    # -----------------------------------------------------------------------
    proj2_sources = {
        "app/main.py": """import safe_pkg

def run():
    safe_pkg.safe_api()

if __name__ == '__main__':
    run()
"""
    }
    dep2_sources = {
        "safe-pkg": {
            "safe_pkg/__init__.py": """def safe_api():
    return 'ok'

def vulnerable_subroutine():
    return 'dangerous'
"""
        }
    }
    cg2 = CallGraphBuilder().build_graph("proj2", proj2_sources, dep2_sources)
    detector2 = EntryPointDetector()
    detector2.detect_and_register(cg2, proj2_sources)

    adv2 = Advisory(
        id="GHSA-not-reachable-2",
        package_name="safe-pkg",
        extracted_symbols=[
            AffectedSymbol(
                package="safe-pkg",
                module="safe_pkg",
                qualified_name="safe_pkg.vulnerable_subroutine",
                symbol_type=SymbolType.FUNCTION,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
                confidence=ConfidenceLevel.HIGH,
            )
        ],
    )
    engine2 = VerdictEngine(call_graph=cg2, dynamic_sites=[])
    finding2 = engine2.evaluate_advisory(adv2, "1.0.0")
    assert finding2.verdict == Verdict.NOT_REACHABLE
    assert finding2.confidence == ConfidenceLevel.HIGH
    assert len(finding2.call_path) == 0

    # -----------------------------------------------------------------------
    # Project 3: UNCERTAIN (via non-constant getattr touching target package)
    # -----------------------------------------------------------------------
    proj3_sources = {
        "app/main.py": """import dynamic_pkg

def run(action_name):
    fn = getattr(dynamic_pkg, action_name)
    return fn()

if __name__ == '__main__':
    run('test')
"""
    }
    dep3_sources = {
        "dynamic-pkg": {
            "dynamic_pkg/__init__.py": """def vulnerable_endpoint():
    pass
"""
        }
    }
    import ast
    tree3 = ast.parse(proj3_sources["app/main.py"])
    imports3 = extract_module_imports(tree3, "app.main")
    classifier3 = DynamicFeatureClassifier("app/main.py", "app.main", imports3)
    classifier3.visit(tree3)

    cg3 = CallGraphBuilder().build_graph("proj3", proj3_sources, dep3_sources)
    detector3 = EntryPointDetector()
    detector3.detect_and_register(cg3, proj3_sources)

    adv3 = Advisory(
        id="GHSA-uncertain-3",
        package_name="dynamic-pkg",
        extracted_symbols=[
            AffectedSymbol(
                package="dynamic-pkg",
                module="dynamic_pkg",
                qualified_name="dynamic_pkg.vulnerable_endpoint",
                symbol_type=SymbolType.FUNCTION,
                source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
                confidence=ConfidenceLevel.HIGH,
            )
        ],
    )
    engine3 = VerdictEngine(call_graph=cg3, dynamic_sites=classifier3.dynamic_sites)
    finding3 = engine3.evaluate_advisory(adv3, "1.0.0")
    assert finding3.verdict == Verdict.UNCERTAIN
    assert len(finding3.uncertainty_reasons) >= 1

    # -----------------------------------------------------------------------
    # OpenVEX Document Validation
    # -----------------------------------------------------------------------
    vex_doc = generate_openvex_for_findings([finding1, finding2, finding3])
    raw_vex = vex_doc.to_openvex_json()
    parsed_vex = json.loads(raw_vex)

    # OpenVEX MUST contain ONLY the NOT_REACHABLE finding!
    assert len(parsed_vex["statements"]) == 1
    stmt = parsed_vex["statements"][0]
    assert stmt["vulnerability"]["name"] == "GHSA-not-reachable-2"
    assert stmt["status"] == "not_affected"
    assert stmt["justification"] == "vulnerable_code_not_in_execute_path"
    assert "safe-pkg@1.0.0" in stmt["products"][0]["identifiers"]["purl"]


def test_cli_scan_command_with_advisory_file(tmp_path: Path) -> None:
    """Test full CLI scan execution writing findings.json and openvex.json."""
    project_dir = tmp_path / "test_app"
    project_dir.mkdir()
    (project_dir / "main.py").write_text("""import safe_lib

def run():
    safe_lib.safe_work()

if __name__ == '__main__':
    run()
""", encoding="utf-8")
    (project_dir / "requirements.txt").write_text("safe-lib == 1.0.0\n", encoding="utf-8")

    adv_file = tmp_path / "advisory.json"
    adv_file.write_text(json.dumps({
        "id": "GHSA-cli-test",
        "aliases": ["CVE-2022-0001"],
        "summary": "Sample advisory for CLI test",
        "affected": [
            {
                "package": {"name": "safe-lib", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]
            }
        ]
    }), encoding="utf-8")

    out_dir = tmp_path / "cli_out"
    result = runner.invoke(app, [
        "scan",
        str(project_dir),
        "--advisories",
        str(adv_file),
        "--out",
        str(out_dir),
    ])

    assert result.exit_code == 0
    assert (out_dir / "findings.json").exists()
    assert (out_dir / "openvex.json").exists()
