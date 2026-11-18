"""Evaluation harness for pyreach reachability verdicts.

Runs benchmarks from eval/expected_verdicts.json covering live demo projects
and synthetic/inline edge cases. Reports accuracy, precision, and soundness.
Fails with non-zero exit code if any unsound verdict (reachable marked NOT_REACHABLE) occurs.
"""

from __future__ import annotations

import ast
import json
import shutil
import sys
import tempfile
from pathlib import Path

from packaging.utils import canonicalize_name
from rich.console import Console
from rich.table import Table
from typer.testing import CliRunner

from pyreach.analysis.callgraph_builder import CallGraphBuilder
from pyreach.analysis.dynamic import DynamicFeatureClassifier
from pyreach.analysis.entry_points import EntryPointDetector
from pyreach.analysis.imports import extract_module_imports
from pyreach.cli import app
from pyreach.engine.verdict import VerdictEngine
from pyreach.models import (
    Advisory,
    AffectedSymbol,
    AnalysisMode,
    ConfidenceLevel,
    SymbolEvidenceSource,
    SymbolType,
    Verdict,
)


def evaluate_inline_fixture(case: dict) -> str:
    """Run reachability evaluation on an inline synthetic fixture."""
    project_sources: dict[str, str] = case.get("project_sources", {})
    dep_sources: dict[str, dict[str, str]] = case.get("dep_sources", {})
    pkg_name = str(canonicalize_name(case.get("package", "dependency")))
    norm_dep_sources: dict[str, dict[str, str]] = {
        str(canonicalize_name(k)): v for k, v in dep_sources.items()
    }

    # Build CallGraph
    builder = CallGraphBuilder()
    cg = builder.build_graph(
        project_name="eval_test_project",
        project_sources=project_sources,
        dependency_sources=norm_dep_sources,
    )

    # Register native modules if specified
    for nat in case.get("native_modules", []):
        cg.native_modules.add(nat)

    # Detect Entry Points
    detector = EntryPointDetector(mode=AnalysisMode.APP)
    detector.detect_and_register(cg, project_sources)

    # Extract dynamic constructs across project files
    dynamic_sites = []
    for rel_path, code in project_sources.items():
        mod_name = rel_path.replace("/", ".").replace("\\", ".")
        if mod_name.endswith(".py"):
            mod_name = mod_name[:-3]
        try:
            tree = ast.parse(code)
            imports = extract_module_imports(tree, mod_name)
            classifier = DynamicFeatureClassifier(rel_path, mod_name, imports)
            classifier.visit(tree)
            dynamic_sites.extend(classifier.dynamic_sites)
        except Exception:
            continue

    # Construct Advisory and AffectedSymbol
    target_mod = case.get("target_module", "")
    target_sym = case.get("target_symbol", "")
    affected = [
        AffectedSymbol(
            package=pkg_name,
            module=target_mod,
            qualified_name=target_sym,
            symbol_type=SymbolType.FUNCTION,
            confidence=ConfidenceLevel.HIGH,
            source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
        )
    ]
    advisory = Advisory(
        id=case.get("advisory_id", "GHSA-eval-test"),
        package_name=pkg_name,
        extracted_symbols=affected,
    )

    # Compute verdict
    engine = VerdictEngine(call_graph=cg, dynamic_sites=dynamic_sites)
    finding = engine.evaluate_advisory(
        advisory=advisory,
        installed_version="1.0.0",
        required_packages=list(norm_dep_sources.keys()),
    )
    return finding.verdict.value


def evaluate_directory_project(case: dict) -> str:
    """Run reachability scan on a project directory via the CLI."""
    project_path = Path(case["project_path"])
    advisory_id = case["advisory_id"]

    runner = CliRunner()
    tmp_out = Path(tempfile.mkdtemp(prefix="pyreach_eval_"))
    try:
        res = runner.invoke(
            app,
            [
                "scan",
                str(project_path),
                "-a",
                advisory_id,
                "-o",
                str(tmp_out),
            ],
        )
        if res.exit_code != 0:
            return f"ERROR: CLI exited with code {res.exit_code}: {res.output}"

        findings_file = tmp_out / "findings.json"
        if not findings_file.exists():
            return "ERROR: findings.json not generated"

        data = json.loads(findings_file.read_text(encoding="utf-8"))
        if not data:
            return "ERROR: findings.json is empty"

        return str(data[0].get("verdict", "UNKNOWN"))
    finally:
        shutil.rmtree(tmp_out, ignore_errors=True)


def main() -> int:
    console = Console()
    benchmarks_file = Path("eval/expected_verdicts.json")
    if not benchmarks_file.exists():
        console.print(f"[bold red]Error:[/] Benchmark file '{benchmarks_file}' does not exist.")
        return 1

    cases = json.loads(benchmarks_file.read_text(encoding="utf-8"))
    console.print(f"[bold cyan]Running pyreach Reachability Evaluation Harness ({len(cases)} cases)...[/]\n")

    results_table = Table(
        title="pyreach Benchmark Evaluation Results",
        header_style="bold magenta",
        show_lines=True,
    )
    results_table.add_column("Case Name", style="bold", width=32)
    results_table.add_column("Package / Advisory", width=22)
    results_table.add_column("Expected", justify="center", width=14)
    results_table.add_column("Actual", justify="center", width=14)
    results_table.add_column("Status", justify="center", width=10)

    total_cases = len(cases)
    matched_cases = 0
    unsound_cases = 0

    for case in cases:
        name = case["name"]
        pkg_adv = f"{case.get('package', 'dep')} ({case.get('advisory_id', 'test')})"
        expected = case["expected_verdict"]

        if case.get("fixture_type") == "inline":
            actual = evaluate_inline_fixture(case)
        else:
            actual = evaluate_directory_project(case)

        # Soundness violation: expected REACHABLE, but marked NOT_REACHABLE
        is_unsound = (expected == Verdict.REACHABLE.value and actual == Verdict.NOT_REACHABLE.value)
        if is_unsound:
            unsound_cases += 1
            status_str = "[bold red]UNSOUND[/]"
        elif actual == expected:
            matched_cases += 1
            status_str = "[bold green]PASS[/]"
        else:
            status_str = "[bold yellow]FAIL[/]"

        actual_colored = (
            f"[bold green]{actual}[/]" if actual == expected
            else f"[bold red]{actual}[/]"
        )

        results_table.add_row(name, pkg_adv, expected, actual_colored, status_str)

    console.print(results_table)
    console.print()

    accuracy = (matched_cases / total_cases) * 100.0 if total_cases > 0 else 0.0

    summary_table = Table(title="Evaluation Metrics Summary", header_style="bold cyan")
    summary_table.add_column("Metric", style="bold", width=30)
    summary_table.add_column("Value", justify="right", width=20)

    summary_table.add_row("Total Benchmark Cases", str(total_cases))
    summary_table.add_row("Correct Verdicts", f"{matched_cases} / {total_cases}")
    summary_table.add_row("Benchmark Accuracy", f"{accuracy:.1f}%")
    summary_table.add_row(
        "Unsound Verdicts (False Safe)",
        "[bold green]0[/]" if unsound_cases == 0 else f"[bold red]{unsound_cases}[/]",
    )

    console.print(summary_table)

    if unsound_cases > 0:
        console.print(
            f"\n[bold red]CRITICAL FAILURE:[/] {unsound_cases} unsound verdict(s) detected! "
            "Reachable vulnerable code was marked NOT_REACHABLE. This violates the core soundness guarantee."
        )
        return 1

    if matched_cases != total_cases:
        console.print(
            f"\n[bold yellow]FAILURE:[/] {total_cases - matched_cases} verdict mismatch(es) detected."
        )
        return 1

    console.print("\n[bold green]ALL EVALUATION BENCHMARKS PASSED SOUNDLY AND ACCURATELY![/]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
