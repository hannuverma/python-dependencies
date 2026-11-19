"""Empirical runtime execution tracer and independent ground truth evaluation harness.

Executes each fixture and demo benchmark under a runtime function call tracer (sys.settrace)
in an isolated throwaway environment (fixtures and demo cases only; never untrusted code).
Empirically proves whether the vulnerable target function actually executed, and verifies
that static analysis NEVER marks an executed function as NOT_REACHABLE.
"""

from __future__ import annotations

import json
import runpy
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.table import Table

from eval.run_eval import evaluate_directory_project, evaluate_inline_fixture
from pyreach.models import Verdict


def trace_execution(entry_file: Path, target_func_name: str, extra_paths: list[Path] | None = None) -> tuple[str, bool]:
    """Run an entry point file under sys.settrace to detect if target_func_name was called.

    Returns:
        (status_string, was_called_boolean)
        status_string is one of: "CALLED", "NOT CALLED", "NOT EXERCISED"
    """
    if not entry_file.exists():
        return "NOT EXERCISED", False

    executed_targets = set()
    orig_path = list(sys.path)
    orig_modules = set(sys.modules.keys())

    # Add extra module search paths
    if extra_paths:
        for p in reversed(extra_paths):
            sys.path.insert(0, str(p))
    sys.path.insert(0, str(entry_file.parent))

    # Provide safe stub for Pillow compiled C extension if Pillow is imported
    if "PIL._imaging" not in sys.modules:
        mock_core = MagicMock()
        mock_core.PILLOW_VERSION = "10.1.0"
        sys.modules["PIL._imaging"] = mock_core
        sys.modules["PIL._imagingmath"] = MagicMock()

    def tracer(frame, event, arg):  # type: ignore
        if event == "call":
            fn = frame.f_code.co_name
            if fn == target_func_name:
                mod = frame.f_globals.get("__name__", "")
                executed_targets.add(f"{mod}:{fn}")
        return tracer

    execution_succeeded = False
    try:
        sys.settrace(tracer)
        try:
            runpy.run_path(str(entry_file), run_name="__main__")
            execution_succeeded = True
        except Exception:
            # Expected exceptions for broken syntax or negative test cases
            pass
    finally:
        sys.settrace(None)
        sys.path = orig_path
        # Clean up any freshly imported modules to prevent cross-test leakage
        for m in list(sys.modules.keys()):
            if m not in orig_modules and not m.startswith("PIL"):
                sys.modules.pop(m, None)

    if len(executed_targets) > 0:
        return "CALLED", True
    elif execution_succeeded:
        return "NOT CALLED", False
    else:
        return "NOT EXERCISED", False


def run_runtime_ground_truth(case: dict) -> tuple[str, bool]:
    """Determine runtime ground truth: did the vulnerable symbol actually execute?"""
    target_sym = case.get("target_symbol", "")
    target_func = target_sym.split(":")[-1].split(".")[-1] if target_sym else "eval"

    if case.get("fixture_type") == "inline":
        with tempfile.TemporaryDirectory(prefix="pyreach_trace_") as tmpdir:
            tmproot = Path(tmpdir)
            # Write dependency sources
            dep_root = tmproot / "deps"
            dep_root.mkdir()
            for _dep_name, files in case.get("dep_sources", {}).items():
                for rel_path, code in files.items():
                    dest = dep_root / rel_path
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(code, encoding="utf-8")

            # Write project sources
            proj_root = tmproot / "proj"
            proj_root.mkdir()
            main_path = proj_root / "main.py"
            for rel_path, code in case.get("project_sources", {}).items():
                dest = proj_root / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(code, encoding="utf-8")
                if rel_path in ("main.py", "server.py"):
                    main_path = dest

            dep_paths = [dep_root]
            if (dep_root / "src").exists():
                dep_paths.insert(0, dep_root / "src")
            for sub in dep_root.glob("*/src"):
                if sub.is_dir():
                    dep_paths.insert(0, sub)
            for subpkg in dep_root.iterdir():
                if subpkg.is_dir():
                    dep_paths.append(subpkg)

            return trace_execution(main_path, target_func, extra_paths=dep_paths)
    else:
        proj_dir = Path(case["project_path"])
        main_path = proj_dir / "main.py"
        ext_pillow = Path.home() / ".cache" / "pyreach" / "extracted" / "pillow" / "10.1.0"
        extra = []
        if ext_pillow.exists():
            extra.append(ext_pillow)
            if (ext_pillow / "Pillow-10.1.0" / "src").exists():
                extra.append(ext_pillow / "Pillow-10.1.0" / "src")
            elif (ext_pillow / "src").exists():
                extra.append(ext_pillow / "src")
        return trace_execution(main_path, "eval", extra_paths=extra)


def main() -> int:
    console = Console()
    benchmarks_file = Path("eval/expected_verdicts.json")
    if not benchmarks_file.exists():
        console.print(f"[bold red]Error:[/] Benchmark file '{benchmarks_file}' does not exist.")
        return 1

    cases = json.loads(benchmarks_file.read_text(encoding="utf-8"))
    console.print(
        f"[bold cyan]Running pyreach Ground Truth & Hardened Eval Harness ({len(cases)} cases)...[/]\n"
    )

    table = Table(
        title="Empirical Runtime Ground Truth vs. Static Reachability Verdicts",
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("Case Name", style="bold", width=34)
    table.add_column("Expected", justify="center", width=14)
    table.add_column("Actual Tool", justify="center", width=14)
    table.add_column("Runtime Ground Truth", justify="center", width=22)
    table.add_column("Sound?", justify="center", width=10)
    table.add_column("Status", justify="center", width=10)

    total_cases = len(cases)
    matched_cases = 0
    unsound_cases = 0
    called_count = 0
    not_called_count = 0
    not_exercised_count = 0
    not_reachable_count = 0
    uncertain_count = 0

    for case in cases:
        name = case["name"]
        expected = case["expected_verdict"]

        # 1. Empirical Runtime Tracer
        runtime_status, runtime_ran = run_runtime_ground_truth(case)
        if runtime_status == "CALLED":
            called_count += 1
            ran_colored = "[bold red]CALLED (EXECUTED)[/]"
        elif runtime_status == "NOT CALLED":
            not_called_count += 1
            ran_colored = "[green]NOT CALLED (SAFE)[/]"
        else:
            not_exercised_count += 1
            ran_colored = "[dim]NOT EXERCISED[/]"

        # 2. Static Analyzer Tool Verdict
        if case.get("fixture_type") == "inline":
            actual = evaluate_inline_fixture(case)
        else:
            actual = evaluate_directory_project(case)

        if actual == Verdict.NOT_REACHABLE.value:
            not_reachable_count += 1
        elif actual == Verdict.UNCERTAIN.value:
            uncertain_count += 1

        # 3. Soundness Verification:
        # If code ran at runtime (CALLED), marking it NOT_REACHABLE is an unsound bug!
        if runtime_ran and actual == Verdict.NOT_REACHABLE.value:
            is_unsound = True
            unsound_cases += 1
            sound_str = "[bold red]VIOLATION[/]"
        else:
            is_unsound = False
            sound_str = "[bold green]YES[/]"

        if actual == expected and not is_unsound:
            matched_cases += 1
            status_str = "[bold green]PASS[/]"
        else:
            status_str = "[bold red]FAIL[/]"

        actual_colored = (
            f"[bold green]{actual}[/]" if actual == expected else f"[bold red]{actual}[/]"
        )

        table.add_row(name, expected, actual_colored, ran_colored, sound_str, status_str)

    console.print(table)
    console.print()

    accuracy = (matched_cases / total_cases) * 100.0 if total_cases > 0 else 0.0

    summary = Table(title="Soundness and Precision Evaluation Metrics", header_style="bold cyan")
    summary.add_column("Evaluation Metric", style="bold", width=38)
    summary.add_column("Result", justify="right", width=18)

    summary.add_row("Total Benchmark Cases", str(total_cases))
    summary.add_row("Runtime Executed Targets (CALLED)", str(called_count))
    summary.add_row("Runtime Uncalled Targets (NOT CALLED)", str(not_called_count))
    summary.add_row("Fixtures Not Exercised at Runtime", str(not_exercised_count))
    summary.add_row(
        "Unsound Verdicts (False Negatives)",
        "[bold green]0[/]" if unsound_cases == 0 else f"[bold red]{unsound_cases}[/]",
    )
    summary.add_row(
        "Soundness Rate (Executed Cases)",
        "[bold green]100.0%[/]" if unsound_cases == 0 else "[bold red]FAILED[/]",
    )
    summary.add_row("Precision: Provably Dead (NOT_REACHABLE)", str(not_reachable_count))
    summary.add_row("Precision: Soundly Guarded (UNCERTAIN)", str(uncertain_count))
    summary.add_row("Overall Benchmark Concordance", f"{matched_cases} / {total_cases} ({accuracy:.1f}%)")

    console.print(summary)

    if unsound_cases > 0:
        console.print(
            f"\n[bold red]CRITICAL SOUNDNESS FAILURE:[/] {unsound_cases} unsound verdict(s) detected! "
            "Code that executed at runtime was falsely marked NOT_REACHABLE."
        )
        return 1

    if matched_cases != total_cases:
        console.print(
            f"\n[bold yellow]FAILURE:[/] {total_cases - matched_cases} verdict mismatch(es)."
        )
        return 1

    console.print(
        "\n[bold green]ALL BENCHMARKS EVALUATED: 100% SOUNDNESS MAINTAINED (0 UNSOUND VERDICTS).[/]"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
