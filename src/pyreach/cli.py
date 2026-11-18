"""Command-line interface for pyreach vulnerability reachability analyzer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from packaging.utils import canonicalize_name
from rich.console import Console

from pyreach.advisory.osv_client import HTTPOSVClient, parse_osv_json
from pyreach.analysis.callgraph_builder import CallGraphBuilder
from pyreach.analysis.dynamic import DynamicFeatureClassifier
from pyreach.analysis.entry_points import EntryPointDetector
from pyreach.analysis.imports import extract_module_imports
from pyreach.engine.reporter import export_findings_json, render_terminal_report
from pyreach.engine.verdict import VerdictEngine
from pyreach.engine.vex import generate_openvex_for_findings
from pyreach.isolation.manifest_parser import parse_project_manifests
from pyreach.models import Advisory, AnalysisMode, Finding

app = typer.Typer(
    name="pyreach",
    help="Sound vulnerability reachability analyzer for Python dependencies.",
    add_completion=False,
)
console = Console()


def scan_project_py_files(root: Path) -> dict[str, str]:
    """Scan all Python source files in root directory, returning rel_path -> content."""
    sources: dict[str, str] = {}
    for p in root.rglob("*.py"):
        if any(part in p.parts for part in (".venv", "venv", ".git", "__pycache__", "build", "dist")):
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        try:
            sources[rel] = p.read_text(encoding="utf-8")
        except Exception:
            continue
    return sources


@app.command()
def scan(
    project_path: Annotated[
        Path,
        typer.Argument(help="Path to Python project directory to analyze."),
    ],
    advisories: Annotated[
        list[str],
        typer.Option(
            "--advisories",
            "-a",
            help="OSV advisory IDs (e.g. GHSA-xxx) or paths to advisory JSON files.",
        ),
    ],
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Output directory for findings.json and openvex.json.",
        ),
    ] = None,
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            "-m",
            help="Analysis mode: 'app' (applications with entry points) or 'library' (public API).",
        ),
    ] = "app",
) -> None:
    """Scan a Python project and decide reachability for each given advisory."""
    if not project_path.exists():
        console.print(f"[bold red]Error:[/] Project path '{project_path}' does not exist.")
        raise typer.Exit(code=1)

    analysis_mode = AnalysisMode.LIBRARY if mode.lower() == "library" else AnalysisMode.APP

    # 1. Collect project sources
    project_sources = scan_project_py_files(project_path)
    if not project_sources:
        console.print(f"[bold yellow]Warning:[/] No Python source files found in '{project_path}'.")

    # 2. Parse manifests to discover pinned dependencies
    pinned_pkgs = parse_project_manifests(project_path)
    pkg_versions = {p.name: p.version for p in pinned_pkgs}
    required_packages = list(pkg_versions.keys())

    # 3. Load advisories
    adv_objects: list[Advisory] = []
    osv_client = HTTPOSVClient()
    for adv_input in advisories:
        p = Path(adv_input)
        if p.exists() and p.suffix == ".json":
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                adv_objects.append(parse_osv_json(data))
            except Exception as e:
                console.print(f"[bold red]Error parsing advisory JSON '{adv_input}':[/] {e}")
        else:
            # Split comma-separated IDs if passed as a single string
            for adv_id in adv_input.split(","):
                clean_id = adv_id.strip()
                if clean_id:
                    adv = osv_client.get_advisory(clean_id)
                    if adv:
                        adv_objects.append(adv)
                    else:
                        console.print(f"[bold yellow]Warning:[/] Advisory '{clean_id}' not found in OSV database.")

    if not adv_objects:
        console.print("[bold red]Error:[/] No valid advisories provided to evaluate.")
        raise typer.Exit(code=1)

    # 4. Build unified call graph
    builder = CallGraphBuilder()
    cg = builder.build_graph(
        project_name=canonicalize_name(project_path.name),
        project_sources=project_sources,
        dependency_sources={},  # Dependencies analyzed if unpacked in site-packages or cache
    )

    # 5. Detect entry points
    detector = EntryPointDetector(mode=analysis_mode)
    detector.detect_and_register(cg, project_sources, project_path)

    # 6. Extract dynamic constructs across project files
    dynamic_sites = []
    for rel_path, code in project_sources.items():
        mod_name = rel_path.replace("/", ".").replace("\\", ".")
        if mod_name.endswith(".py"):
            mod_name = mod_name[:-3]
        try:
            import ast
            tree = ast.parse(code)
            imports = extract_module_imports(tree, mod_name)
            classifier = DynamicFeatureClassifier(rel_path, mod_name, imports)
            classifier.visit(tree)
            dynamic_sites.extend(classifier.dynamic_sites)
        except Exception:
            continue

    # 7. Evaluate each advisory
    verdict_engine = VerdictEngine(call_graph=cg, dynamic_sites=dynamic_sites)
    findings: list[Finding] = []

    for adv in adv_objects:
        norm_pkg = canonicalize_name(adv.package_name)
        installed_v = pkg_versions.get(norm_pkg, "unknown")
        f = verdict_engine.evaluate_advisory(
            advisory=adv,
            installed_version=installed_v,
            required_packages=required_packages if required_packages else None,
        )
        findings.append(f)

    # 8. Render Rich terminal report
    render_terminal_report(findings, console=console)

    # 9. Export JSON and OpenVEX if requested
    if out:
        out_dir = Path(out)
        out_dir.mkdir(parents=True, exist_ok=True)
        findings_json_path = out_dir / "findings.json"
        openvex_path = out_dir / "openvex.json"

        export_findings_json(findings, findings_json_path)
        vex_doc = generate_openvex_for_findings(findings)
        openvex_path.write_text(vex_doc.to_openvex_json(indent=2), encoding="utf-8")

        console.print(f"[bold green]Artifacts written successfully:[/] {out_dir.resolve()}")
        console.print(f"  • Findings JSON: {findings_json_path.name}")
        console.print(f"  • OpenVEX Document: {openvex_path.name}")


@app.command()
def explain(
    findings_file: Annotated[
        Path,
        typer.Argument(help="Path to findings.json file exported from a scan."),
    ],
) -> None:
    """Render human-readable explanations of all findings from a findings.json file."""
    if not findings_file.exists():
        console.print(f"[bold red]Error:[/] File '{findings_file}' does not exist.")
        raise typer.Exit(code=1)
    try:
        data = json.loads(findings_file.read_text(encoding="utf-8"))
        for item in data:
            f = Finding.model_validate(item)
            console.print(f.explain())
            console.print("-" * 60)
    except Exception as e:
        console.print(f"[bold red]Error parsing findings file:[/] {e}")
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the pyreach version."""
    console.print("pyreach 0.1.0")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
