"""Command-line interface for pyreach vulnerability reachability analyzer."""

from __future__ import annotations

import concurrent.futures
import json
from pathlib import Path
from typing import Annotated

import typer
from packaging.utils import canonicalize_name
from rich.console import Console

from pyreach.advisory.loader import load_advisory_input
from pyreach.advisory.osv_client import HTTPOSVClient
from pyreach.advisory.resolver import AdvisorySymbolResolver, HTTPVCSClient
from pyreach.analysis.callgraph_builder import CallGraphBuilder
from pyreach.analysis.dynamic import DynamicFeatureClassifier
from pyreach.analysis.entry_points import EntryPointDetector
from pyreach.analysis.imports import extract_module_imports
from pyreach.engine.reporter import export_findings_json, render_terminal_report
from pyreach.engine.verdict import VerdictEngine
from pyreach.engine.vex import generate_openvex_for_findings
from pyreach.isolation.cache import CachedPackageSummary, PackageSummaryCache
from pyreach.isolation.manifest_parser import parse_project_manifests
from pyreach.isolation.pypi_client import HTTPPyPIClient
from pyreach.isolation.safe_archive import extract_tar_safely, extract_zip_safely
from pyreach.isolation.wheel_metadata import discover_wheel_top_level_modules
from pyreach.models import Advisory, AnalysisMode, CallGraph, CallGraphEdge, CallGraphNode, Finding

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
    ] = [],
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
    limit: Annotated[
        int | None,
        typer.Option("--limit", help="Maximum advisories to analyze when querying OSV."),
    ] = None,
    only_with_fix_commit: Annotated[
        bool,
        typer.Option("--only-with-fix-commit", help="Analyze only advisories with fix commits."),
    ] = False,
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
    if not advisories:
        for pkg in pinned_pkgs:
            if pkg.version:
                adv_objects.extend(osv_client.query_advisories(pkg.name, pkg.version))
        unique: dict[str, Advisory] = {adv.id: adv for adv in adv_objects}
        adv_objects = list(unique.values())
        if only_with_fix_commit:
            adv_objects = [adv for adv in adv_objects if adv.fix_commits]
        if limit is not None:
            adv_objects = adv_objects[: max(0, limit)]
        console.print(f"Loaded {len(adv_objects)} advisories from OSV querybatch")
    for adv_input in advisories:
        try:
            loaded, source = load_advisory_input(adv_input, osv_client)
            adv_objects.extend(loaded)
            console.print(f"Loaded {len(loaded)} advisories from {source}")
        except ValueError as exc:
            console.print(f"[bold red]Error loading advisories:[/] {exc}")

    if not adv_objects:
        console.print("[bold red]Error:[/] No valid advisories provided to evaluate.")
        raise typer.Exit(code=1)

    # 4. Acquire pinned dependencies and build CallGraph with full caching & concurrency
    pypi_client = HTTPPyPIClient()
    cache_root = Path.home() / ".cache" / "pyreach"
    dl_dir = cache_root / "downloads"
    ext_dir = cache_root / "extracted"
    summary_cache = PackageSummaryCache()
    builder = CallGraphBuilder()
    cg = CallGraph()

    # Step 4a: Concurrently download & extract any un-extracted packages
    missing_pkgs = [
        pkg for pkg in pinned_pkgs
        if pkg.version and not (ext_dir / canonicalize_name(pkg.name) / pkg.version).exists()
    ]
    if missing_pkgs:
        console.print(f"[cyan]Acquiring {len(missing_pkgs)} missing package(s) from PyPI concurrently...[/cyan]")

        def _download_and_extract(p_entry: object) -> None:
            pkg_name = getattr(p_entry, "name", "")
            pkg_ver = getattr(p_entry, "version", "")
            if not pkg_ver:
                return
            norm_name = canonicalize_name(pkg_name)
            target = ext_dir / norm_name / pkg_ver
            try:
                arc = pypi_client.download_package(
                    package=norm_name,
                    version=pkg_ver,
                    dest_dir=dl_dir,
                    prefer_wheel=True,
                )
                if arc.suffix in (".whl", ".zip"):
                    extract_zip_safely(arc, target)
                else:
                    extract_tar_safely(arc, target)
            except Exception as e:
                console.print(f"[bold yellow]Warning:[/] Could not acquire '{pkg_name}=={pkg_ver}': {e}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(missing_pkgs))) as executor:
            list(executor.map(_download_and_extract, missing_pkgs))

    # Step 4b: Per-package graph analysis function
    def _analyze_package(p_entry: object) -> tuple[str, CachedPackageSummary | None]:
        pkg_name = getattr(p_entry, "name", "")
        pkg_ver = getattr(p_entry, "version", "")
        norm_name = canonicalize_name(pkg_name)
        if not pkg_ver:
            return norm_name, None

        target_extract = ext_dir / norm_name / pkg_ver
        if not target_extract.exists():
            return norm_name, None

        # Check SQLite cache first
        cached = summary_cache.get(norm_name, pkg_ver, "extracted")
        if cached and cached.package_stats:
            return norm_name, cached

        search_dir = target_extract
        children = [p for p in target_extract.iterdir() if p.is_dir() and not p.name.startswith(".")]
        if (
            len(children) == 1
            and not (target_extract / "__init__.py").exists()
            and not children[0].name.endswith(".dist-info")
        ):
            search_dir = children[0]
        if (search_dir / "src").is_dir():
            search_dir = search_dir / "src"

        pkg_sources: dict[str, str] = {}
        for py_path in search_dir.rglob("*.py"):
            rel_f = str(py_path.relative_to(search_dir)).replace("\\", "/")
            try:
                pkg_sources[rel_f] = py_path.read_text(encoding="utf-8")
            except Exception:
                continue

        discovered_top_levels = discover_wheel_top_level_modules(search_dir)
        if not discovered_top_levels and search_dir != target_extract:
            discovered_top_levels = discover_wheel_top_level_modules(target_extract)

        dist_fn = ""
        dist_tag = ""
        is_plat = False
        meta_path = target_extract / ".dist_meta.json"
        if meta_path.exists():
            try:
                mdata = json.loads(meta_path.read_text(encoding="utf-8"))
                dist_fn = mdata.get("filename", "")
                dist_tag = mdata.get("distribution_tag", "")
                is_plat = bool(mdata.get("is_platform_wheel"))
            except Exception:
                pass
        else:
            wheel_files = list(target_extract.glob("*.dist-info/WHEEL"))
            if wheel_files:
                try:
                    content = wheel_files[0].read_text(encoding="utf-8", errors="ignore")
                    tags = [line.split(":", 1)[1].strip() for line in content.splitlines() if line.startswith("Tag:")]
                    dist_tag = tags[0] if tags else "unknown"
                    is_pure = "none-any" in dist_tag.lower()
                    dist_fn = f"{norm_name}-{pkg_ver}-{dist_tag}.whl"
                    is_plat = not is_pure
                except Exception:
                    pass
            else:
                dist_fn = f"{norm_name}-{pkg_ver}.tar.gz"
                dist_tag = "sdist"

        has_platform_cond = any(
            ("sys.platform" in code or "os.name" in code or "platform.system" in code)
            for code in pkg_sources.values()
        )

        pkg_native_mods: list[str] = []
        for nat_path in list(search_dir.rglob("*.so")) + list(search_dir.rglob("*.pyd")):
            rel_n = str(nat_path.relative_to(search_dir)).replace("\\", "/")
            parts = rel_n.split("/")
            if parts:
                mod_name = ".".join(parts[:-1]) if len(parts) > 1 else norm_name
                file_stem = parts[-1].split(".")[0]
                full_mod = f"{mod_name}.{file_stem}" if mod_name else file_stem
                pkg_native_mods.append(full_mod)

        pkg_builder = CallGraphBuilder()
        nodes, edges, stats = pkg_builder.build_package_graph(norm_name, pkg_sources, is_dependency=True)

        summary = CachedPackageSummary(
            package_name=norm_name,
            version=pkg_ver,
            wheel_hash="extracted",
            analyzer_version="0.1.0",
            nodes=[n.model_dump() for n in nodes],
            edges=[e.model_dump() for e in edges],
            native_modules=pkg_native_mods,
            package_stats=stats.model_dump(),
            top_level_modules=list(discovered_top_levels),
            has_platform_conditionals=has_platform_cond,
            distribution_filename=dist_fn,
            distribution_tag=dist_tag,
            is_platform_wheel=is_plat,
        )
        summary_cache.put(norm_name, pkg_ver, "extracted", summary)
        return norm_name, summary

    # Step 4c: Check cache hits and analyze uncached packages
    cached_summaries: list[CachedPackageSummary] = []
    uncached_entries: list[object] = []
    for pkg in pinned_pkgs:
        if not pkg.version:
            continue
        norm_name = canonicalize_name(pkg.name)
        cached = summary_cache.get(norm_name, pkg.version, "extracted")
        if cached and cached.package_stats:
            cached_summaries.append(cached)
        else:
            uncached_entries.append(pkg)

    if cached_summaries:
        console.print(f"[dim]Loaded {len(cached_summaries)} pre-computed package call graph(s) from SQLite cache[/dim]")

    new_summaries: list[CachedPackageSummary] = []
    if uncached_entries:
        console.print(f"[cyan]Parsing ASTs for {len(uncached_entries)} package(s) across CPU threads...[/cyan]")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(uncached_entries))) as executor:
            for _, summary in executor.map(_analyze_package, uncached_entries):
                if summary:
                    new_summaries.append(summary)

    # Step 4d: Populate CallGraph from all summaries
    package_top_levels: dict[str, set[str]] = {}
    package_distribution_filenames: dict[str, str] = {}
    package_distribution_tags: dict[str, str] = {}
    package_platform_wheels: dict[str, str] = {}
    package_has_platform_conditionals: set[str] = set()
    native_modules: set[str] = set()

    for summary in cached_summaries + new_summaries:
        norm_name = canonicalize_name(summary.package_name)
        for node_dict in summary.nodes:
            cg.add_node(CallGraphNode.model_validate(node_dict))
        for edge_dict in summary.edges:
            cg.add_edge(CallGraphEdge.model_validate(edge_dict))
        pstats = summary.package_stats
        cg.record_package_stats(
            norm_name,
            pstats.get("files_total", 0),
            pstats.get("files_parsed", 0),
            pstats.get("files_failed", 0),
        )
        native_modules.update(summary.native_modules)
        package_top_levels[norm_name] = set(summary.top_level_modules)
        if summary.distribution_filename:
            package_distribution_filenames[norm_name] = summary.distribution_filename
        if summary.distribution_tag:
            package_distribution_tags[norm_name] = summary.distribution_tag
        if summary.is_platform_wheel:
            package_platform_wheels[norm_name] = summary.distribution_filename
        if summary.has_platform_conditionals:
            package_has_platform_conditionals.add(norm_name)

    # Step 4e: Parse local project sources into CallGraph
    proj_nodes, proj_edges, proj_stats = builder.build_package_graph(
        package_name=canonicalize_name(project_path.name),
        sources=project_sources,
        is_dependency=False,
    )
    for n in proj_nodes:
        cg.add_node(n)
    for e in proj_edges:
        cg.add_edge(e)
    cg.record_package_stats(
        canonicalize_name(project_path.name),
        proj_stats.files_total,
        proj_stats.files_parsed,
        proj_stats.files_failed,
    )

    cg.native_modules.update(native_modules)
    cg.package_top_levels.update(package_top_levels)
    cg.package_distribution_filenames.update(package_distribution_filenames)
    cg.package_distribution_tags.update(package_distribution_tags)
    cg.package_platform_wheels.update(package_platform_wheels)
    cg.package_has_platform_conditionals.update(package_has_platform_conditionals)

    # Step 4f: Resolve advisory symbols
    vcs_client = HTTPVCSClient()
    resolver = AdvisorySymbolResolver(vcs_client=vcs_client)
    for adv in adv_objects:
        if not adv.extracted_symbols:
            try:
                adv.extracted_symbols = resolver.resolve(adv)
            except Exception as e:
                console.print(f"[bold yellow]Warning:[/] Could not resolve symbols for advisory '{adv.id}': {e}")

    # 6. Detect entry points
    detector = EntryPointDetector(mode=analysis_mode)
    detector.detect_and_register(cg, project_sources, project_path)

    # 7. Extract dynamic constructs across project files
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
        console.print(f"  Findings JSON: {findings_json_path.name}")
        console.print(f"  OpenVEX Document: {openvex_path.name}")


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
