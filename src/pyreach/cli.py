"""Command-line interface for pyreach vulnerability reachability analyzer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from packaging.utils import canonicalize_name
from rich.console import Console

from pyreach.advisory.osv_client import HTTPOSVClient, parse_osv_json
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
from pyreach.isolation.text_reader import read_text_file
from pyreach.isolation.wheel_metadata import discover_wheel_top_level_modules
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
                data = json.loads(read_text_file(p))
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

    # 4. Acquire pinned dependencies and resolve advisory symbols
    dependency_sources: dict[str, dict[str, str]] = {}
    native_modules: set[str] = set()
    package_top_levels: dict[str, set[str]] = {}
    package_distribution_filenames: dict[str, str] = {}
    package_distribution_tags: dict[str, str] = {}
    package_platform_wheels: dict[str, str] = {}
    package_has_platform_conditionals: set[str] = set()
    pypi_client = HTTPPyPIClient()
    cache_root = Path.home() / ".cache" / "pyreach"
    dl_dir = cache_root / "downloads"
    ext_dir = cache_root / "extracted"
    summary_cache = PackageSummaryCache()

    for pkg in pinned_pkgs:
        norm_pkg_name = canonicalize_name(pkg.name)
        if not pkg.version:
            continue
        target_extract = ext_dir / norm_pkg_name / pkg.version
        archive_file: Path | None = None
        if not target_extract.exists():
            try:
                console.print(f"[cyan]📦 Downloading {norm_pkg_name}=={pkg.version} from PyPI...[/cyan]")
                archive_file = pypi_client.download_package(
                    package=norm_pkg_name,
                    version=pkg.version,
                    dest_dir=dl_dir,
                    prefer_wheel=True,
                )
                console.print(f"[cyan]📂 Extracting {archive_file.name} safely into sandbox cache...[/cyan]")
                if archive_file.suffix in (".whl", ".zip"):
                    extract_zip_safely(archive_file, target_extract)
                else:
                    extract_tar_safely(archive_file, target_extract)
                console.print(f"[cyan]🔍 Parsing and indexing {norm_pkg_name} source ASTs...[/cyan]")
            except Exception as e:
                console.print(f"[bold yellow]Warning:[/] Could not acquire package '{pkg.name}=={pkg.version}' from PyPI: {e}")
                continue

        # Check summary cache if wheel is present
        wheel_hash = "extracted"
        if archive_file and archive_file.exists():
            import hashlib
            wheel_hash = hashlib.sha256(archive_file.read_bytes()).hexdigest()

        cached = summary_cache.get(norm_pkg_name, pkg.version, wheel_hash)
        if cached:
            console.print(f"[dim]⚡ Package summary cache hit for {norm_pkg_name}=={pkg.version}[/dim]")
            native_modules.update(cached.native_modules)
            package_top_levels[norm_pkg_name] = set(cached.top_level_modules)

        # Load extracted sources and native modules
        if target_extract.exists():
            search_dir = target_extract
            children = [p for p in target_extract.iterdir() if p.is_dir() and not p.name.startswith(".")]
            if len(children) == 1 and not (target_extract / "__init__.py").exists():
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
            dependency_sources[norm_pkg_name] = pkg_sources

            # Discover top-level importable modules dynamically from wheel metadata
            discovered_top_levels = discover_wheel_top_level_modules(search_dir)
            if not discovered_top_levels and search_dir != target_extract:
                discovered_top_levels = discover_wheel_top_level_modules(target_extract)
            package_top_levels[norm_pkg_name] = discovered_top_levels
            if discovered_top_levels and not cached:
                console.print(f"[dim]🔍 Discovered top-level import module(s) for {norm_pkg_name}: {', '.join(sorted(discovered_top_levels))}[/dim]")

            # Distribution metadata tracking
            meta_path = target_extract / ".dist_meta.json"
            if meta_path.exists():
                try:
                    mdata = json.loads(meta_path.read_text(encoding="utf-8"))
                    package_distribution_filenames[norm_pkg_name] = mdata.get("filename", "")
                    package_distribution_tags[norm_pkg_name] = mdata.get("distribution_tag", "")
                    if mdata.get("is_platform_wheel"):
                        package_platform_wheels[norm_pkg_name] = mdata.get("filename", "")
                except Exception:
                    pass
            elif archive_file and (dl_dir / f"{archive_file.name}.meta.json").exists():
                try:
                    mdata = json.loads((dl_dir / f"{archive_file.name}.meta.json").read_text(encoding="utf-8"))
                    package_distribution_filenames[norm_pkg_name] = mdata.get("filename", "")
                    package_distribution_tags[norm_pkg_name] = mdata.get("distribution_tag", "")
                    if mdata.get("is_platform_wheel"):
                        package_platform_wheels[norm_pkg_name] = mdata.get("filename", "")
                    meta_path.write_text(json.dumps(mdata), encoding="utf-8")
                except Exception:
                    pass
            else:
                wheel_files = list(target_extract.glob("*.dist-info/WHEEL"))
                if wheel_files:
                    try:
                        content = wheel_files[0].read_text(encoding="utf-8", errors="ignore")
                        tags = [line.split(":", 1)[1].strip() for line in content.splitlines() if line.startswith("Tag:")]
                        tag = tags[0] if tags else "unknown"
                        is_pure = "none-any" in tag.lower()
                        fn = f"{norm_pkg_name}-{pkg.version}-{tag}.whl"
                        package_distribution_filenames[norm_pkg_name] = fn
                        package_distribution_tags[norm_pkg_name] = tag
                        if not is_pure:
                            package_platform_wheels[norm_pkg_name] = fn
                    except Exception:
                        pass
                else:
                    package_distribution_filenames[norm_pkg_name] = f"{norm_pkg_name}-{pkg.version}.tar.gz"
                    package_distribution_tags[norm_pkg_name] = "sdist"

            # Check for platform-conditional Python code
            for code in pkg_sources.values():
                if "sys.platform" in code or "os.name" in code or "platform.system" in code:
                    package_has_platform_conditionals.add(norm_pkg_name)
                    break

            # Check for native extensions
            for nat_path in list(search_dir.rglob("*.so")) + list(search_dir.rglob("*.pyd")):
                rel_n = str(nat_path.relative_to(search_dir)).replace("\\", "/")
                parts = rel_n.split("/")
                if parts:
                    mod_name = ".".join(parts[:-1]) if len(parts) > 1 else norm_pkg_name
                    file_stem = parts[-1].split(".")[0]
                    full_mod = f"{mod_name}.{file_stem}" if mod_name else file_stem
                    native_modules.add(full_mod)

            # Save in summary cache if not already cached
            if not cached:
                summary_cache.put(
                    package_name=norm_pkg_name,
                    version=pkg.version,
                    wheel_hash=wheel_hash,
                    summary=CachedPackageSummary(
                        package_name=norm_pkg_name,
                        version=pkg.version,
                        wheel_hash=wheel_hash,
                        analyzer_version="0.1.0",
                        nodes=[],
                        edges=[],
                        native_modules=list(native_modules),
                        package_stats={},
                        top_level_modules=list(discovered_top_levels),
                    ),
                )

    # Resolve advisory symbols if not already provided
    vcs_client = HTTPVCSClient()
    resolver = AdvisorySymbolResolver(vcs_client=vcs_client)
    for adv in adv_objects:
        if not adv.extracted_symbols:
            try:
                adv.extracted_symbols = resolver.resolve(adv)
            except Exception as e:
                console.print(f"[bold yellow]Warning:[/] Could not resolve symbols for advisory '{adv.id}': {e}")

    # 5. Build unified call graph
    builder = CallGraphBuilder()
    cg = builder.build_graph(
        project_name=canonicalize_name(project_path.name),
        project_sources=project_sources,
        dependency_sources=dependency_sources,
    )
    cg.native_modules.update(native_modules)
    cg.package_top_levels.update(package_top_levels)
    cg.package_distribution_filenames.update(package_distribution_filenames)
    cg.package_distribution_tags.update(package_distribution_tags)
    cg.package_platform_wheels.update(package_platform_wheels)
    cg.package_has_platform_conditionals.update(package_has_platform_conditionals)

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
