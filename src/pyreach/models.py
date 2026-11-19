"""Core Pydantic data models for pyreach vulnerability reachability analyzer.

All models strictly follow Pydantic v2 conventions and support full serialization
to JSON, OpenVEX v0.2.0, and cache backends.
"""

from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from enum import Enum
from typing import Literal

from packaging.utils import canonicalize_name
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ConfidenceLevel(str, Enum):
    """Confidence level assigned to verdicts, extracted symbols, and reachability hops."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Verdict(str, Enum):
    """The reachability verdict for a specific advisory against a project."""

    REACHABLE = "REACHABLE"
    NOT_REACHABLE = "NOT_REACHABLE"
    UNCERTAIN = "UNCERTAIN"


class AnalysisMode(str, Enum):
    """Analysis operational mode based on project structure."""

    APP = "app"  # Applications with executable entry points (__main__, CLI, web routes)
    LIBRARY = "library"  # Reusable libraries where all public API members are entry points


class EntryPointType(str, Enum):
    """Classification of root entry points."""

    MAIN = "main"  # if __name__ == '__main__' or top-level script
    CONSOLE_SCRIPT = "console_script"  # Declared in pyproject.toml / setup.cfg
    FASTAPI_ROUTE = "fastapi_route"  # @app.get, @router.post, etc.
    FLASK_ROUTE = "flask_route"  # @app.route
    DJANGO_VIEW = "django_view"  # Django view or URL pattern
    CELERY_TASK = "celery_task"  # @celery.task or @shared_task
    CLI_COMMAND = "cli_command"  # Click / Typer / Argparse commands
    PUBLIC_API = "public_api"  # Library public interface (__all__ or non-underscore)


class SymbolEvidenceSource(str, Enum):
    """Provenance for how an affected symbol was identified."""

    FIX_COMMIT_DIFF = "fix_commit_diff"
    RELEASE_NOTES = "release_notes"
    TAG_DIFF = "tag_diff"
    LLM_FALLBACK = "llm_fallback"
    MANUAL_OVERRIDE = "manual_override"
    ECOSYSTEM_DATABASE = "ecosystem_database"


class SymbolType(str, Enum):
    """Syntactic type of an affected symbol."""

    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    MODULE = "module"


class UncertaintyCategory(str, Enum):
    """Specific category of dynamic or unresolvable construct causing uncertainty."""

    GETATTR_NON_CONSTANT = "getattr_non_constant"
    DYNAMIC_IMPORT = "dynamic_import"
    REFLECTION = "reflection"
    EVAL_EXEC = "eval_exec"
    ENTRY_POINT_PLUGIN = "entry_point_plugin"
    C_EXTENSION = "c_extension"
    MONKEY_PATCH = "monkey_patch"
    DESERIALIZATION = "deserialization"
    CALLBACK_INDIRECT = "callback_indirect"
    IMPRECISE_SYMBOL = "imprecise_symbol"
    UNRESOLVED_CALL_TARGET = "unresolved_call_target"
    UNRESOLVED_ENTRY_POINTS = "unresolved_entry_points"
    MISSING_DEPENDENCY_SOURCE = "missing_dependency_source"
    PLATFORM_WHEEL = "platform_wheel"
    NO_AFFECTED_SYMBOLS = "no_affected_symbols"
    OTHER = "other"


class EntryPoint(BaseModel):
    """Execution root entry point for a project or dependency."""

    model_config = ConfigDict(frozen=True)

    symbol_id: str = Field(description="node_id in the call graph")
    entry_type: EntryPointType
    file_path: str | None = Field(default=None, description="Source file defining the entry point")
    line_number: int | None = Field(default=None, description="Definition line number")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH)
    description: str | None = Field(default=None, description="Additional context")


class FrameworkDiscoveryStatus(BaseModel):
    """Status of entry point discovery for a specific framework or subsystem."""

    model_config = ConfigDict(frozen=True)

    framework: str = Field(description="Framework identifier, e.g. 'fastapi', 'flask', 'main'")
    completed: bool = Field(default=True, description="Whether discovery finished without errors")
    discovered_count: int = Field(default=0, description="Number of entry points discovered")


class PackageParseStats(BaseModel):
    """Parse tracking metrics for a direct or transitive dependency package."""

    model_config = ConfigDict(frozen=True)

    package_name: str = Field(description="PEP 503 normalized package name")
    files_total: int = Field(default=0, description="Total Python files detected in package")
    files_parsed: int = Field(default=0, description="Python files successfully parsed into AST")
    files_failed: int = Field(default=0, description="Python files that failed during parsing")


class AffectedSymbol(BaseModel):
    """A specific symbol (function, method, class, or module) affected by an advisory."""

    model_config = ConfigDict(frozen=True)

    package: str = Field(description="Normalized dependency package name, e.g. 'urllib3'")
    module: str = Field(description="Dotted module path, e.g. 'urllib3.util.ssl_'")
    qualified_name: str = Field(
        description="Full qualified symbol name, e.g. 'urllib3.util.ssl_.create_urllib3_context'"
    )
    symbol_type: SymbolType = Field(default=SymbolType.FUNCTION)
    source_of_evidence: SymbolEvidenceSource = Field(
        description="How this symbol was identified as vulnerable"
    )
    confidence: ConfidenceLevel = Field(
        description="Confidence of this symbol extraction (HIGH for clean commit diff, LOW for LLM)"
    )
    line_start: int | None = Field(default=None, description="Starting line in source file")
    line_end: int | None = Field(default=None, description="Ending line in source file")
    file_path: str | None = Field(
        default=None,
        description="Source file path where the affected symbol was modified or defined",
    )
    diff_hunk: str | None = Field(
        default=None,
        description="Git diff hunk context where changes occurred",
    )
    is_public_api: bool = Field(
        default=True,
        description="Whether this symbol is part of the package's public API or exported in __all__",
    )
    exposed_by_public_callers: list[str] = Field(
        default_factory=list,
        description="If private, package-internal public functions that transitively call this symbol",
    )
    description: str | None = Field(
        default=None,
        description="Additional context regarding the vulnerability in this symbol",
    )


class Advisory(BaseModel):
    """Vulnerability advisory ingested from OSV / PyPA database."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(
        description="Primary identifier, e.g. 'GHSA-q2x7-8rv8-972v' or 'CVE-2021-28363'"
    )
    aliases: list[str] = Field(
        default_factory=list, description="Equivalent CVE or GHSA identifiers"
    )
    package_name: str = Field(description="Normalized target package name")
    ecosystem: str = Field(default="PyPI", description="Ecosystem name")
    summary: str | None = Field(default=None, description="Short summary of the vulnerability")
    details: str | None = Field(default=None, description="Detailed advisory markdown or text")
    affected_ranges: list[str] = Field(
        default_factory=list, description="Version specifiers or ranges"
    )
    fixed_versions: list[str] = Field(
        default_factory=list, description="Explicit versions containing fixes"
    )
    fix_commits: list[str] = Field(
        default_factory=list,
        description="Git commit URLs or SHAs that resolved the vulnerability",
    )
    references: list[str] = Field(default_factory=list, description="All external reference links")
    extracted_symbols: list[AffectedSymbol] = Field(
        default_factory=list,
        description="Vulnerable symbols identified via commit diff or fallback analysis",
    )
    native_fix_detected: bool = Field(
        default=False,
        description="Whether a referenced fix changes native source or extension code",
    )

    def is_version_affected(self, version: str) -> bool:
        """Check if a given version string is affected by this advisory."""
        from packaging.version import InvalidVersion, Version

        try:
            target_v = Version(version)
        except InvalidVersion:
            return True

        if self.fixed_versions:
            for fix in self.fixed_versions:
                try:
                    if target_v >= Version(fix):
                        return False
                except InvalidVersion:
                    continue
        return True


class CallGraphNode(BaseModel):
    """A node in the inter-procedural call graph representing a callable or module."""

    model_config = ConfigDict(frozen=True)

    node_id: str = Field(
        description="Globally unique canonical identifier, e.g. 'myapp.views:process_file' or 'urllib3.poolmanager:PoolManager.urlopen'"
    )
    package: str = Field(description="Package name: local project name or dependency name")
    module: str = Field(description="Dotted module path")
    name: str = Field(description="Unqualified function, method, or class name")
    qualified_name: str = Field(description="Fully-qualified symbol name within module")
    file_path: str | None = Field(default=None, description="Source file path on disk")
    line_number: int | None = Field(
        default=None, description="Line number where symbol is defined"
    )
    is_dependency: bool = Field(default=False, description="True if inside a third-party dependency")
    is_entry_point: bool = Field(
        default=False,
        description="True if this node is an execution root (main, CLI, route, framework hook, package public API)",
    )
    has_dynamic_call: bool = Field(
        default=False,
        description="True if this node contains unresolved dynamic invocations (getattr, eval, etc.)",
    )
    is_native: bool = Field(
        default=False,
        description="True if this node resides in a compiled native extension (.so/.pyd)",
    )


class CallGraphEdge(BaseModel):
    """A directed edge in the call graph from caller to callee."""

    model_config = ConfigDict(frozen=True)

    caller_id: str = Field(description="node_id of caller")
    callee_id: str = Field(description="node_id of callee")
    call_site_file: str | None = Field(default=None, description="File where call occurs")
    call_site_line: int | None = Field(default=None, description="Line number of call site")
    call_type: str = Field(default="direct", description="direct, dynamic, callback, or framework")
    snippet: str | None = Field(default=None, description="Source line code at call site")
    is_dynamic: bool = Field(
        default=False,
        description="Whether call was resolved via constant propagation / reflection",
    )
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH)


class CallHop(BaseModel):
    """A single step in an evidence call path."""

    model_config = ConfigDict(frozen=True)

    symbol: str = Field(description="Qualified name or node_id of callable")
    file_path: str = Field(description="Source file path")
    line_number: int = Field(description="Call site line number")
    call_type: str = Field(
        default="direct", description="direct, dynamic, callback, or framework_hook"
    )
    snippet: str | None = Field(default=None, description="Source line content if available")


class UncertaintyReason(BaseModel):
    """Detailed record of why analysis cannot be soundly proved unreachable."""

    model_config = ConfigDict(frozen=True)

    category: UncertaintyCategory
    location: str = Field(
        description="file:line location of the construct, e.g. 'app/plugins.py:42'"
    )
    details: str = Field(description="Concrete explanation of the ambiguity")
    potential_targets: list[str] = Field(
        default_factory=list,
        description="Candidate target symbols if partially resolved",
    )


class CallGraph(BaseModel):
    """Complete in-memory call graph for project and dependencies."""

    nodes: dict[str, CallGraphNode] = Field(default_factory=dict)
    edges: list[CallGraphEdge] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    entry_points_complete: bool = Field(
        default=False,
        description="Flag set to True only when entry-point discovery has successfully scanned all frameworks",
    )
    framework_statuses: dict[str, FrameworkDiscoveryStatus] = Field(
        default_factory=dict,
        description="Per-framework discovery status tracking",
    )
    registered_packages: set[str] = Field(
        default_factory=set,
        description="PEP 503 normalized package names present in the call graph",
    )
    package_stats: dict[str, PackageParseStats] = Field(
        default_factory=dict,
        description="Per-package AST parse tracking metrics",
    )
    native_modules: set[str] = Field(
        default_factory=set,
        description="Set of dotted module names that are compiled native extensions (.so/.pyd)",
    )
    package_top_levels: dict[str, set[str]] = Field(
        default_factory=dict,
        description="PEP 503 normalized package name -> set of importable top-level module names from wheel top_level.txt/RECORD",
    )
    package_platform_wheels: dict[str, str] = Field(
        default_factory=dict,
        description="Normalized package name -> platform wheel filename if only platform wheels were available",
    )
    package_has_platform_conditionals: set[str] = Field(
        default_factory=set,
        description="Normalized package names containing platform-conditional code (sys.platform/os.name)",
    )
    package_distribution_filenames: dict[str, str] = Field(
        default_factory=dict,
        description="Normalized package name -> archive filename analyzed",
    )
    package_distribution_tags: dict[str, str] = Field(
        default_factory=dict,
        description="Normalized package name -> distribution tag (e.g. py3-none-any, sdist, cp310-macosx)",
    )

    def add_node(self, node: CallGraphNode) -> None:
        self.nodes[node.node_id] = node
        self.registered_packages.add(canonicalize_name(node.package))

    def add_edge(self, edge: CallGraphEdge) -> None:
        self.edges.append(edge)

    def add_entry_point(self, entry_point: EntryPoint) -> None:
        self.entry_points.append(entry_point)
        if entry_point.symbol_id in self.nodes:
            old_node = self.nodes[entry_point.symbol_id]
            self.nodes[entry_point.symbol_id] = CallGraphNode(
                node_id=old_node.node_id,
                package=old_node.package,
                module=old_node.module,
                name=old_node.name,
                qualified_name=old_node.qualified_name,
                file_path=old_node.file_path,
                line_number=old_node.line_number,
                is_dependency=old_node.is_dependency,
                is_entry_point=True,
                has_dynamic_call=old_node.has_dynamic_call,
                is_native=old_node.is_native,
            )

    def record_framework_status(self, framework: str, completed: bool, discovered_count: int = 0) -> None:
        """Record discovery outcome for a specific framework or subsystem."""
        self.framework_statuses[framework] = FrameworkDiscoveryStatus(
            framework=framework,
            completed=completed,
            discovered_count=discovered_count,
        )

    def record_package_stats(
        self, package_name: str, files_total: int, files_parsed: int, files_failed: int
    ) -> None:
        """Record per-package parse metrics using PEP 503 normalized package names."""
        norm_name = canonicalize_name(package_name)
        self.package_stats[norm_name] = PackageParseStats(
            package_name=norm_name,
            files_total=files_total,
            files_parsed=files_parsed,
            files_failed=files_failed,
        )

    def has_confident_entry_points(self) -> bool:
        """Verify whether entry points have been completely and confidently determined.

        Returns True ONLY if:
        1. entry_points_complete is True (detector signaled discovery finished across project),
        2. At least one entry point was registered,
        3. Discovery completed successfully for every detected framework, and
        4. Every registered entry point has HIGH confidence.
        Otherwise returns False, requiring the verdict to be UNCERTAIN (unresolved_entry_points).
        """
        if not self.entry_points_complete:
            return False
        if not self.entry_points:
            return False
        if any(not status.completed for status in self.framework_statuses.values()):
            return False
        return all(ep.confidence == ConfidenceLevel.HIGH for ep in self.entry_points)

    def get_callees(self, caller_id: str) -> list[str]:
        return [e.callee_id for e in self.edges if e.caller_id == caller_id]

    def get_callers(self, callee_id: str) -> list[str]:
        return [e.caller_id for e in self.edges if e.callee_id == callee_id]

    def verify_dependency_chain(self, required_packages: list[str]) -> list[UncertaintyReason]:
        """Check if all required packages in the dependency chain were fetched and parsed cleanly.

        Fails safe with MISSING_DEPENDENCY_SOURCE if:
        - Any package is missing from package_stats or registered_packages,
        - Any Python file failed to parse (files_failed > 0), or
        - The package has zero nodes in the call graph (files_parsed == 0 or node count == 0).
        """
        missing_reasons: list[UncertaintyReason] = []
        for raw_pkg in required_packages:
            norm_pkg = canonicalize_name(raw_pkg)
            stats = self.package_stats.get(norm_pkg)

            if norm_pkg not in self.registered_packages or stats is None:
                missing_reasons.append(
                    UncertaintyReason(
                        category=UncertaintyCategory.MISSING_DEPENDENCY_SOURCE,
                        location=f"package:{raw_pkg}",
                        details=(
                            f"Dependency '{raw_pkg}' (normalized: '{norm_pkg}') was declared in "
                            "manifest/lockfile but was not fetched or registered in the call graph."
                        ),
                    )
                )
                continue

            if stats.files_failed > 0:
                missing_reasons.append(
                    UncertaintyReason(
                        category=UncertaintyCategory.MISSING_DEPENDENCY_SOURCE,
                        location=f"package:{raw_pkg}",
                        details=(
                            f"Dependency '{raw_pkg}' had {stats.files_failed}/{stats.files_total} "
                            "files fail during AST parsing. Failing safe to UNCERTAIN."
                        ),
                    )
                )

            pkg_nodes = [
                n for n in self.nodes.values() if canonicalize_name(n.package) == norm_pkg
            ]
            if len(pkg_nodes) == 0 or stats.files_parsed == 0:
                missing_reasons.append(
                    UncertaintyReason(
                        category=UncertaintyCategory.MISSING_DEPENDENCY_SOURCE,
                        location=f"package:{raw_pkg}",
                        details=(
                            f"Dependency '{raw_pkg}' yielded 0 AST nodes in call graph "
                            f"(files_parsed={stats.files_parsed}, total={stats.files_total}). "
                            "Failing safe to UNCERTAIN."
                        ),
                    )
                )

        return missing_reasons

    def find_shortest_call_path(
        self,
        start_node_id: str,
        target_package: str,
        target_module: str,
        target_qualified_name: str,
    ) -> list[CallHop] | None:
        """Find the shortest directed path from start_node_id to target matching (package, module, qualified_name)."""
        norm_target_pkg = canonicalize_name(target_package)
        target_node_ids = {
            node_id
            for node_id, node in self.nodes.items()
            if canonicalize_name(node.package) == norm_target_pkg
            and node.module == target_module
            and node.qualified_name == target_qualified_name
        }
        if not target_node_ids:
            return None

        adj: dict[str, list[CallGraphEdge]] = {}
        for edge in self.edges:
            adj.setdefault(edge.caller_id, []).append(edge)

        queue: deque[tuple[str, list[CallGraphEdge]]] = deque([(start_node_id, [])])
        visited: set[str] = {start_node_id}

        while queue:
            current, path = queue.popleft()
            if current in target_node_ids:
                hops: list[CallHop] = []
                for edge in path:
                    caller_node = self.nodes.get(edge.caller_id)
                    callee_node = self.nodes.get(edge.callee_id)
                    symbol_repr = callee_node.qualified_name if callee_node else edge.callee_id
                    file_path = (
                        edge.call_site_file
                        or (caller_node.file_path if caller_node else "unknown")
                        or "unknown"
                    )
                    line_no = (
                        edge.call_site_line
                        or (caller_node.line_number if caller_node else 0)
                        or 0
                    )
                    hops.append(
                        CallHop(
                            symbol=symbol_repr,
                            file_path=file_path,
                            line_number=line_no,
                            call_type=edge.call_type,
                            snippet=edge.snippet,
                        )
                    )
                if not hops:
                    target_node = self.nodes.get(current)
                    symbol_repr = target_node.qualified_name if target_node else current
                    file_path = (target_node.file_path or "unknown") if target_node else "unknown"
                    line_no = (target_node.line_number or 0) if target_node else 0
                    hops.append(
                        CallHop(
                            symbol=symbol_repr,
                            file_path=file_path,
                            line_number=line_no,
                            call_type="entry_point",
                            snippet=None,
                        )
                    )
                return hops

            for edge in adj.get(current, []):
                neighbor = edge.callee_id
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, [*path, edge]))

        return None

    def find_shortest_call_path_from_any_entry(
        self,
        target_package: str,
        target_module: str,
        target_qualified_name: str,
    ) -> list[CallHop] | None:
        """Multi-source BFS finding the shortest call path starting from ALL registered entry points."""
        norm_target_pkg = canonicalize_name(target_package)
        target_node_ids = {
            node_id
            for node_id, node in self.nodes.items()
            if canonicalize_name(node.package) == norm_target_pkg
            and node.module == target_module
            and node.qualified_name == target_qualified_name
        }
        if not target_node_ids:
            return None

        entry_ids = {ep.symbol_id for ep in self.entry_points} | {
            n.node_id for n in self.nodes.values() if n.is_entry_point
        }
        if not entry_ids:
            return None

        adj: dict[str, list[CallGraphEdge]] = {}
        for edge in self.edges:
            adj.setdefault(edge.caller_id, []).append(edge)

        # Multi-source BFS: enqueue all entry points with empty initial path
        queue: deque[tuple[str, list[CallGraphEdge]]] = deque([(eid, []) for eid in entry_ids if eid in self.nodes])
        visited: set[str] = set(entry_ids)

        while queue:
            current, path = queue.popleft()
            if current in target_node_ids:
                hops: list[CallHop] = []
                for edge in path:
                    caller_node = self.nodes.get(edge.caller_id)
                    callee_node = self.nodes.get(edge.callee_id)
                    symbol_repr = callee_node.qualified_name if callee_node else edge.callee_id
                    file_path = (
                        edge.call_site_file
                        or (caller_node.file_path if caller_node else "unknown")
                        or "unknown"
                    )
                    line_no = (
                        edge.call_site_line
                        or (caller_node.line_number if caller_node else 0)
                        or 0
                    )
                    hops.append(
                        CallHop(
                            symbol=symbol_repr,
                            file_path=file_path,
                            line_number=line_no,
                            call_type=edge.call_type,
                            snippet=edge.snippet,
                        )
                    )
                if not hops:
                    target_node = self.nodes.get(current)
                    symbol_repr = target_node.qualified_name if target_node else current
                    file_path = (target_node.file_path or "unknown") if target_node else "unknown"
                    line_no = (target_node.line_number or 0) if target_node else 0
                    hops.append(
                        CallHop(
                            symbol=symbol_repr,
                            file_path=file_path,
                            line_number=line_no,
                            call_type="entry_point",
                            snippet=None,
                        )
                    )
                return hops

            for edge in adj.get(current, []):
                neighbor = edge.callee_id
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, [*path, edge]))

        return None


class Finding(BaseModel):
    """Final reachability finding for a single advisory against an installed dependency."""

    advisory_id: str = Field(description="Vulnerability ID (GHSA/CVE)")
    package_name: str = Field(description="Dependency package name")
    installed_version: str = Field(description="Installed version analyzed")
    verdict: Verdict = Field(description="REACHABLE, NOT_REACHABLE, or UNCERTAIN")
    confidence: ConfidenceLevel = Field(description="Confidence of this verdict")
    affected_symbols: list[AffectedSymbol] = Field(
        default_factory=list,
        description="The vulnerable symbols targeted during reachability search",
    )
    call_path: list[CallHop] = Field(
        default_factory=list,
        description="Full call path from project entry point to vulnerable symbol (for REACHABLE)",
    )
    uncertainty_reasons: list[UncertaintyReason] = Field(
        default_factory=list,
        description="List of unresolved dynamic sites or ambiguous points (for UNCERTAIN)",
    )
    distribution_filename: str | None = Field(
        default=None,
        description="Exact wheel or sdist archive filename analyzed from PyPI",
    )
    distribution_tag: str | None = Field(
        default=None,
        description="Distribution tag of analyzed package (e.g. py3-none-any, sdist, cp310-macosx_10_10_x86_64)",
    )
    analysis_timestamp: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    summary: str = Field(description="Human-readable explanation of the verdict")

    @model_validator(mode="after")
    def validate_soundness_and_confidence_invariants(self) -> Finding:
        """Enforce strict soundness rules regarding LLM symbols, entry points, and verdicts."""
        if not self.affected_symbols:
            if self.verdict == Verdict.NOT_REACHABLE:
                raise ValueError(
                    "Soundness violation: NOT_REACHABLE is forbidden with no affected symbols."
                )

        has_llm_symbol = any(
            sym.source_of_evidence == SymbolEvidenceSource.LLM_FALLBACK
            for sym in self.affected_symbols
        )

        if has_llm_symbol:
            # Rule 1: If ANY affected symbol came from LLM fallback, NOT_REACHABLE is forbidden.
            if self.verdict == Verdict.NOT_REACHABLE:
                raise ValueError(
                    "Soundness violation: NOT_REACHABLE is forbidden when any affected symbol "
                    "was derived from LLM fallback. The best negative verdict is UNCERTAIN."
                )
            # Rule 2: LLM symbols may yield REACHABLE, but confidence must be LOW.
            if self.verdict == Verdict.REACHABLE and self.confidence != ConfidenceLevel.LOW:
                raise ValueError(
                    "Confidence violation: REACHABLE findings based on LLM-derived symbols "
                    "must be labeled with LOW confidence."
                )

        if self.verdict == Verdict.NOT_REACHABLE:
            # Rule 3a: NOT_REACHABLE is forbidden if uncertainty_reasons is non-empty
            if self.uncertainty_reasons:
                # Rule 3c: Check specific fatal categories
                fatal_categories = {
                    UncertaintyCategory.MISSING_DEPENDENCY_SOURCE,
                    UncertaintyCategory.UNRESOLVED_ENTRY_POINTS,
                }
                present_fatal = [
                    r.category.value
                    for r in self.uncertainty_reasons
                    if r.category in fatal_categories
                ]
                if present_fatal:
                    raise ValueError(
                        f"Soundness violation: NOT_REACHABLE is forbidden when fatal uncertainty "
                        f"reasons {present_fatal} are present. Best verdict must be UNCERTAIN."
                    )
                raise ValueError(
                    f"Soundness violation: NOT_REACHABLE is forbidden when uncertainty_reasons is non-empty. "
                    f"Found {len(self.uncertainty_reasons)} uncertainty reason(s). Best verdict must be UNCERTAIN."
                )

            # Rule 3b: NOT_REACHABLE must strictly have HIGH confidence
            if self.confidence != ConfidenceLevel.HIGH:
                raise ValueError(
                    f"Soundness violation: NOT_REACHABLE must strictly have HIGH confidence, "
                    f"got '{self.confidence.value}'."
                )

        return self

    def explain(self) -> str:
        """Render the verdict, evidence call path, and uncertainty reasons as formatted plain text."""
        lines: list[str] = []
        lines.append(f"Advisory:  {self.advisory_id} ({self.package_name}=={self.installed_version})")
        lines.append(f"Verdict:   {self.verdict.value} (Confidence: {self.confidence.value})")
        if self.distribution_filename:
            tag_str = f" [tag: {self.distribution_tag}]" if self.distribution_tag else ""
            lines.append(f"Package Dist: {self.distribution_filename}{tag_str}")
        lines.append(f"Summary:   {self.summary}")

        if self.affected_symbols:
            lines.append("\nAffected Symbols Targeted:")
            for sym in self.affected_symbols:
                lines.append(
                    f"  - {sym.qualified_name} [{sym.symbol_type.value}] "
                    f"(Source: {sym.source_of_evidence.value}, Confidence: {sym.confidence.value})"
                )

        if self.call_path:
            lines.append("\nCall Path Evidence:")
            for i, hop in enumerate(self.call_path, 1):
                snippet_str = f" | code: {hop.snippet.strip()}" if hop.snippet else ""
                lines.append(
                    f"  {i}. {hop.symbol} at {hop.file_path}:{hop.line_number} "
                    f"({hop.call_type}){snippet_str}"
                )

        if self.uncertainty_reasons:
            lines.append("\nUncertainty Reasons (Preventing Sound Unreachability Proof):")
            for i, reason in enumerate(self.uncertainty_reasons, 1):
                lines.append(f"  {i}. [{reason.category.value}] at {reason.location}")
                lines.append(f"     Details: {reason.details}")
                if reason.potential_targets:
                    lines.append(f"     Candidate targets: {', '.join(reason.potential_targets)}")

        return "\n".join(lines)


# --- OpenVEX Data Models (OpenVEX v0.2.0 Spec) ---


class VEXProduct(BaseModel):
    """OpenVEX product identifier using Package URL (purl)."""

    model_config = ConfigDict(populate_by_name=True)
    subcomponents: list[str] = Field(default_factory=list)
    identifiers: dict[str, str] = Field(
        default_factory=dict,
        description="Map of identifier schemes, e.g. {'purl': 'pkg:pypi/requests@2.25.0'}",
    )

    @classmethod
    def from_purl(cls, purl: str) -> VEXProduct:
        return cls(identifiers={"purl": purl})


class VEXVulnerability(BaseModel):
    """OpenVEX vulnerability identifier."""

    name: str = Field(description="Primary ID, e.g. CVE-2021-28363")
    aliases: list[str] = Field(default_factory=list)


class VEXStatement(BaseModel):
    """A single OpenVEX statement."""

    vulnerability: VEXVulnerability
    products: list[VEXProduct]
    status: Literal["not_affected", "affected", "under_investigation", "fixed"]
    justification: (
        Literal[
            "component_not_present",
            "vulnerable_code_not_present",
            "vulnerable_code_not_in_execute_path",
            "vulnerable_code_cannot_be_controlled_by_adversary",
            "inline_mitigations_already_exist",
        ]
        | None
    ) = None
    impact_statement: str | None = None
    action_statement: str | None = None
    status_notes: str | None = None
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class OpenVEXDocument(BaseModel):
    """Complete OpenVEX document conforming to OpenVEX v0.2.0."""

    model_config = ConfigDict(populate_by_name=True)

    context: str = Field(default="https://openvex.dev/ns/v0.2.0", alias="@context")
    id: str = Field(
        default_factory=lambda: f"https://pyreach.local/vex/{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}",
        alias="@id",
    )
    author: str = Field(default="pyreach vulnerability reachability analyzer")
    role: str = Field(default="automated-security-tool")
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    version: int = Field(default=1)
    tooling: str = Field(default="pyreach/0.1.0")
    statements: list[VEXStatement] = Field(default_factory=list)

    def to_openvex_json(self, indent: int = 2) -> str:
        """Serialize to OpenVEX compliant JSON."""
        return self.model_dump_json(by_alias=True, indent=indent, exclude_none=True)
