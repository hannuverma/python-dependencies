"""Unified inter-procedural call graph builder spanning project, direct, and transitive dependencies."""

from __future__ import annotations

import ast
from collections import deque
from pathlib import PurePosixPath

from packaging.utils import canonicalize_name

from pyreach.analysis.ast_visitor import ClassHierarchyInfo, ModuleCallGraphVisitor
from pyreach.analysis.imports import ModuleImports, extract_module_imports
from pyreach.models import (
    AffectedSymbol,
    CallGraph,
)


def file_to_module_name(file_path: str, package_name: str) -> str:
    """Normalize file path to dotted module name."""
    p = PurePosixPath(file_path.replace("\\", "/"))
    parts = list(p.parts)
    if parts and parts[0] in ("src", "lib"):
        parts = parts[1:]
    if parts and parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    norm_pkg = canonicalize_name(package_name).replace("-", "_")
    if parts and canonicalize_name(parts[0]).replace("-", "_") == norm_pkg:
        return ".".join(parts)
    return f"{norm_pkg}.{'.'.join(parts)}" if parts else norm_pkg


class CallGraphBuilder:
    """Coordinates parsing of project and dependency sources into a combined CallGraph."""

    def __init__(self) -> None:
        self.all_classes: dict[str, ClassHierarchyInfo] = {}

    def build_graph(
        self,
        project_name: str,
        project_sources: dict[str, str],  # rel_path -> code
        dependency_sources: dict[str, dict[str, str]],  # pkg_name -> {rel_path: code}
    ) -> CallGraph:
        """Parse all sources and construct the unified inter-procedural CallGraph."""
        cg = CallGraph()

        all_packages: dict[str, tuple[dict[str, str], bool]] = {
            project_name: (project_sources, False)
        }
        for dep_pkg, sources in dependency_sources.items():
            all_packages[dep_pkg] = (sources, True)

        # -------------------------------------------------------------------
        # Phase 1: Parse ASTs, track parse stats, and build import / class tables
        # -------------------------------------------------------------------
        parsed_modules: dict[str, tuple[str, str, str, ast.Module, ModuleImports, bool]] = {}

        for pkg_name, (sources, is_dep) in all_packages.items():
            norm_pkg = canonicalize_name(pkg_name)
            files_total = len(sources)
            files_parsed = 0
            files_failed = 0

            for rel_path, code in sources.items():
                mod_name = file_to_module_name(rel_path, norm_pkg)
                try:
                    tree_module = ast.parse(code)
                    imports = extract_module_imports(tree_module, mod_name)
                    parsed_modules[f"{norm_pkg}:{mod_name}"] = (
                        norm_pkg,
                        mod_name,
                        rel_path,
                        tree_module,
                        imports,
                        is_dep,
                    )
                    files_parsed += 1
                except SyntaxError:
                    files_failed += 1

            cg.record_package_stats(
                package_name=norm_pkg,
                files_total=files_total,
                files_parsed=files_parsed,
                files_failed=files_failed,
            )

        # Pre-index all classes, bases, methods, and local definitions across all modules
        module_local_defs: dict[str, set[str]] = {}
        for key, (_p, mod_name, _rel, tree_ast, _imp, _d) in parsed_modules.items():
            local_defs: set[str] = set()
            for ast_item in ast.walk(tree_ast):
                if isinstance(ast_item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    local_defs.add(ast_item.name)
                elif isinstance(ast_item, ast.ClassDef):
                    local_defs.add(ast_item.name)
                    bases: list[str] = []
                    for b in ast_item.bases:
                        if isinstance(b, ast.Name):
                            bases.append(b.id)
                        elif isinstance(b, ast.Attribute) and isinstance(b.value, ast.Name):
                            bases.append(f"{b.value.id}.{b.attr}")
                    cls_info = ClassHierarchyInfo(name=ast_item.name, module=mod_name, bases=bases)
                    for item in ast_item.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            cls_info.methods[item.name] = f"{mod_name}.{ast_item.name}.{item.name}"
                    self.all_classes[f"{mod_name}.{ast_item.name}"] = cls_info
                    self.all_classes[ast_item.name] = cls_info
            module_local_defs[key] = local_defs

        # -------------------------------------------------------------------
        # Phase 2: Visit all parsed modules to build nodes, classes, and call edges
        # -------------------------------------------------------------------
        for (
            key,
            (pkg_str, m_name, file_p, parsed_tree, m_imports, dep_flag),
        ) in parsed_modules.items():
            visitor = ModuleCallGraphVisitor(
                package_name=pkg_str,
                module_name=m_name,
                file_path=file_p,
                imports=m_imports,
                is_dependency=dep_flag,
                all_classes=self.all_classes,
            )
            visitor.local_definitions = module_local_defs.get(key, set())
            visitor.visit(parsed_tree)

            for cg_node in visitor.nodes.values():
                cg.add_node(cg_node)
            for cg_edge in visitor.edges:
                cg.add_edge(cg_edge)

        return cg

    def expand_private_vulnerable_symbols(
        self,
        call_graph: CallGraph,
        affected_symbols: list[AffectedSymbol],
    ) -> list[AffectedSymbol]:
        """For any private vulnerable symbol, compute public API entry points inside the dependency that call it."""
        updated: list[AffectedSymbol] = []

        # Build reverse adjacency list: callee_id -> list[caller_id]
        rev_adj: dict[str, list[str]] = {}
        for edge in call_graph.edges:
            rev_adj.setdefault(edge.callee_id, []).append(edge.caller_id)

        for sym in affected_symbols:
            if sym.is_public_api:
                updated.append(sym)
                continue

            # Target private node_id in call graph
            target_ids = [
                node_id
                for node_id, node in call_graph.nodes.items()
                if canonicalize_name(node.package) == canonicalize_name(sym.package)
                and node.qualified_name == sym.qualified_name
            ]

            if not target_ids:
                updated.append(sym)
                continue

            # Backward BFS to find all public API nodes in this dependency
            public_callers: list[str] = []
            queue: deque[str] = deque(target_ids)
            visited: set[str] = set(target_ids)

            while queue:
                curr = queue.popleft()
                for caller_id in rev_adj.get(curr, []):
                    if caller_id not in visited:
                        visited.add(caller_id)
                        caller_node = call_graph.nodes.get(caller_id)
                        if caller_node and canonicalize_name(caller_node.package) == canonicalize_name(sym.package):
                            # Check if caller is public (name does not start with _)
                            if not caller_node.name.startswith("_") and caller_node.name != "<module>":
                                if caller_node.qualified_name not in public_callers:
                                    public_callers.append(caller_node.qualified_name)
                            queue.append(caller_id)

            updated_sym = AffectedSymbol(
                package=sym.package,
                module=sym.module,
                qualified_name=sym.qualified_name,
                symbol_type=sym.symbol_type,
                source_of_evidence=sym.source_of_evidence,
                confidence=sym.confidence,
                line_start=sym.line_start,
                line_end=sym.line_end,
                file_path=sym.file_path,
                diff_hunk=sym.diff_hunk,
                is_public_api=False,
                exposed_by_public_callers=public_callers,
                description=f"Private symbol exposed by public API callers: {public_callers}",
            )
            updated.append(updated_sym)

        return updated
