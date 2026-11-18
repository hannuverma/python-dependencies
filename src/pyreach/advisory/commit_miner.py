"""Maps diff hunks to enclosing AST symbols in the pre-fix version of Python files."""

from __future__ import annotations

import ast
from pathlib import PurePosixPath
from typing import Any

from packaging.utils import canonicalize_name

from pyreach.advisory.diff_parser import FileDiff
from pyreach.models import (
    AffectedSymbol,
    ConfidenceLevel,
    SymbolEvidenceSource,
    SymbolType,
)


def normalize_module_path(file_path: str, package_name: str) -> str:
    """Convert file path into a dotted Python module path matching package namespace."""
    p = PurePosixPath(file_path.replace("\\", "/"))
    parts = list(p.parts)

    # Strip top-level source folders like 'src', 'lib', or package root variations
    if parts and parts[0] in ("src", "lib"):
        parts = parts[1:]

    # Remove .py or __init__.py extension
    if parts and parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]

    # Ensure module starts with package name if known
    norm_pkg = canonicalize_name(package_name).replace("-", "_")
    if parts and canonicalize_name(parts[0]).replace("-", "_") == norm_pkg:
        return ".".join(parts)
    return f"{norm_pkg}.{'.'.join(parts)}" if parts else norm_pkg


class ASTSymbolLocator(ast.NodeVisitor):
    """Locates enclosing functions, methods, and classes for specific line ranges."""

    def __init__(self, module_name: str) -> None:
        self.module_name = module_name
        self.scope_stack: list[dict[str, Any]] = []
        self.symbols: list[dict[str, Any]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        parent_scope = ".".join(s["name"] for s in self.scope_stack)
        qname = f"{parent_scope}.{node.name}" if parent_scope else node.name
        full_qname = f"{self.module_name}.{qname}"

        end_line = getattr(node, "end_lineno", node.lineno)
        entry = {
            "name": node.name,
            "qualified_name": full_qname,
            "symbol_type": SymbolType.CLASS,
            "line_start": node.lineno,
            "line_end": end_line,
            "is_public": not node.name.startswith("_"),
        }
        self.symbols.append(entry)
        self.scope_stack.append({"name": node.name, "type": "class"})
        self.generic_visit(node)
        self.scope_stack.pop()

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        parent_classes = [s["name"] for s in self.scope_stack if s["type"] == "class"]
        is_method = len(parent_classes) > 0
        parent_scope = ".".join(s["name"] for s in self.scope_stack)
        qname = f"{parent_scope}.{node.name}" if parent_scope else node.name
        full_qname = f"{self.module_name}.{qname}"

        end_line = getattr(node, "end_lineno", node.lineno)
        entry = {
            "name": node.name,
            "qualified_name": full_qname,
            "symbol_type": SymbolType.METHOD if is_method else SymbolType.FUNCTION,
            "line_start": node.lineno,
            "line_end": end_line,
            "is_public": not node.name.startswith("_"),
        }
        self.symbols.append(entry)
        self.scope_stack.append({"name": node.name, "type": "function"})
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)


class CommitMiner:
    """Extracts vulnerable symbols by analyzing pre-fix source code and diff hunks."""

    def __init__(self, package_name: str) -> None:
        self.package_name = canonicalize_name(package_name)

    def mine_file_diff(
        self,
        file_diff: FileDiff,
        pre_fix_source: str,
        evidence_source: SymbolEvidenceSource = SymbolEvidenceSource.FIX_COMMIT_DIFF,
    ) -> list[AffectedSymbol]:
        """Map changed line ranges in a FileDiff to enclosing AST symbols in pre_fix_source."""
        target_path = file_diff.old_path or file_diff.new_path
        module_name = normalize_module_path(target_path, self.package_name)

        try:
            tree = ast.parse(pre_fix_source)
        except SyntaxError:
            # If pre-fix file cannot be parsed, report the module as affected at MEDIUM confidence
            hunk_sample = file_diff.hunks[0].hunk_text if file_diff.hunks else None
            return [
                AffectedSymbol(
                    package=self.package_name,
                    module=module_name,
                    qualified_name=module_name,
                    symbol_type=SymbolType.MODULE,
                    source_of_evidence=evidence_source,
                    confidence=ConfidenceLevel.MEDIUM,
                    file_path=target_path,
                    diff_hunk=hunk_sample,
                    description="Pre-fix source failed AST parse; falling back to module scope.",
                )
            ]

        locator = ASTSymbolLocator(module_name)
        locator.visit(tree)

        extracted: list[AffectedSymbol] = []
        seen_symbols: set[str] = set()

        for hunk in file_diff.hunks:
            hunk_matched = False
            for line_no in hunk.changed_pre_lines:
                # Find the innermost symbol enclosing this changed line
                enclosing = [
                    s for s in locator.symbols
                    if s["line_start"] <= line_no <= s["line_end"]
                ]
                if enclosing:
                    # Sort by span length ascending to pick the innermost symbol
                    enclosing.sort(key=lambda s: s["line_end"] - s["line_start"])
                    target = enclosing[0]
                    qname = target["qualified_name"]
                    if qname not in seen_symbols:
                        seen_symbols.add(qname)
                        extracted.append(
                            AffectedSymbol(
                                package=self.package_name,
                                module=module_name,
                                qualified_name=qname,
                                symbol_type=target["symbol_type"],
                                source_of_evidence=evidence_source,
                                confidence=ConfidenceLevel.HIGH,
                                line_start=target["line_start"],
                                line_end=target["line_end"],
                                file_path=target_path,
                                diff_hunk=hunk.hunk_text,
                                is_public_api=target["is_public"],
                                description=f"Enclosing {target['symbol_type'].value} for modified line {line_no}",
                            )
                        )
                    hunk_matched = True

            # If changed lines are outside all functions/classes (module level)
            if not hunk_matched:
                if module_name not in seen_symbols:
                    seen_symbols.add(module_name)
                    extracted.append(
                        AffectedSymbol(
                            package=self.package_name,
                            module=module_name,
                            qualified_name=module_name,
                            symbol_type=SymbolType.MODULE,
                            source_of_evidence=evidence_source,
                            confidence=ConfidenceLevel.MEDIUM,
                            file_path=target_path,
                            diff_hunk=hunk.hunk_text,
                            is_public_api=True,
                            description="Module-level changes outside function/class scopes.",
                        )
                    )

        return extracted
