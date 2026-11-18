"""Dynamic feature classification and namespace touch auditor implementing docs/architecture.md."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from packaging.utils import canonicalize_name

from pyreach.analysis.imports import ModuleImports
from pyreach.models import (
    CallGraphEdge,
    ConfidenceLevel,
    UncertaintyCategory,
    UncertaintyReason,
)


@dataclass(frozen=True)
class DynamicSite:
    """A detected dynamic Python construct."""

    file_path: str
    line_number: int
    category: UncertaintyCategory
    enclosing_module: str
    receiver_expr: str | None = None
    attribute_expr: str | None = None
    is_constant: bool = False
    resolved_target: str | None = None
    imported_packages_in_scope: tuple[str, ...] = field(default_factory=tuple)


class DynamicFeatureClassifier(ast.NodeVisitor):
    """AST visitor detecting dynamic language constructs and resolving constant cases."""

    def __init__(self, file_path: str, module_name: str, imports: ModuleImports) -> None:
        self.file_path = file_path
        self.module_name = module_name
        self.imports = imports
        self.dynamic_sites: list[DynamicSite] = []
        self.resolved_edges: list[CallGraphEdge] = []
        self.current_caller_id = f"{module_name}:<module>"
        self.scope_stack: list[str] = [self.current_caller_id]

        # Extract imported packages in this file's scope
        self.imported_packages = tuple(sorted({
            canonicalize_name(imp.source_module.split(".")[0])
            for imp in imports.alias_map.values()
        }))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        func_id = f"{self.module_name}:{node.name}"
        self.scope_stack.append(func_id)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        func_id = f"{self.module_name}:{node.name}"
        self.scope_stack.append(func_id)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        class_id = f"{self.module_name}:{node.name}"
        self.scope_stack.append(class_id)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check for monkey patching: target_mod.func = my_replacement or target_cls.method = patch
        for target in node.targets:
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                receiver = target.value.id
                attr = target.attr
                # If receiver is an imported module/class from another package -> MONKEY PATCH
                if receiver in self.imports.alias_map:
                    imp = self.imports.alias_map[receiver]
                    self.dynamic_sites.append(
                        DynamicSite(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            category=UncertaintyCategory.MONKEY_PATCH,
                            enclosing_module=self.module_name,
                            receiver_expr=f"{imp.source_module}.{imp.symbol_name or receiver}",
                            attribute_expr=attr,
                            is_constant=True,
                            imported_packages_in_scope=self.imported_packages,
                        )
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        caller_id = self.scope_stack[-1]

        # 1. getattr(obj, name, [default]), setattr(obj, name, val), hasattr(obj, name)
        if isinstance(func, ast.Name) and func.id in ("getattr", "setattr", "hasattr"):
            if len(node.args) >= 2:
                rec_expr = ast.unparse(node.args[0]) if hasattr(ast, "unparse") else str(node.args[0])
                attr_arg = node.args[1]

                if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                    # Constant resolvable attribute
                    const_attr = attr_arg.value
                    self.dynamic_sites.append(
                        DynamicSite(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            category=UncertaintyCategory.REFLECTION,
                            enclosing_module=self.module_name,
                            receiver_expr=rec_expr,
                            attribute_expr=const_attr,
                            is_constant=True,
                            resolved_target=const_attr,
                            imported_packages_in_scope=self.imported_packages,
                        )
                    )
                    # Create medium-confidence edge if receiver was imported
                    if rec_expr in self.imports.alias_map:
                        imp = self.imports.alias_map[rec_expr]
                        callee_mod = imp.source_module
                        self.resolved_edges.append(
                            CallGraphEdge(
                                caller_id=caller_id,
                                callee_id=f"{callee_mod}:{const_attr}",
                                call_site_file=self.file_path,
                                call_site_line=node.lineno,
                                is_dynamic=True,
                                confidence=ConfidenceLevel.MEDIUM,
                            )
                        )
                else:
                    # Non-constant getattr/setattr/hasattr
                    attr_expr = ast.unparse(attr_arg) if hasattr(ast, "unparse") else str(attr_arg)
                    self.dynamic_sites.append(
                        DynamicSite(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            category=UncertaintyCategory.GETATTR_NON_CONSTANT,
                            enclosing_module=self.module_name,
                            receiver_expr=rec_expr,
                            attribute_expr=attr_expr,
                            is_constant=False,
                            imported_packages_in_scope=self.imported_packages,
                        )
                    )

        # 2. importlib.import_module(name) or __import__(name)
        elif (
            (isinstance(func, ast.Attribute) and func.attr == "import_module")
            or (isinstance(func, ast.Name) and func.id == "__import__")
        ):
            if node.args:
                arg0 = node.args[0]
                if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                    mod_target = arg0.value
                    self.dynamic_sites.append(
                        DynamicSite(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            category=UncertaintyCategory.DYNAMIC_IMPORT,
                            enclosing_module=self.module_name,
                            attribute_expr=mod_target,
                            is_constant=True,
                            resolved_target=f"{mod_target}:<module>",
                            imported_packages_in_scope=self.imported_packages,
                        )
                    )
                    self.resolved_edges.append(
                        CallGraphEdge(
                            caller_id=caller_id,
                            callee_id=f"{mod_target}:<module>",
                            call_site_file=self.file_path,
                            call_site_line=node.lineno,
                            is_dynamic=True,
                            confidence=ConfidenceLevel.MEDIUM,
                        )
                    )
                else:
                    arg_expr = ast.unparse(arg0) if hasattr(ast, "unparse") else str(arg0)
                    self.dynamic_sites.append(
                        DynamicSite(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            category=UncertaintyCategory.DYNAMIC_IMPORT,
                            enclosing_module=self.module_name,
                            attribute_expr=arg_expr,
                            is_constant=False,
                            imported_packages_in_scope=self.imported_packages,
                        )
                    )

        # 3. eval() and exec()
        elif isinstance(func, ast.Name) and func.id in ("eval", "exec"):
            self.dynamic_sites.append(
                DynamicSite(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    category=UncertaintyCategory.EVAL_EXEC,
                    enclosing_module=self.module_name,
                    receiver_expr=func.id,
                    is_constant=False,
                    imported_packages_in_scope=self.imported_packages,
                )
            )

        # 4. Deserialization: pickle.loads, yaml.load, yaml.unsafe_load
        elif isinstance(func, ast.Attribute):
            rec_str = ast.unparse(func.value) if hasattr(ast, "unparse") else ""
            if "pickle" in rec_str and func.attr in ("load", "loads"):
                self.dynamic_sites.append(
                    DynamicSite(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        category=UncertaintyCategory.DESERIALIZATION,
                        enclosing_module=self.module_name,
                        receiver_expr=f"{rec_str}.{func.attr}",
                        is_constant=False,
                        imported_packages_in_scope=self.imported_packages,
                    )
                )
            elif "yaml" in rec_str and func.attr in ("load", "unsafe_load"):
                self.dynamic_sites.append(
                    DynamicSite(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        category=UncertaintyCategory.DESERIALIZATION,
                        enclosing_module=self.module_name,
                        receiver_expr=f"{rec_str}.{func.attr}",
                        is_constant=False,
                        imported_packages_in_scope=self.imported_packages,
                    )
                )
            elif func.attr in ("entry_points", "iter_entry_points"):
                self.dynamic_sites.append(
                    DynamicSite(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        category=UncertaintyCategory.ENTRY_POINT_PLUGIN,
                        enclosing_module=self.module_name,
                        receiver_expr=rec_str,
                        is_constant=False,
                        imported_packages_in_scope=self.imported_packages,
                    )
                )

        # 5. Direct entry_points() or iter_entry_points() calls
        elif isinstance(func, ast.Name) and func.id in ("entry_points", "iter_entry_points"):
            self.dynamic_sites.append(
                DynamicSite(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    category=UncertaintyCategory.ENTRY_POINT_PLUGIN,
                    enclosing_module=self.module_name,
                    receiver_expr=func.id,
                    is_constant=False,
                    imported_packages_in_scope=self.imported_packages,
                )
            )

        self.generic_visit(node)


class NamespaceTouchAuditor:
    """Audits whether an unresolved dynamic site touches a target package's namespace per docs/architecture.md."""

    @staticmethod
    def touches_namespace(site: DynamicSite, target_package: str) -> tuple[bool, str]:
        """Check Conditions A, B, and C for target_package.

        Returns (True, reason) if site touches the namespace, else (False, "").
        """
        norm_target = canonicalize_name(target_package)

        # If site was cleanly resolved to a constant safe target, it doesn't cause uncertainty
        if site.is_constant and site.category not in (
            UncertaintyCategory.MONKEY_PATCH,
        ):
            return False, ""

        # 0. Monkey patching check (specifically targets receiver package)
        if site.category == UncertaintyCategory.MONKEY_PATCH and site.receiver_expr:
            norm_rec = canonicalize_name(site.receiver_expr.split(".")[0])
            if norm_rec == norm_target or norm_target in site.receiver_expr.lower():
                return (
                    True,
                    f"Monkey patching detected targeting package '{target_package}': "
                    f"{site.receiver_expr}.{site.attribute_expr}",
                )
            return False, ""

        # -------------------------------------------------------------------
        # Condition A: Import or Re-export Scope Reachability
        # -------------------------------------------------------------------
        # A1: Target package is imported in the same file/scope
        if norm_target in site.imported_packages_in_scope:
            return (
                True,
                f"Condition A triggered: Package '{target_package}' is imported in module "
                f"'{site.enclosing_module}' containing dynamic construct '{site.category.value}'.",
            )

        # A2: Dynamic import with non-constant string that could resolve to target package
        if site.category == UncertaintyCategory.DYNAMIC_IMPORT and not site.is_constant:
            return (
                True,
                f"Condition A triggered: Non-constant dynamic import '{site.attribute_expr}' "
                f"in '{site.enclosing_module}' could resolve to package '{target_package}'.",
            )

        # -------------------------------------------------------------------
        # Condition B: Object Origin and Dataflow Taint
        # -------------------------------------------------------------------
        # Receiver explicitly names or references target package
        if site.receiver_expr:
            norm_rec = canonicalize_name(site.receiver_expr.split(".")[0])
            if norm_rec == norm_target or norm_target in site.receiver_expr.lower():
                return (
                    True,
                    f"Condition B triggered: Receiver '{site.receiver_expr}' originates from "
                    f"vulnerable package '{target_package}'.",
                )

        # -------------------------------------------------------------------
        # Condition C: Non-Constant Reflection on Target Namespace
        # -------------------------------------------------------------------
        if site.category == UncertaintyCategory.GETATTR_NON_CONSTANT:
            if site.receiver_expr and (
                norm_target in site.receiver_expr.lower() or site.receiver_expr in site.imported_packages_in_scope
            ):
                return (
                    True,
                    f"Condition C triggered: Non-constant getattr on receiver '{site.receiver_expr}' "
                    f"touching '{target_package}' namespace with attribute '{site.attribute_expr}'.",
                )

        # Monkey patching specifically targeting target package
        if site.category == UncertaintyCategory.MONKEY_PATCH and site.receiver_expr:
            if norm_target in site.receiver_expr.lower() or site.receiver_expr.split(".")[0] in site.imported_packages_in_scope:
                return (
                    True,
                    f"Monkey patching detected targeting package '{target_package}': "
                    f"{site.receiver_expr}.{site.attribute_expr}",
                )

        # Plugin loading via entry_points() touches any installed package providing plugins
        if site.category == UncertaintyCategory.ENTRY_POINT_PLUGIN:
            return (
                True,
                f"Condition A/C triggered: Dynamic plugin loader entry_points() could load "
                f"plugins registered by package '{target_package}'.",
            )

        # Untrusted deserialization or eval/exec in scope importing target package
        if site.category in (UncertaintyCategory.EVAL_EXEC, UncertaintyCategory.DESERIALIZATION):
            if norm_target in site.imported_packages_in_scope:
                return (
                    True,
                    f"Dynamic code execution/deserialization '{site.category.value}' in scope "
                    f"importing '{target_package}'.",
                )

        # Provably disjoint: dynamic site does NOT touch target package
        return False, ""

    @classmethod
    def audit_dynamic_sites_for_alert(
        cls,
        sites: list[DynamicSite],
        target_package: str,
    ) -> list[UncertaintyReason]:
        """Audit all dynamic sites and return UncertaintyReasons for those touching target_package."""
        reasons: list[UncertaintyReason] = []
        for s in sites:
            touches, explanation = cls.touches_namespace(s, target_package)
            if touches:
                reasons.append(
                    UncertaintyReason(
                        category=s.category,
                        location=f"{s.file_path}:{s.line_number}",
                        details=explanation,
                        potential_targets=[s.attribute_expr] if s.attribute_expr else [],
                    )
                )
        return reasons
