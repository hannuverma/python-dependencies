"""Import table and symbol re-export resolution for Python modules."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ImportedSymbol:
    """Target module and symbol name pointed to by an import statement."""

    source_module: str
    symbol_name: str | None = None  # None if module-level import e.g. 'import foo'
    is_star_import: bool = False


@dataclass
class ModuleImports:
    """Collection of imports declared within a single Python file/module."""

    module_name: str
    # local_alias -> ImportedSymbol
    alias_map: dict[str, ImportedSymbol] = field(default_factory=dict)
    star_imports: list[str] = field(default_factory=list)
    exported_all: list[str] = field(default_factory=list)


def resolve_relative_import(current_module: str, level: int, module_part: str | None) -> str:
    """Resolve a relative import (level >= 1) against current dotted module path."""
    parts = current_module.split(".")
    # level=1: same package (pop 1 if current_module is a module inside package)
    strip_count = level
    if strip_count > len(parts):
        base_parts = []
    else:
        base_parts = parts[:-strip_count]

    if module_part:
        base_parts.append(module_part)
    return ".".join(base_parts)


def extract_module_imports(tree: ast.AST, module_name: str) -> ModuleImports:
    """Scan an AST tree to build its ModuleImports table."""
    mod_imports = ModuleImports(module_name=module_name)

    for node in ast.iter_child_nodes(tree):
        # 1. __all__ declaration
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                mod_imports.exported_all.append(elt.value)

        # 2. import x, import x as y
        elif isinstance(node, ast.Import):
            for alias in node.names:
                as_name = alias.asname or alias.name
                mod_imports.alias_map[as_name] = ImportedSymbol(
                    source_module=alias.name,
                    symbol_name=None,
                )

        # 3. from x import y, from . import z, from x import *
        elif isinstance(node, ast.ImportFrom):
            level = node.level or 0
            if level > 0:
                base_module = resolve_relative_import(module_name, level, node.module)
            else:
                base_module = node.module or ""

            for alias in node.names:
                if alias.name == "*":
                    mod_imports.star_imports.append(base_module)
                else:
                    as_name = alias.asname or alias.name
                    mod_imports.alias_map[as_name] = ImportedSymbol(
                        source_module=base_module,
                        symbol_name=alias.name,
                    )

    return mod_imports
