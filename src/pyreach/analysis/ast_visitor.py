"""AST visitor extracting call graph nodes, inheritance hierarchies, and call edges with CHA."""

from __future__ import annotations

import ast

from pyreach.analysis.imports import ModuleImports
from pyreach.models import (
    CallGraphEdge,
    CallGraphNode,
    ConfidenceLevel,
)


class ClassHierarchyInfo:
    """Class definition metadata and base classes for MRO / CHA resolution."""

    def __init__(self, name: str, module: str, bases: list[str]) -> None:
        self.name = name
        self.module = module
        self.bases = bases  # base class names or qualified names
        self.methods: dict[str, str] = {}  # method_name -> qualified_method_name


class ModuleCallGraphVisitor(ast.NodeVisitor):
    """Visits a single module's AST to extract nodes, inheritance, local types, and call edges."""

    def __init__(
        self,
        package_name: str,
        module_name: str,
        file_path: str,
        imports: ModuleImports,
        is_dependency: bool = False,
        all_classes: dict[str, ClassHierarchyInfo] | None = None,
        all_module_imports: dict[str, ModuleImports] | None = None,
    ) -> None:
        self.package_name = package_name
        self.module_name = module_name
        self.file_path = file_path
        self.imports = imports
        self.is_dependency = is_dependency
        self.all_classes = all_classes or {}
        self.all_module_imports = all_module_imports or {}
        self.local_definitions: set[str] = set()

        self.nodes: dict[str, CallGraphNode] = {}
        self.edges: list[CallGraphEdge] = []
        self.classes: dict[str, ClassHierarchyInfo] = {}

        # Scope tracking: stack of node_ids representing current enclosing callable/class
        self.scope_stack: list[str] = []
        # Local variable type inference: var_name -> class_type_name
        self.local_var_types: dict[str, str] = {}
        self.local_constants: dict[str, str] = {}
        self.local_fn_targets: dict[str, str] = {}

        # Create module-level top-level node (<module_init> / <module>)
        mod_node_id = f"{module_name}:<module_init>"
        mod_node = CallGraphNode(
            node_id=mod_node_id,
            package=self.package_name,
            module=self.module_name,
            name="<module_init>",
            qualified_name=self.module_name,
            file_path=self.file_path,
            line_number=1,
            is_dependency=self.is_dependency,
            is_entry_point=not self.is_dependency,
        )
        self.nodes[mod_node_id] = mod_node
        self.nodes[f"{module_name}:<module>"] = mod_node
        self.current_caller_id = mod_node_id

    def _get_current_caller(self) -> str:
        return self.scope_stack[-1] if self.scope_stack else f"{self.module_name}:<module_init>"

    def visit_Import(self, node: ast.Import) -> None:
        caller_id = self._get_current_caller()
        for alias in node.names:
            mod_target = alias.name
            callee_id = f"{mod_target}:<module_init>"
            self.edges.append(
                CallGraphEdge(
                    caller_id=caller_id,
                    callee_id=callee_id,
                    call_site_file=self.file_path,
                    call_site_line=node.lineno,
                    call_type="import",
                    confidence=ConfidenceLevel.HIGH,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        caller_id = self._get_current_caller()
        level = node.level or 0
        if level > 0:
            from pyreach.analysis.imports import resolve_relative_import
            base_mod = resolve_relative_import(self.module_name, level, node.module)
        else:
            base_mod = node.module or ""

        if base_mod:
            self.edges.append(
                CallGraphEdge(
                    caller_id=caller_id,
                    callee_id=f"{base_mod}:<module_init>",
                    call_site_file=self.file_path,
                    call_site_line=node.lineno,
                    call_type="import",
                    confidence=ConfidenceLevel.HIGH,
                )
            )
        for alias in node.names:
            submod = f"{base_mod}.{alias.name}" if base_mod else alias.name
            self.edges.append(
                CallGraphEdge(
                    caller_id=caller_id,
                    callee_id=f"{submod}:<module_init>",
                    call_site_file=self.file_path,
                    call_site_line=node.lineno,
                    call_type="import",
                    confidence=ConfidenceLevel.HIGH,
                )
            )
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases: list[str] = []
        for b in node.bases:
            if isinstance(b, ast.Name):
                bases.append(b.id)
            elif isinstance(b, ast.Attribute) and isinstance(b.value, ast.Name):
                bases.append(f"{b.value.id}.{b.attr}")

        if node.name in self.all_classes:
            class_info = self.all_classes[node.name]
        elif f"{self.module_name}.{node.name}" in self.all_classes:
            class_info = self.all_classes[f"{self.module_name}.{node.name}"]
        else:
            class_info = ClassHierarchyInfo(name=node.name, module=self.module_name, bases=bases)
            self.all_classes[f"{self.module_name}.{node.name}"] = class_info
            self.all_classes[node.name] = class_info
        self.classes[node.name] = class_info

        node_id = f"{self.module_name}:{node.name}"
        self.nodes[node_id] = CallGraphNode(
            node_id=node_id,
            package=self.package_name,
            module=self.module_name,
            name=node.name,
            qualified_name=f"{self.module_name}.{node.name}",
            file_path=self.file_path,
            line_number=node.lineno,
            is_dependency=self.is_dependency,
        )

        self.scope_stack.append(node_id)
        self.generic_visit(node)
        self.scope_stack.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        parent_id = self._get_current_caller()
        parent_is_class = (
            ":" in parent_id
            and not (parent_id.endswith("<module>") or parent_id.endswith("<module_init>"))
            and "." not in parent_id.split(":")[-1]
        )

        if parent_is_class:
            class_name = parent_id.split(":")[-1]
            qname = f"{self.module_name}.{class_name}.{node.name}"
            node_id = f"{self.module_name}:{class_name}.{node.name}"
            if class_name in self.classes:
                self.classes[class_name].methods[node.name] = qname
        else:
            qname = f"{self.module_name}.{node.name}"
            node_id = f"{self.module_name}:{node.name}"

        self.nodes[node_id] = CallGraphNode(
            node_id=node_id,
            package=self.package_name,
            module=self.module_name,
            name=node.name,
            qualified_name=qname,
            file_path=self.file_path,
            line_number=node.lineno,
            is_dependency=self.is_dependency,
        )

        # Handle decorators: in Python, decorators execute at definition time in parent_id
        if node.decorator_list:
            for dec in node.decorator_list:
                dec_id = None
                if isinstance(dec, ast.Name):
                    dec_id = self._resolve_direct_call(dec.id)
                elif isinstance(dec, ast.Attribute):
                    callees = self._resolve_attribute_call(dec.value, dec.attr)
                    if callees:
                        dec_id = callees[0]
                elif isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Name):
                        dec_id = self._resolve_direct_call(dec.func.id)
                    elif isinstance(dec.func, ast.Attribute):
                        callees = self._resolve_attribute_call(dec.func.value, dec.func.attr)
                        if callees:
                            dec_id = callees[0]

                if dec_id:
                    self.edges.append(
                        CallGraphEdge(
                            caller_id=parent_id,
                            callee_id=dec_id,
                            call_site_file=self.file_path,
                            call_site_line=node.lineno,
                            call_type="decorator",
                            confidence=ConfidenceLevel.HIGH,
                        )
                    )
                    self.edges.append(
                        CallGraphEdge(
                            caller_id=dec_id,
                            callee_id=node_id,
                            call_site_file=self.file_path,
                            call_site_line=node.lineno,
                            call_type="callback",
                            confidence=ConfidenceLevel.HIGH,
                        )
                    )
                else:
                    self.edges.append(
                        CallGraphEdge(
                            caller_id=parent_id,
                            callee_id=node_id,
                            call_site_file=self.file_path,
                            call_site_line=node.lineno,
                            call_type="callback",
                            confidence=ConfidenceLevel.MEDIUM,
                        )
                    )

        self.scope_stack.append(node_id)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # 1. Track constant string assignments: fn_name = 'vuln_dynamic_op'
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.local_constants[t.id] = node.value.value

        # 2. Track getattr assignments: fn = getattr(module, attr_expr)
        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "getattr":
            if len(node.value.args) >= 2:
                rec_arg = node.value.args[0]
                attr_arg = node.value.args[1]
                const_name = None
                if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                    const_name = attr_arg.value
                elif isinstance(attr_arg, ast.Name) and attr_arg.id in self.local_constants:
                    const_name = self.local_constants[attr_arg.id]

                if const_name:
                    callees: list[str] = []
                    if isinstance(rec_arg, ast.Name):
                        if rec_arg.id in self.imports.alias_map:
                            callees.append(f"{self.imports.alias_map[rec_arg.id].source_module}:{const_name}")
                        else:
                            callees.append(f"{rec_arg.id}:{const_name}")
                    elif isinstance(rec_arg, ast.Attribute):
                        for base in self._resolve_attribute_call(rec_arg.value, rec_arg.attr):
                            callees.append(f"{base}.{const_name}")
                    for t in node.targets:
                        if isinstance(t, ast.Name) and callees:
                            self.local_fn_targets[t.id] = callees[0]

        # 3. Simple local type inference: x = ClassName() or x = module.ClassName()
        if isinstance(node.value, ast.Call):
            target_type: str | None = None
            if isinstance(node.value.func, ast.Name):
                target_type = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name):
                target_type = f"{node.value.func.value.id}.{node.value.func.attr}"

            if target_type:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.local_var_types[t.id] = target_type

        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        caller_id = self._get_current_caller()
        call_line = node.lineno
        for item in node.items:
            # In Python, with expr executes expr.__enter__() and expr.__exit__()
            callees: list[str] = []
            ctx_expr = item.context_expr
            if isinstance(ctx_expr, ast.Call):
                func = ctx_expr.func
                if isinstance(func, ast.Name):
                    c = self._resolve_direct_call(func.id)
                    if c:
                        callees.append(c)
                elif isinstance(func, ast.Attribute):
                    callees.extend(self._resolve_attribute_call(func.value, func.attr))
            elif isinstance(ctx_expr, ast.Name):
                c = self._resolve_direct_call(ctx_expr.id)
                if c:
                    callees.append(c)
            elif isinstance(ctx_expr, ast.Attribute):
                callees.extend(self._resolve_attribute_call(ctx_expr.value, ctx_expr.attr))

            for callee in callees:
                for method in ("__enter__", "__exit__"):
                    self.edges.append(
                        CallGraphEdge(
                            caller_id=caller_id,
                            callee_id=f"{callee}.{method}",
                            call_site_file=self.file_path,
                            call_site_line=call_line,
                            call_type="context_manager",
                            confidence=ConfidenceLevel.HIGH,
                        )
                    )

            if isinstance(item.context_expr, ast.Call) and item.optional_vars:
                if isinstance(item.optional_vars, ast.Name):
                    func = item.context_expr.func
                    if isinstance(func, ast.Name):
                        self.local_var_types[item.optional_vars.id] = func.id
                    elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                        self.local_var_types[item.optional_vars.id] = f"{func.value.id}.{func.attr}"
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        caller_id = self._get_current_caller()
        call_line = node.lineno
        func = node.func

        # 1. Direct call: func_name()
        if isinstance(func, ast.Name):
            callee_name = func.id
            callee_id = self._resolve_direct_call(callee_name)
            if callee_id:
                self.edges.append(
                    CallGraphEdge(
                        caller_id=caller_id,
                        callee_id=callee_id,
                        call_site_file=self.file_path,
                        call_site_line=call_line,
                        call_type="direct",
                        confidence=ConfidenceLevel.HIGH,
                    )
                )

        # 2. Attribute call: obj.method() or module.func()
        elif isinstance(func, ast.Attribute):
            attr_name = func.attr
            callee_ids = self._resolve_attribute_call(func.value, attr_name)
            for callee_id in callee_ids:
                self.edges.append(
                    CallGraphEdge(
                        caller_id=caller_id,
                        callee_id=callee_id,
                        call_site_file=self.file_path,
                        call_site_line=call_line,
                        call_type="direct",
                        confidence=ConfidenceLevel.HIGH,
                    )
                )

        # 3. Callbacks passed as arguments: register(callback=fn), do_work(fn), or dispatch(pkg.callback)
        for arg in [*node.args, *(kw.value for kw in node.keywords if kw.value)]:
            if isinstance(arg, ast.Name):
                cb_callee = self._resolve_direct_call(arg.id)
                if cb_callee:
                    self.edges.append(
                        CallGraphEdge(
                            caller_id=caller_id,
                            callee_id=cb_callee,
                            call_site_file=self.file_path,
                            call_site_line=call_line,
                            call_type="callback",
                            confidence=ConfidenceLevel.MEDIUM,
                        )
                    )
            elif isinstance(arg, ast.Attribute):
                cb_callees = self._resolve_attribute_call(arg.value, arg.attr)
                for cb in cb_callees:
                    self.edges.append(
                        CallGraphEdge(
                            caller_id=caller_id,
                            callee_id=cb,
                            call_site_file=self.file_path,
                            call_site_line=call_line,
                            call_type="callback",
                            confidence=ConfidenceLevel.MEDIUM,
                        )
                    )

        self.generic_visit(node)

    def _resolve_direct_call(self, name: str) -> str | None:
        """Resolve a direct function call locally or via imports."""
        # 0. Check local function targets from constant reflection (fn = getattr(mod, 'name'))
        if name in self.local_fn_targets:
            return self.local_fn_targets[name]

        # 1. Check local module definitions (including forward references)
        if name in self.local_definitions or f"{self.module_name}:{name}" in self.nodes:
            return f"{self.module_name}:{name}"

        # 2. Check import table
        if name in self.imports.alias_map:
            imp = self.imports.alias_map[name]
            target_mod = imp.source_module
            target_sym = imp.symbol_name or name

            # Follow transitive re-exports across packages and modules
            if self.all_module_imports:
                visited_aliases: set[str] = set()
                while target_mod in self.all_module_imports:
                    alias_key = f"{target_mod}:{target_sym}"
                    if alias_key in visited_aliases:
                        break
                    visited_aliases.add(alias_key)
                    mod_imp = self.all_module_imports[target_mod]
                    if target_sym in mod_imp.alias_map:
                        reexport = mod_imp.alias_map[target_sym]
                        target_mod = reexport.source_module
                        target_sym = reexport.symbol_name or target_sym
                    else:
                        break

            return f"{target_mod}:{target_sym}"

        return None

    def _expr_to_dotted_name(self, expr: ast.expr) -> str | None:
        """Convert a Name or chained Attribute expression into a dotted name string."""
        parts: list[str] = []
        curr = expr
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
            return ".".join(reversed(parts))
        return None

    def _resolve_attribute_call(self, receiver: ast.expr, attr_name: str) -> list[str]:
        """Resolve obj.attr() using local type inference or Class Hierarchy Analysis (CHA)."""
        obj_name = self._expr_to_dotted_name(receiver)

        # A. Receiver is a Name or Dotted Attribute chain: obj.attr()
        if obj_name:
            # Case A0: Receiver is 'self' -> look up in enclosing class and base classes
            if obj_name == "self":
                # Find enclosing class in scope_stack
                for scope in reversed(self.scope_stack):
                    # Check if scope is class or method of class
                    class_name = scope.split(":")[-1].split(".")[0]
                    cls_info = self.classes.get(class_name) or self.all_classes.get(class_name)
                    if cls_info and attr_name in cls_info.methods:
                        return [f"{cls_info.module}:{cls_info.name}.{attr_name}"]
                    # Check base classes recursively
                    if cls_info:
                        for base in cls_info.bases:
                            base_key = base.split(".")[-1]
                            base_info = self.all_classes.get(base) or self.all_classes.get(base_key)
                            if base_info and attr_name in base_info.methods:
                                return [f"{base_info.module}:{base_info.name}.{attr_name}"]

            # Case A1: Receiver is directly an imported module or alias: urllib3.util.parse_url()
            if obj_name in self.imports.alias_map:
                imp = self.imports.alias_map[obj_name]
                if imp.symbol_name is None:
                    # receiver is a module
                    target_module = imp.source_module
                    return [f"{target_module}:{attr_name}"]
                else:
                    # receiver could be an imported submodule (from PIL import ImageMath -> ImageMath.eval)
                    # or an imported class/object (from mymod import MyClass -> MyClass.method)
                    target_module = imp.source_module
                    target_class = imp.symbol_name
                    submodule_target = f"{target_module}.{target_class}:{attr_name}"
                    class_target = f"{target_module}:{target_class}.{attr_name}"
                    return [submodule_target, class_target]

            # Case A1b: Dotted prefix matches an imported module or alias:
            # e.g. 'import urllib3; urllib3.util.url.parse_url()'
            parts = obj_name.split(".")
            if len(parts) > 1 and parts[0] in self.imports.alias_map:
                imp = self.imports.alias_map[parts[0]]
                base_mod = f"{imp.source_module}.{imp.symbol_name}" if imp.symbol_name else imp.source_module
                sub_path = ".".join(parts[1:])
                resolved_mod = f"{base_mod}.{sub_path}"
                return [f"{resolved_mod}:{attr_name}"]

            # Case A2: Receiver has inferred local type: client = PoolManager(); client.urlopen()
            if obj_name in self.local_var_types:
                type_name = self.local_var_types[obj_name]
                # Check if type_name was imported
                if type_name in self.imports.alias_map:
                    imp = self.imports.alias_map[type_name]
                    target_module = imp.source_module
                    target_class = imp.symbol_name or type_name
                    return [f"{target_module}:{target_class}.{attr_name}"]
                return [f"{self.module_name}:{type_name}.{attr_name}"]

        # Case B: Class Hierarchy Analysis (CHA) Over-approximation
        # When receiver type is ambiguous, search all candidate classes that define attr_name
        candidate_ids: list[str] = []
        for class_qname, class_info in self.all_classes.items():
            if attr_name in class_info.methods:
                callee = f"{class_info.module}:{class_info.name}.{attr_name}"
                if callee not in candidate_ids:
                    candidate_ids.append(callee)

        return candidate_ids
