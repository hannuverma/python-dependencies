"""Entry-point detector for applications and libraries across standard Python frameworks."""

from __future__ import annotations

import ast
from pathlib import Path

from pyreach.models import (
    AnalysisMode,
    CallGraph,
    ConfidenceLevel,
    EntryPoint,
    EntryPointType,
)

RECOGNIZED_FRAMEWORKS = {
    "fastapi": EntryPointType.FASTAPI_ROUTE,
    "flask": EntryPointType.FLASK_ROUTE,
    "django": EntryPointType.DJANGO_VIEW,
    "click": EntryPointType.CLI_COMMAND,
    "typer": EntryPointType.CLI_COMMAND,
    "celery": EntryPointType.CELERY_TASK,
}

UNRECOGNIZED_FRAMEWORK_IMPORTS = {
    "tornado", "bottle", "falcon", "pyramid", "sanic", "aiohttp.web", "litestar"
}


class EntryPointDetector:
    """Scans project ASTs to identify and register execution roots."""

    def __init__(self, mode: AnalysisMode = AnalysisMode.APP) -> None:
        self.mode = mode

    def detect_and_register(
        self,
        call_graph: CallGraph,
        project_sources: dict[str, str],  # relative_path -> source_code
        project_root: Path | None = None,
    ) -> bool:
        """Scan project files, register EntryPoint models, and update framework statuses.

        Returns True if discovery completed cleanly across all detected frameworks.
        """
        detected_frameworks: set[str] = set()
        unrecognized_detected: list[str] = []

        # 1. First pass: detect which frameworks are imported across project files
        for file_path, source in project_sources.items():
            try:
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            base = alias.name.split(".")[0]
                            if base in RECOGNIZED_FRAMEWORKS:
                                detected_frameworks.add(base)
                            if base in UNRECOGNIZED_FRAMEWORK_IMPORTS:
                                unrecognized_detected.append(base)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            base = node.module.split(".")[0]
                            if base in RECOGNIZED_FRAMEWORKS:
                                detected_frameworks.add(base)
                            if base in UNRECOGNIZED_FRAMEWORK_IMPORTS:
                                unrecognized_detected.append(base)
            except SyntaxError:
                continue

        # If unrecognized frameworks were imported, discovery cannot be complete
        if unrecognized_detected:
            for unrec in unrecognized_detected:
                call_graph.record_framework_status(framework=unrec, completed=False, discovered_count=0)
            call_graph.entry_points_complete = False

        # 2. Scan for specific framework entry points and __main__ guards
        discovered_per_fw: dict[str, int] = {fw: 0 for fw in detected_frameworks}
        main_discovered = 0

        for file_path, source in project_sources.items():
            mod_name = file_path.replace("\\", "/").replace("/", ".")
            if mod_name.endswith(".py"):
                mod_name = mod_name[:-3]

            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                # A. if __name__ == '__main__':
                if isinstance(node, ast.If):
                    if self._is_main_guard(node.test):
                        main_discovered += 1
                        mod_node_id = f"{mod_name}:<module_init>"
                        call_graph.add_entry_point(
                            EntryPoint(
                                symbol_id=mod_node_id,
                                entry_type=EntryPointType.MAIN,
                                file_path=file_path,
                                line_number=node.lineno,
                                confidence=ConfidenceLevel.HIGH,
                                description="Execution guard: if __name__ == '__main__'",
                            )
                        )
                        # Also register alias <module>
                        call_graph.add_entry_point(
                            EntryPoint(
                                symbol_id=f"{mod_name}:<module>",
                                entry_type=EntryPointType.MAIN,
                                file_path=file_path,
                                line_number=node.lineno,
                                confidence=ConfidenceLevel.HIGH,
                                description="Execution guard: if __name__ == '__main__'",
                            )
                        )

                # B. Decorator-based framework endpoints
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for decorator in node.decorator_list:
                        fw_type = self._classify_decorator(decorator)
                        if fw_type:
                            func_node_id = f"{mod_name}:{node.name}"
                            call_graph.add_entry_point(
                                EntryPoint(
                                    symbol_id=func_node_id,
                                    entry_type=fw_type,
                                    file_path=file_path,
                                    line_number=node.lineno,
                                    confidence=ConfidenceLevel.HIGH,
                                    description=f"Framework registered endpoint: {fw_type.value}",
                                )
                            )
                            # Increment count for that framework
                            for fw_key, mapped_type in RECOGNIZED_FRAMEWORKS.items():
                                if mapped_type == fw_type and fw_key in discovered_per_fw:
                                    discovered_per_fw[fw_key] += 1

                # C. Library mode: all public non-underscore functions/classes are entry points
                if self.mode == AnalysisMode.LIBRARY:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        if not node.name.startswith("_"):
                            pub_node_id = f"{mod_name}:{node.name}"
                            call_graph.add_entry_point(
                                EntryPoint(
                                    symbol_id=pub_node_id,
                                    entry_type=EntryPointType.PUBLIC_API,
                                    file_path=file_path,
                                    line_number=node.lineno,
                                    confidence=ConfidenceLevel.HIGH,
                                    description="Library public API member",
                                )
                            )

        # Record framework discovery statuses
        call_graph.record_framework_status("main", completed=True, discovered_count=main_discovered)
        for fw, count in discovered_per_fw.items():
            call_graph.record_framework_status(fw, completed=True, discovered_count=count)

        # Set entry_points_complete flag if no unrecognized frameworks were imported and entry points exist
        if not unrecognized_detected and len(call_graph.entry_points) > 0:
            call_graph.entry_points_complete = True
            return True
        else:
            call_graph.entry_points_complete = False
            return False

    def _is_main_guard(self, test_expr: ast.expr) -> bool:
        """Check if test_expr represents __name__ == '__main__'."""
        if isinstance(test_expr, ast.Compare):
            left = test_expr.left
            if isinstance(left, ast.Name) and left.id == "__name__":
                for comp in test_expr.comparators:
                    if isinstance(comp, ast.Constant) and comp.value == "__main__":
                        return True
        return False

    def _classify_decorator(self, dec: ast.expr) -> EntryPointType | None:
        """Determine if a decorator matches a known framework endpoint."""
        # @app.get('/'), @router.post('/'), @app.route('/')
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Attribute):
                attr = func.attr.lower()
                if attr in ("get", "post", "put", "delete", "patch", "options", "head"):
                    return EntryPointType.FASTAPI_ROUTE
                if attr == "route":
                    return EntryPointType.FLASK_ROUTE
                if attr == "command":
                    return EntryPointType.CLI_COMMAND
                if attr == "task":
                    return EntryPointType.CELERY_TASK
            elif isinstance(func, ast.Name):
                name = func.id.lower()
                if name in ("shared_task", "task"):
                    return EntryPointType.CELERY_TASK
        elif isinstance(dec, ast.Attribute):
            attr = dec.attr.lower()
            if attr == "command":
                return EntryPointType.CLI_COMMAND
        elif isinstance(dec, ast.Name):
            name = dec.id.lower()
            if name in ("shared_task", "task"):
                return EntryPointType.CELERY_TASK
        return None
