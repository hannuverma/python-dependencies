"""Static analysis, AST traversal, entry point detection, and call graph construction."""

from pyreach.analysis.ast_visitor import ClassHierarchyInfo, ModuleCallGraphVisitor
from pyreach.analysis.callgraph_builder import CallGraphBuilder
from pyreach.analysis.dynamic import DynamicFeatureClassifier, DynamicSite, NamespaceTouchAuditor
from pyreach.analysis.entry_points import EntryPointDetector
from pyreach.analysis.imports import ModuleImports, extract_module_imports
from pyreach.analysis.reachability import ReachabilityEngine

__all__ = [
    "ModuleImports",
    "extract_module_imports",
    "ClassHierarchyInfo",
    "ModuleCallGraphVisitor",
    "EntryPointDetector",
    "CallGraphBuilder",
    "ReachabilityEngine",
    "DynamicSite",
    "DynamicFeatureClassifier",
    "NamespaceTouchAuditor",
]
