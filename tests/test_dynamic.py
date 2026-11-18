"""Unit tests for Stage 5: Dynamic feature classification and namespace touch auditing."""

import ast

from pyreach.analysis.dynamic import (
    DynamicFeatureClassifier,
    NamespaceTouchAuditor,
)
from pyreach.analysis.imports import extract_module_imports
from pyreach.models import UncertaintyCategory


def test_unrelated_getattr_does_not_poison_target_alert() -> None:
    """An unresolved getattr on an unrelated package does NOT touch urllib3 namespace."""
    code = """import json

def parse_data(custom_obj, field):
    return getattr(custom_obj, field)
"""
    tree = ast.parse(code)
    imports = extract_module_imports(tree, "app.utils")
    classifier = DynamicFeatureClassifier("app/utils.py", "app.utils", imports)
    classifier.visit(tree)

    assert len(classifier.dynamic_sites) == 1
    site = classifier.dynamic_sites[0]
    assert site.category == UncertaintyCategory.GETATTR_NON_CONSTANT

    # Auditing against 'urllib3': must NOT touch
    touches_urllib3, _ = NamespaceTouchAuditor.touches_namespace(site, "urllib3")
    assert touches_urllib3 is False

    # Auditing against 'json' (which is in scope): touches json scope per Condition A
    touches_json, _ = NamespaceTouchAuditor.touches_namespace(site, "json")
    assert touches_json is True


def test_getattr_on_target_package_triggers_uncertainty() -> None:
    """A getattr on a client object from the vulnerable package triggers Condition B/C."""
    code = """import urllib3

def dispatch_request(client, method_name):
    fn = getattr(client, method_name)
    return fn()
"""
    tree = ast.parse(code)
    imports = extract_module_imports(tree, "app.http")
    classifier = DynamicFeatureClassifier("app/http.py", "app.http", imports)
    classifier.visit(tree)

    reasons = NamespaceTouchAuditor.audit_dynamic_sites_for_alert(
        classifier.dynamic_sites, "urllib3"
    )
    assert len(reasons) >= 1
    assert reasons[0].category == UncertaintyCategory.GETATTR_NON_CONSTANT
    assert "app/http.py:4" in reasons[0].location
    assert "urllib3" in reasons[0].details


def test_non_constant_dynamic_import_triggers_uncertainty() -> None:
    """Non-constant importlib.import_module triggers Condition A."""
    code = """import importlib

def load_driver(driver_name):
    return importlib.import_module(driver_name)
"""
    tree = ast.parse(code)
    imports = extract_module_imports(tree, "app.loader")
    classifier = DynamicFeatureClassifier("app/loader.py", "app.loader", imports)
    classifier.visit(tree)

    reasons = NamespaceTouchAuditor.audit_dynamic_sites_for_alert(
        classifier.dynamic_sites, "requests"
    )
    assert len(reasons) == 1
    assert reasons[0].category == UncertaintyCategory.DYNAMIC_IMPORT
    assert "app/loader.py:4" in reasons[0].location
    assert "Condition A triggered" in reasons[0].details


def test_constant_resolvable_getattr_becomes_edge() -> None:
    """Constant getattr(module, 'literal') resolves to a safe edge without uncertainty."""
    code = """import urllib3

def call_parse():
    fn = getattr(urllib3, "parse_url")
    return fn
"""
    tree = ast.parse(code)
    imports = extract_module_imports(tree, "app.safe")
    classifier = DynamicFeatureClassifier("app/safe.py", "app.safe", imports)
    classifier.visit(tree)

    # Constant getattr creates a resolved edge
    assert len(classifier.resolved_edges) == 1
    edge = classifier.resolved_edges[0]
    assert edge.callee_id == "urllib3:parse_url"
    assert edge.is_dynamic is True

    # And does NOT trigger an uncertainty reason for urllib3
    reasons = NamespaceTouchAuditor.audit_dynamic_sites_for_alert(
        classifier.dynamic_sites, "urllib3"
    )
    assert len(reasons) == 0


def test_entry_points_plugin_loading() -> None:
    """importlib.metadata.entry_points() loading triggers ENTRY_POINT_PLUGIN."""
    code = """from importlib.metadata import entry_points

def discover_plugins():
    return entry_points()
"""
    tree = ast.parse(code)
    imports = extract_module_imports(tree, "app.plugins")
    classifier = DynamicFeatureClassifier("app/plugins.py", "app.plugins", imports)
    classifier.visit(tree)

    assert len(classifier.dynamic_sites) == 1
    assert classifier.dynamic_sites[0].category == UncertaintyCategory.ENTRY_POINT_PLUGIN

    reasons = NamespaceTouchAuditor.audit_dynamic_sites_for_alert(
        classifier.dynamic_sites, "flask"
    )
    assert len(reasons) == 1
    assert reasons[0].category == UncertaintyCategory.ENTRY_POINT_PLUGIN


def test_monkey_patching_targets_specific_package() -> None:
    """Monkey patching urllib3 attributes targets urllib3, but does NOT affect jinja2."""
    code = """import urllib3

def apply_hotfix():
    urllib3.PoolManager = None
"""
    tree = ast.parse(code)
    imports = extract_module_imports(tree, "app.patch")
    classifier = DynamicFeatureClassifier("app/patch.py", "app.patch", imports)
    classifier.visit(tree)

    assert len(classifier.dynamic_sites) == 1
    site = classifier.dynamic_sites[0]
    assert site.category == UncertaintyCategory.MONKEY_PATCH

    # Touches urllib3
    reasons_urllib3 = NamespaceTouchAuditor.audit_dynamic_sites_for_alert(
        classifier.dynamic_sites, "urllib3"
    )
    assert len(reasons_urllib3) == 1
    assert "Monkey patching detected" in reasons_urllib3[0].details

    # Does NOT touch jinja2
    reasons_jinja2 = NamespaceTouchAuditor.audit_dynamic_sites_for_alert(
        classifier.dynamic_sites, "jinja2"
    )
    assert len(reasons_jinja2) == 0
