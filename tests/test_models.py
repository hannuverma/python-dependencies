"""Unit tests for pyreach core data models, soundness constraints, and call graphs."""

import json

import pytest

from pyreach.models import (
    Advisory,
    AffectedSymbol,
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
    CallHop,
    ConfidenceLevel,
    EntryPoint,
    EntryPointType,
    Finding,
    OpenVEXDocument,
    SymbolEvidenceSource,
    SymbolType,
    UncertaintyCategory,
    UncertaintyReason,
    Verdict,
    VEXProduct,
    VEXStatement,
    VEXVulnerability,
)


def test_advisory_affected_version_check() -> None:
    adv = Advisory(
        id="GHSA-test-1234",
        aliases=["CVE-2021-99999"],
        package_name="urllib3",
        fixed_versions=["1.26.5"],
    )
    assert adv.is_version_affected("1.26.4") is True
    assert adv.is_version_affected("1.26.5") is False
    assert adv.is_version_affected("1.26.6") is False


def test_affected_symbol_creation() -> None:
    sym = AffectedSymbol(
        package="urllib3",
        module="urllib3.util.ssl_",
        qualified_name="urllib3.util.ssl_.create_urllib3_context",
        symbol_type=SymbolType.FUNCTION,
        source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
        confidence=ConfidenceLevel.HIGH,
        line_start=120,
        line_end=180,
        is_public_api=True,
    )
    assert sym.package == "urllib3"
    assert sym.is_public_api is True
    assert sym.confidence == ConfidenceLevel.HIGH


def test_llm_symbol_soundness_constraint_forbids_not_reachable() -> None:
    """If ANY affected symbol came from LLM fallback, NOT_REACHABLE is forbidden."""
    llm_symbol = AffectedSymbol(
        package="pyyaml",
        module="yaml",
        qualified_name="yaml.load",
        symbol_type=SymbolType.FUNCTION,
        source_of_evidence=SymbolEvidenceSource.LLM_FALLBACK,
        confidence=ConfidenceLevel.LOW,
    )

    with pytest.raises(ValueError, match="Soundness violation: NOT_REACHABLE is forbidden"):
        Finding(
            advisory_id="GHSA-test-llm",
            package_name="pyyaml",
            installed_version="5.3.1",
            verdict=Verdict.NOT_REACHABLE,
            confidence=ConfidenceLevel.HIGH,
            affected_symbols=[llm_symbol],
            summary="Attempting to mark unreachable with LLM symbol",
        )


def test_llm_symbol_reachable_requires_low_confidence() -> None:
    """LLM symbols may yield REACHABLE, but only with LOW confidence."""
    llm_symbol = AffectedSymbol(
        package="pyyaml",
        module="yaml",
        qualified_name="yaml.load",
        symbol_type=SymbolType.FUNCTION,
        source_of_evidence=SymbolEvidenceSource.LLM_FALLBACK,
        confidence=ConfidenceLevel.LOW,
    )

    with pytest.raises(ValueError, match="Confidence violation: REACHABLE findings based on LLM"):
        Finding(
            advisory_id="GHSA-test-llm",
            package_name="pyyaml",
            installed_version="5.3.1",
            verdict=Verdict.REACHABLE,
            confidence=ConfidenceLevel.HIGH,
            affected_symbols=[llm_symbol],
            summary="Reachable via yaml.load",
        )

    reachable_finding = Finding(
        advisory_id="GHSA-test-llm",
        package_name="pyyaml",
        installed_version="5.3.1",
        verdict=Verdict.REACHABLE,
        confidence=ConfidenceLevel.LOW,
        affected_symbols=[llm_symbol],
        call_path=[
            CallHop(
                symbol="app.main:run",
                file_path="app/main.py",
                line_number=10,
                snippet="yaml.load(payload)",
            )
        ],
        summary="Project directly invokes LLM-identified symbol yaml.load",
    )
    assert reachable_finding.verdict == Verdict.REACHABLE
    assert reachable_finding.confidence == ConfidenceLevel.LOW


def test_finding_validator_rejects_not_reachable_on_uncertainty_or_low_confidence() -> None:
    """Finding validator must reject NOT_REACHABLE if uncertainty_reasons non-empty or confidence != HIGH."""
    sym = AffectedSymbol(
        package="urllib3",
        module="urllib3.util.ssl_",
        qualified_name="urllib3.util.ssl_.create_urllib3_context",
        symbol_type=SymbolType.FUNCTION,
        source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
        confidence=ConfidenceLevel.HIGH,
    )

    # (a) Non-empty uncertainty reasons
    reason_generic = UncertaintyReason(
        category=UncertaintyCategory.GETATTR_NON_CONSTANT,
        location="app/main.py:12",
        details="Non-constant getattr",
    )
    with pytest.raises(ValueError, match="forbidden when uncertainty_reasons is non-empty"):
        Finding(
            advisory_id="GHSA-1",
            package_name="urllib3",
            installed_version="1.26.4",
            verdict=Verdict.NOT_REACHABLE,
            confidence=ConfidenceLevel.HIGH,
            affected_symbols=[sym],
            uncertainty_reasons=[reason_generic],
            summary="Invalid NOT_REACHABLE with reasons",
        )

    # (b) Confidence != HIGH
    with pytest.raises(ValueError, match="must strictly have HIGH confidence"):
        Finding(
            advisory_id="GHSA-2",
            package_name="urllib3",
            installed_version="1.26.4",
            verdict=Verdict.NOT_REACHABLE,
            confidence=ConfidenceLevel.MEDIUM,
            affected_symbols=[sym],
            uncertainty_reasons=[],
            summary="Invalid NOT_REACHABLE with MEDIUM confidence",
        )

    # (c) Fatal uncertainty categories: missing_dependency_source or unresolved_entry_points
    reason_missing = UncertaintyReason(
        category=UncertaintyCategory.MISSING_DEPENDENCY_SOURCE,
        location="package:idna",
        details="Missing package",
    )
    with pytest.raises(ValueError, match="fatal uncertainty reasons"):
        Finding(
            advisory_id="GHSA-3",
            package_name="urllib3",
            installed_version="1.26.4",
            verdict=Verdict.NOT_REACHABLE,
            confidence=ConfidenceLevel.HIGH,
            affected_symbols=[sym],
            uncertainty_reasons=[reason_missing],
            summary="Invalid NOT_REACHABLE with missing dependency",
        )

    reason_ep = UncertaintyReason(
        category=UncertaintyCategory.UNRESOLVED_ENTRY_POINTS,
        location="project",
        details="Framework scanning incomplete",
    )
    with pytest.raises(ValueError, match="fatal uncertainty reasons"):
        Finding(
            advisory_id="GHSA-4",
            package_name="urllib3",
            installed_version="1.26.4",
            verdict=Verdict.NOT_REACHABLE,
            confidence=ConfidenceLevel.HIGH,
            affected_symbols=[sym],
            uncertainty_reasons=[reason_ep],
            summary="Invalid NOT_REACHABLE with unresolved entry points",
        )


def test_entry_point_confidence_and_framework_tracking() -> None:
    """has_confident_entry_points requires entry_points_complete flag, framework completion, and HIGH confidence."""
    cg = CallGraph()

    # Case 1: entry_points_complete is False -> returns False
    ep = EntryPoint(
        symbol_id="app.main:run",
        entry_type=EntryPointType.MAIN,
        confidence=ConfidenceLevel.HIGH,
    )
    cg.add_entry_point(ep)
    assert cg.has_confident_entry_points() is False

    # Case 2: Incomplete framework discovery -> returns False
    cg.entry_points_complete = True
    cg.record_framework_status(framework="fastapi", completed=False, discovered_count=0)
    assert cg.has_confident_entry_points() is False

    # Case 3: Framework completed, but an entry point has MEDIUM confidence -> returns False
    cg.record_framework_status(framework="fastapi", completed=True, discovered_count=1)
    cg.add_entry_point(
        EntryPoint(
            symbol_id="app.dynamic:hook",
            entry_type=EntryPointType.CLI_COMMAND,
            confidence=ConfidenceLevel.MEDIUM,
        )
    )
    assert cg.has_confident_entry_points() is False

    # Case 4: Complete discovery and all HIGH confidence -> returns True
    cg_clean = CallGraph()
    cg_clean.entry_points_complete = True
    cg_clean.record_framework_status(framework="main", completed=True, discovered_count=1)
    cg_clean.add_entry_point(
        EntryPoint(
            symbol_id="app.main:run",
            entry_type=EntryPointType.MAIN,
            confidence=ConfidenceLevel.HIGH,
        )
    )
    assert cg_clean.has_confident_entry_points() is True


def test_package_parse_tracking_and_pep503_normalization() -> None:
    """verify_dependency_chain fails safe on failed files, zero nodes, or missing packages with PEP 503 normalization."""
    cg = CallGraph()

    # Register 'Py_YAML' node; canonicalizes to 'py-yaml'
    node = CallGraphNode(
        node_id="yaml:load",
        package="Py_YAML",
        module="yaml",
        name="load",
        qualified_name="yaml.load",
    )
    cg.add_node(node)
    assert "py-yaml" in cg.registered_packages

    # Record clean stats using another spelling 'Py.YAML' -> canonicalizes to 'py-yaml'
    cg.record_package_stats(package_name="Py.YAML", files_total=5, files_parsed=5, files_failed=0)

    # 1. Successful verification with third spelling 'py-yaml' per PEP 503
    reasons = cg.verify_dependency_chain(["py-yaml"])
    assert len(reasons) == 0

    # 2. Package with parse failure (has nodes, but 1 file failed)
    cg.record_package_stats(package_name="broken-lib", files_total=3, files_parsed=2, files_failed=1)
    cg.add_node(
        CallGraphNode(
            node_id="broken:func",
            package="broken-lib",
            module="broken",
            name="func",
            qualified_name="broken.func",
        )
    )
    reasons_failed = cg.verify_dependency_chain(["broken_lib"])
    assert len(reasons_failed) == 1
    assert "1/3 files fail" in reasons_failed[0].details

    # 3. Package with zero nodes
    cg.record_package_stats(package_name="empty-lib", files_total=1, files_parsed=0, files_failed=0)
    cg.registered_packages.add("empty-lib")
    reasons_empty = cg.verify_dependency_chain(["empty-lib"])
    assert len(reasons_empty) == 1
    assert "0 AST nodes" in reasons_empty[0].details

    # 4. Package completely missing
    reasons_missing = cg.verify_dependency_chain(["uninstalled-pkg"])
    assert len(reasons_missing) == 1
    assert "was not fetched or registered" in reasons_missing[0].details


def test_target_matching_by_package_module_qualified_name_and_decoy() -> None:
    """find_shortest_call_path matches strictly by (package, module, qualified_name), rejecting decoys."""
    cg = CallGraph()

    project_node = CallGraphNode(
        node_id="app.client:run",
        package="myapp",
        module="app.client",
        name="run",
        qualified_name="app.client.run",
        is_entry_point=True,
    )
    # Decoy symbol: same module and qualified name, but in package 'decoy-lib'
    decoy_node = CallGraphNode(
        node_id="decoy-lib:create_urllib3_context",
        package="decoy-lib",
        module="urllib3.util.ssl_",
        name="create_urllib3_context",
        qualified_name="urllib3.util.ssl_.create_urllib3_context",
        is_dependency=True,
    )
    # Real vulnerable symbol: in package 'urllib3'
    real_vuln_node = CallGraphNode(
        node_id="urllib3:create_urllib3_context",
        package="urllib3",
        module="urllib3.util.ssl_",
        name="create_urllib3_context",
        qualified_name="urllib3.util.ssl_.create_urllib3_context",
        is_dependency=True,
    )

    cg.add_node(project_node)
    cg.add_node(decoy_node)
    cg.add_node(real_vuln_node)

    # Project only calls the DECOY node
    cg.add_edge(
        CallGraphEdge(
            caller_id=project_node.node_id,
            callee_id=decoy_node.node_id,
            call_site_file="app/client.py",
            call_site_line=25,
            snippet="decoy_ssl.create_urllib3_context()",
        )
    )

    # Searching for target in 'urllib3' must NOT match decoy_node
    path_to_vuln = cg.find_shortest_call_path(
        start_node_id=project_node.node_id,
        target_package="urllib3",
        target_module="urllib3.util.ssl_",
        target_qualified_name="urllib3.util.ssl_.create_urllib3_context",
    )
    assert path_to_vuln is None

    # Multi-source search must also reject the decoy
    cg.entry_points_complete = True
    cg.add_entry_point(
        EntryPoint(
            symbol_id=project_node.node_id,
            entry_type=EntryPointType.MAIN,
            confidence=ConfidenceLevel.HIGH,
        )
    )
    path_multi = cg.find_shortest_call_path_from_any_entry(
        target_package="urllib3",
        target_module="urllib3.util.ssl_",
        target_qualified_name="urllib3.util.ssl_.create_urllib3_context",
    )
    assert path_multi is None

    # Now connect project to real vulnerable node
    cg.add_edge(
        CallGraphEdge(
            caller_id=project_node.node_id,
            callee_id=real_vuln_node.node_id,
            call_site_file="app/client.py",
            call_site_line=30,
            snippet="real_ssl.create_urllib3_context()",
        )
    )
    path_real = cg.find_shortest_call_path_from_any_entry(
        target_package="urllib3",
        target_module="urllib3.util.ssl_",
        target_qualified_name="urllib3.util.ssl_.create_urllib3_context",
    )
    assert path_real is not None
    assert len(path_real) == 1
    assert path_real[0].symbol == "urllib3.util.ssl_.create_urllib3_context"
    assert path_real[0].line_number == 30


def test_finding_explain_plain_text_rendering() -> None:
    sym = AffectedSymbol(
        package="urllib3",
        module="urllib3.util.ssl_",
        qualified_name="urllib3.util.ssl_.create_urllib3_context",
        symbol_type=SymbolType.FUNCTION,
        source_of_evidence=SymbolEvidenceSource.FIX_COMMIT_DIFF,
        confidence=ConfidenceLevel.HIGH,
    )
    hop1 = CallHop(
        symbol="myapp.client.fetch_data",
        file_path="src/myapp/client.py",
        line_number=20,
        call_type="direct",
        snippet="response = requests.get('https://example.com')",
    )
    reason = UncertaintyReason(
        category=UncertaintyCategory.GETATTR_NON_CONSTANT,
        location="src/myapp/plugins.py:42",
        details="Non-constant getattr dynamically selects adapter.",
        potential_targets=["CustomHTTPAdapter", "DefaultAdapter"],
    )

    finding = Finding(
        advisory_id="GHSA-r64q-w8jr-g9qp",
        package_name="urllib3",
        installed_version="1.26.4",
        verdict=Verdict.REACHABLE,
        confidence=ConfidenceLevel.HIGH,
        affected_symbols=[sym],
        call_path=[hop1],
        uncertainty_reasons=[reason],
        summary="Vulnerable context creation reached via requests HTTP adapter.",
    )

    explained = finding.explain()
    assert "Advisory:  GHSA-r64q-w8jr-g9qp (urllib3==1.26.4)" in explained
    assert "Verdict:   REACHABLE (Confidence: high)" in explained
    assert "urllib3.util.ssl_.create_urllib3_context" in explained
    assert "src/myapp/client.py:20" in explained
    assert "src/myapp/plugins.py:42" in explained


def test_entry_point_is_itself_target_returns_one_hop_path() -> None:
    """When an entry point is itself the target (zero hops), return a 1-hop path with call_type='entry_point'."""
    cg = CallGraph()
    target_node = CallGraphNode(
        node_id="app.api:vulnerable_handler",
        package="myapp",
        module="app.api",
        name="vulnerable_handler",
        qualified_name="app.api.vulnerable_handler",
        file_path="src/myapp/api.py",
        line_number=15,
        is_entry_point=True,
    )
    cg.add_node(target_node)
    cg.add_entry_point(
        EntryPoint(
            symbol_id=target_node.node_id,
            entry_type=EntryPointType.FASTAPI_ROUTE,
            file_path="src/myapp/api.py",
            line_number=15,
            confidence=ConfidenceLevel.HIGH,
        )
    )

    # find_shortest_call_path when start == target
    path_direct = cg.find_shortest_call_path(
        start_node_id=target_node.node_id,
        target_package="myapp",
        target_module="app.api",
        target_qualified_name="app.api.vulnerable_handler",
    )
    assert path_direct is not None
    assert len(path_direct) == 1
    assert path_direct[0].symbol == "app.api.vulnerable_handler"
    assert path_direct[0].call_type == "entry_point"
    assert path_direct[0].file_path == "src/myapp/api.py"
    assert path_direct[0].line_number == 15

    # find_shortest_call_path_from_any_entry when entry point is the target
    path_multi = cg.find_shortest_call_path_from_any_entry(
        target_package="myapp",
        target_module="app.api",
        target_qualified_name="app.api.vulnerable_handler",
    )
    assert path_multi is not None
    assert len(path_multi) == 1
    assert path_multi[0].symbol == "app.api.vulnerable_handler"
    assert path_multi[0].call_type == "entry_point"

    # Searching for non-existent target returns None, not an empty list
    path_none = cg.find_shortest_call_path_from_any_entry(
        target_package="myapp",
        target_module="app.api",
        target_qualified_name="app.api.non_existent",
    )
    assert path_none is None


def test_finding_and_vex_serialization() -> None:
    stmt = VEXStatement(
        vulnerability=VEXVulnerability(name="GHSA-test-1234", aliases=["CVE-2021-99999"]),
        products=[VEXProduct.from_purl("pkg:pypi/urllib3@1.26.4")],
        status="not_affected",
        justification="vulnerable_code_not_in_execute_path",
        impact_statement="Static reachability analysis verified no call path leads to affected symbols.",
    )
    vex_doc = OpenVEXDocument(statements=[stmt])
    raw_json = vex_doc.to_openvex_json()
    parsed = json.loads(raw_json)

    assert parsed["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert parsed["statements"][0]["status"] == "not_affected"
    assert parsed["statements"][0]["justification"] == "vulnerable_code_not_in_execute_path"
