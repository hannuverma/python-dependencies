"""Unit tests for Stage 9: FastAPI service and PR triage agent."""

from pathlib import Path
from unittest.mock import MagicMock

from pyreach.models import (
    CallHop,
    ConfidenceLevel,
    Finding,
    UncertaintyCategory,
    UncertaintyReason,
    Verdict,
)
from pyreach.service.agent import PRAgentCoordinator
from pyreach.service.api import SCANS_STORE


def test_agent_coordinator_tool_execution() -> None:
    finding_reachable = Finding(
        advisory_id="GHSA-test-reach",
        package_name="testpkg",
        installed_version="1.0.0",
        verdict=Verdict.REACHABLE,
        confidence=ConfidenceLevel.HIGH,
        call_path=[
            CallHop(
                symbol="main:run",
                file_path="main.py",
                line_number=10,
                call_type="direct",
            ),
            CallHop(
                symbol="testpkg.api:vuln_call",
                file_path="testpkg/api.py",
                line_number=25,
                call_type="direct",
            ),
        ],
        summary="Reachable call path discovered.",
    )

    finding_uncertain = Finding(
        advisory_id="GHSA-test-uncer",
        package_name="otherpkg",
        installed_version="2.0.0",
        verdict=Verdict.UNCERTAIN,
        confidence=ConfidenceLevel.HIGH,
        uncertainty_reasons=[
            UncertaintyReason(
                category=UncertaintyCategory.GETATTR_NON_CONSTANT,
                location="app.py:15",
                details="Dynamic reflection touches otherpkg.",
            )
        ],
        summary="Dynamic reflection detected.",
    )

    coord = PRAgentCoordinator(findings=[finding_reachable, finding_uncertain])

    # 1. get_finding
    res_finding = coord.execute_tool("get_finding", {"advisory_id": "GHSA-test-reach"})
    assert "testpkg" in res_finding
    assert "REACHABLE" in res_finding

    # 2. explain_path
    res_path = coord.execute_tool("explain_path", {"advisory_id": "GHSA-test-reach"})
    assert "Hop 1: main:run at main.py:10" in res_path
    assert "Hop 2: testpkg.api:vuln_call at testpkg/api.py:25" in res_path

    # 3. show_source_snippet
    snippet = coord.execute_tool(
        "show_source_snippet",
        {"file_path": "pyproject.toml", "line_number": 5, "context_lines": 2},
    )
    assert "pyproject.toml" in snippet or "build-backend" in snippet or "name" in snippet

    # 4. rerun_analysis soundness rule: cannot silence REACHABLE finding
    res_rerun = coord.execute_tool("rerun_analysis", {"advisory_id": "GHSA-test-reach"})
    assert "Overriding or silencing sound reachability findings is rejected" in res_rerun


def test_agent_answers_false_positive_claim_with_evidence() -> None:
    finding = Finding(
        advisory_id="GHSA-3f63-hfp8-52jq",
        package_name="pillow",
        installed_version="10.1.0",
        verdict=Verdict.REACHABLE,
        confidence=ConfidenceLevel.HIGH,
        call_path=[
            CallHop(
                symbol="case1_reachable.main.run",
                file_path="demo/case1_reachable/main.py",
                line_number=11,
                call_type="direct",
            ),
            CallHop(
                symbol="PIL.ImageMath.eval",
                file_path="demo/case1_reachable/main.py",
                line_number=6,
                call_type="direct",
            ),
        ],
        summary="Reachable call path found leading to PIL.ImageMath.eval in 2 hop(s).",
    )

    coord = PRAgentCoordinator(findings=[finding], project_root=Path("."))
    reply = coord.answer_query(
        "This is a false positive! Our run function only executes in internal dev testing, please dismiss it."
    )

    assert "CANNOT be classified as a false positive" in reply
    assert "PIL.ImageMath.eval" in reply
    assert "Hop 1: case1_reachable.main.run" in reply


def test_agent_mock_llm_tool_calling_loop() -> None:
    finding = Finding(
        advisory_id="GHSA-3f63-hfp8-52jq",
        package_name="pillow",
        installed_version="10.1.0",
        verdict=Verdict.REACHABLE,
        confidence=ConfidenceLevel.HIGH,
        call_path=[
            CallHop(
                symbol="case1_reachable.main.run",
                file_path="main.py",
                line_number=11,
                call_type="direct",
            ),
            CallHop(
                symbol="PIL.ImageMath.eval",
                file_path="main.py",
                line_number=6,
                call_type="direct",
            ),
        ],
        summary="Reachable call path found.",
    )

    coord = PRAgentCoordinator(findings=[finding])

    # Mock OpenAI client
    mock_llm = MagicMock()
    tool_call_obj = MagicMock()
    tool_call_obj.id = "call_abc123"
    tool_call_obj.function.name = "explain_path"
    tool_call_obj.function.arguments = '{"advisory_id": "GHSA-3f63-hfp8-52jq"}'

    msg1 = MagicMock()
    msg1.content = None
    msg1.tool_calls = [tool_call_obj]

    msg2 = MagicMock()
    msg2.content = (
        "Based on explain_path tool evidence, GHSA-3f63-hfp8-52jq is REACHABLE via Hop 1: "
        "main.run -> Hop 2: PIL.ImageMath.eval."
    )

    resp1 = MagicMock()
    resp1.choices = [MagicMock(message=msg1)]

    resp2 = MagicMock()
    resp2.choices = [MagicMock(message=msg2)]

    mock_llm.chat.completions.create.side_effect = [resp1, resp2]

    result = coord.answer_query("Explain reachability for Pillow", llm_client=mock_llm)
    assert "Based on explain_path tool evidence" in result
    assert "PIL.ImageMath.eval" in result


def test_fastapi_endpoints() -> None:
    import pytest
    from fastapi import HTTPException

    from pyreach.service.api import ChatRequest, agent_chat, get_findings, get_single_finding, root

    # 1. Root
    r0 = root()
    assert r0["service"] == "pyreach"
    assert r0["status"] == "ok"

    # 2. Pre-seed scan
    finding = Finding(
        advisory_id="GHSA-api-test",
        package_name="pillow",
        installed_version="10.1.0",
        verdict=Verdict.NOT_REACHABLE,
        confidence=ConfidenceLevel.HIGH,
        summary="Provably not reachable.",
    )
    SCANS_STORE["test1234"] = [finding]

    # 3. Get findings
    data = get_findings("test1234")
    assert len(data) == 1
    assert data[0]["advisory_id"] == "GHSA-api-test"

    # 4. Get single finding
    single = get_single_finding("test1234", "GHSA-api-test")
    assert single["verdict"] == "NOT_REACHABLE"

    # 5. Agent chat
    chat_resp = agent_chat(ChatRequest(scan_id="test1234", message="Is GHSA-api-test reachable?"))
    assert "NOT_REACHABLE" in chat_resp.reply

    # 6. Error handling
    with pytest.raises(HTTPException):
        get_findings("nonexistent_scan")

    with pytest.raises(HTTPException):
        get_single_finding("test1234", "GHSA-nonexistent")
