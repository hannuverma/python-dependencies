"""FastAPI service exposing pyreach analysis findings and PR agent chat endpoints."""

from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typer.testing import CliRunner

from pyreach.cli import app as cli_app
from pyreach.models import Finding
from pyreach.service.agent import PRAgentCoordinator

app = FastAPI(
    title="pyreach Vulnerability Reachability Service",
    description="REST API and PR Triage Agent for Python vulnerability reachability analysis.",
    version="0.1.0",
)

# In-memory storage of scans: scan_id -> list[Finding]
SCANS_STORE: dict[str, list[Finding]] = {}
SCANS_PROJECT_ROOT: dict[str, Path] = {}


class ScanRequest(BaseModel):
    project_path: str = Field(description="Local path to the Python project.")
    advisories: list[str] = Field(description="List of OSV advisory IDs or JSON paths.")
    mode: str = Field(default="app", description="Analysis mode: 'app' or 'library'.")


class ScanResponse(BaseModel):
    scan_id: str
    total_findings: int
    findings_summary: list[dict[str, Any]]


class ChatRequest(BaseModel):
    scan_id: str = Field(description="Scan ID of pre-computed findings.")
    message: str = Field(description="User or PR comment query.")


class ChatResponse(BaseModel):
    scan_id: str
    reply: str


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "ok", "service": "pyreach", "version": "0.1.0"}


@app.post("/scan", response_model=ScanResponse)
def trigger_scan(req: ScanRequest) -> ScanResponse:
    p = Path(req.project_path)
    if not p.exists() or not p.is_dir():
        raise HTTPException(status_code=400, detail=f"Project path '{req.project_path}' does not exist.")

    scan_id = str(uuid.uuid4())[:8]

    runner = CliRunner()
    tmp_out = Path(tempfile.mkdtemp(prefix=f"pyreach_scan_{scan_id}_"))
    try:
        args = ["scan", str(p), "-m", req.mode, "-o", str(tmp_out)]
        for adv in req.advisories:
            args.extend(["-a", adv])
        res = runner.invoke(cli_app, args)
        if res.exit_code != 0:
            raise HTTPException(status_code=500, detail=f"pyreach scan failed: {res.output}")

        findings_file = tmp_out / "findings.json"
        if not findings_file.exists():
            raise HTTPException(status_code=500, detail="findings.json was not generated.")

        data = json.loads(findings_file.read_text(encoding="utf-8"))
        findings = [Finding.model_validate(item) for item in data]
        SCANS_STORE[scan_id] = findings
        SCANS_PROJECT_ROOT[scan_id] = p

        summary_list = [
            {
                "advisory_id": f.advisory_id,
                "package": f.package_name,
                "version": f.installed_version,
                "verdict": f.verdict.value,
                "confidence": f.confidence.value,
            }
            for f in findings
        ]

        return ScanResponse(
            scan_id=scan_id,
            total_findings=len(findings),
            findings_summary=summary_list,
        )
    finally:
        shutil.rmtree(tmp_out, ignore_errors=True)


@app.get("/findings/{scan_id}")
def get_findings(scan_id: str) -> list[dict[str, Any]]:
    if scan_id not in SCANS_STORE:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return [dict(json.loads(f.model_dump_json())) for f in SCANS_STORE[scan_id]]


@app.get("/findings/{scan_id}/{advisory_id}")
def get_single_finding(scan_id: str, advisory_id: str) -> dict[str, Any]:
    if scan_id not in SCANS_STORE:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    for f in SCANS_STORE[scan_id]:
        if f.advisory_id.lower() == advisory_id.lower():
            return dict(json.loads(f.model_dump_json()))
    raise HTTPException(status_code=404, detail=f"Advisory '{advisory_id}' not found in scan '{scan_id}'.")


@app.post("/agent/chat", response_model=ChatResponse)
def agent_chat(req: ChatRequest) -> ChatResponse:
    if req.scan_id not in SCANS_STORE:
        raise HTTPException(status_code=404, detail=f"Scan '{req.scan_id}' not found.")

    findings = SCANS_STORE[req.scan_id]
    project_root = SCANS_PROJECT_ROOT.get(req.scan_id)
    coordinator = PRAgentCoordinator(findings=findings, project_root=project_root)
    reply = coordinator.answer_query(req.message)

    return ChatResponse(scan_id=req.scan_id, reply=reply)
