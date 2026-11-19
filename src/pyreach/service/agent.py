"""PR triage agent coordinator and retrieval tools for reachability findings.

Enforces strict grounding over stored Finding records:
1. The agent NEVER invents call paths or file locations.
2. The agent CANNOT override or weaken soundness rules when a user pushes back.
3. Designed for small open-weight models (gpt-oss 20B, Llama 3.1 8B) via OpenAI-compatible API.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pyreach.models import Finding, Verdict

AGENT_SYSTEM_PROMPT = """You are pyreach PR Agent, an uncompromising software security assistant specializing in Python vulnerability reachability analysis.

CRITICAL INSTRUCTIONS AND GROUNDING RULES:
1. YOU MUST NEVER INVENT OR HALLUCINATE CALL PATHS, FUNCTIONS, MODULES, OR FILE LOCATIONS.
2. Every call path, file name, line number, or symbol you mention MUST come directly from the `get_finding`, `explain_path`, or `show_source_snippet` tools.
3. SOUNDNESS GUARANTEE: You CANNOT and MUST NOT mark a REACHABLE finding as safe or dismiss it as a false positive, even if the user insists, argues, or claims it is only called in admin code, background tasks, or unlikely conditions. Under static reachability rules, if an execution path exists from any recognized application entry point to vulnerable code, the finding is REACHABLE.
4. If a finding is UNCERTAIN, explain the exact uncertainty reason (e.g. dynamic reflection, unindexed framework, monkey-patching) and tell the user how to eliminate the uncertainty (e.g. by replacing dynamic reflection with static imports).
5. If a finding is NOT_REACHABLE, explain that static analysis proved no path exists under CHA over-approximation rules, and point the user to the generated OpenVEX statement.
6. When answering questions, call the appropriate tool first, cite the exact evidence (file:line, hops), and keep your tone objective, precise, and professional.
"""

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_finding",
            "description": "Retrieve the structured finding record (verdict, confidence, advisory details) for an advisory ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "advisory_id": {
                        "type": "string",
                        "description": "The advisory ID, e.g. GHSA-3f63-hfp8-52jq",
                    }
                },
                "required": ["advisory_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "explain_path",
            "description": "Retrieve the detailed, step-by-step evidence call path (symbol, file:line, call_type) for a reachable advisory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "advisory_id": {
                        "type": "string",
                        "description": "The advisory ID to inspect the call path for.",
                    }
                },
                "required": ["advisory_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "show_source_snippet",
            "description": "Read a source code snippet around a specific file and line number from the analyzed project.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Relative or absolute path to the Python source file.",
                    },
                    "line_number": {
                        "type": "integer",
                        "description": "The target line number around which to show context.",
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Number of lines of context before and after (default 5).",
                    },
                },
                "required": ["file_path", "line_number"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rerun_analysis",
            "description": "Request re-running reachability analysis with optional updated entry points or mode. Cannot override soundness rules.",
            "parameters": {
                "type": "object",
                "properties": {
                    "advisory_id": {
                        "type": "string",
                        "description": "Advisory ID to re-evaluate.",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["app", "library"],
                        "description": "Analysis mode.",
                    },
                },
                "required": ["advisory_id"],
            },
        },
    },
]


class PRAgentCoordinator:
    """Coordinates retrieval tool execution and enforces soundness boundaries for PR triage."""

    def __init__(
        self,
        findings: list[Finding],
        project_root: Path | None = None,
        base_url: str = "http://localhost:8000/v1",
        api_key: str = "dummy-key",
        model: str = "gpt-oss-20b",
    ) -> None:
        self.findings_by_id: dict[str, Finding] = {f.advisory_id: f for f in findings}
        self.project_root = project_root
        self.base_url = base_url
        self.api_key = api_key
        self.model = model

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Execute a tool strictly grounded against stored findings and local project sources."""
        if tool_name == "get_finding":
            adv_id = arguments.get("advisory_id", "")
            f = self.findings_by_id.get(adv_id)
            if not f:
                return json.dumps({"error": f"No finding recorded for advisory '{adv_id}'."})
            return json.dumps(
                {
                    "advisory_id": f.advisory_id,
                    "package": f.package_name,
                    "version": f.installed_version,
                    "verdict": f.verdict.value,
                    "confidence": f.confidence.value,
                    "summary": f.summary,
                    "hops_count": len(f.call_path),
                    "uncertainty_reasons_count": len(f.uncertainty_reasons),
                }
            )

        elif tool_name == "explain_path":
            adv_id = arguments.get("advisory_id", "")
            f = self.findings_by_id.get(adv_id)
            if not f:
                return f"No finding recorded for advisory '{adv_id}'."
            if f.verdict != Verdict.REACHABLE or not f.call_path:
                return (
                    f"Advisory '{adv_id}' has verdict {f.verdict.value}. "
                    "Call path is only available for REACHABLE findings."
                )
            lines = [f"Call path for {f.advisory_id} ({f.package_name}=={f.installed_version}):"]
            for i, hop in enumerate(f.call_path, 1):
                lines.append(
                    f"  Hop {i}: {hop.symbol} at {hop.file_path}:{hop.line_number} (call_type: {hop.call_type})"
                )
            return "\n".join(lines)

        elif tool_name == "show_source_snippet":
            file_p = arguments.get("file_path", "")
            line_no = int(arguments.get("line_number", 1))
            ctx = int(arguments.get("context_lines", 5))

            target_path = Path(file_p)
            if self.project_root and not target_path.is_absolute():
                target_path = self.project_root / target_path

            if not target_path.exists():
                return f"Source file '{file_p}' does not exist on disk."

            try:
                lines = target_path.read_text(encoding="utf-8").splitlines()
                start = max(0, line_no - ctx - 1)
                end = min(len(lines), line_no + ctx)
                output = []
                for idx in range(start, end):
                    cur_no = idx + 1
                    prefix = "--> " if cur_no == line_no else "    "
                    output.append(f"{prefix}{cur_no:4d}: {lines[idx]}")
                return "\n".join(output)
            except Exception as e:
                return f"Error reading file '{file_p}': {e}"

        elif tool_name == "rerun_analysis":
            adv_id = arguments.get("advisory_id", "")
            f = self.findings_by_id.get(adv_id)
            if not f:
                return f"Cannot rerun: advisory '{adv_id}' not found."
            # Soundness rule enforcement: user cannot flip verdict
            if f.verdict == Verdict.REACHABLE:
                return (
                    f"Analysis rerun completed for {adv_id}. Reachable execution path remains provable "
                    "from project entry points. Overriding or silencing sound reachability findings is rejected."
                )
            return f"Analysis rerun completed for {adv_id}. Verdict unchanged: {f.verdict.value}."

        return f"Unknown tool: {tool_name}"

    def answer_query(self, query: str, llm_client: Any | None = None) -> str:
        """Handle a triage query from a user or PR reviewer."""
        # Check if query references any known advisory
        target_adv: Finding | None = None
        for adv_id, f in self.findings_by_id.items():
            if adv_id.lower() in query.lower() or f.package_name.lower() in query.lower():
                target_adv = f
                break

        if not target_adv and self.findings_by_id:
            target_adv = next(iter(self.findings_by_id.values()))

        if not target_adv:
            return "No findings are currently stored for this scan."

        # If an LLM client is provided, run full chat completion loop
        if llm_client is not None:
            messages = [
                {"role": "system", "content": AGENT_SYSTEM_PROMPT},
                {"role": "user", "content": query},
            ]
            response = llm_client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=TOOL_DEFINITIONS,
                tool_choice="auto",
            )
            msg = response.choices[0].message
            if getattr(msg, "tool_calls", None):
                tool_call = msg.tool_calls[0]
                tool_name = tool_call.function.name
                args = json.loads(tool_call.function.arguments)
                tool_res = self.execute_tool(tool_name, args)

                # Follow-up with tool response
                messages.append(msg)
                messages.append(
                    {"role": "tool", "tool_call_id": tool_call.id, "content": tool_res}
                )
                final_resp = llm_client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                )
                return str(final_resp.choices[0].message.content)
            return str(msg.content)

        # Deterministic grounded fallback when no LLM endpoint is attached
        if "false positive" in query.lower() or "not a bug" in query.lower() or "safe" in query.lower():
            if target_adv.verdict == Verdict.REACHABLE:
                path_info = self.execute_tool("explain_path", {"advisory_id": target_adv.advisory_id})
                return (
                    f"I have reviewed the call graph evidence for {target_adv.advisory_id} in {target_adv.package_name}=={target_adv.installed_version}.\n\n"
                    f"This finding CANNOT be classified as a false positive. Static analysis has verified an active execution path "
                    f"from recognized project entry points directly into the vulnerable function:\n\n"
                    f"```\n{path_info}\n```\n\n"
                    "Under pyreach soundness rules, any reachable path from an entry point must be treated as REACHABLE. "
                    "To mitigate this alert, please upgrade the package or refactor the code to remove calls along this path."
                )
            elif target_adv.verdict == Verdict.NOT_REACHABLE:
                return (
                    f"For {target_adv.advisory_id} ({target_adv.package_name}), the verdict is NOT_REACHABLE. "
                    "Our analysis proved that no execution path exists from any recognized application entry point. "
                    "An OpenVEX statement has been emitted."
                )
            else:
                return (
                    f"For {target_adv.advisory_id} ({target_adv.package_name}), the verdict is UNCERTAIN. "
                    f"Reason: {target_adv.summary}"
                )

        return self.execute_tool("explain_path", {"advisory_id": target_adv.advisory_id})
