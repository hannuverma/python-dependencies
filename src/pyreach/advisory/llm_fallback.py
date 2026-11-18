"""LLM fallback extractor with strict AST existence validation."""

from __future__ import annotations

import ast
import json
from typing import Protocol

from packaging.utils import canonicalize_name

from pyreach.advisory.commit_miner import normalize_module_path
from pyreach.models import (
    Advisory,
    AffectedSymbol,
    ConfidenceLevel,
    SymbolEvidenceSource,
    SymbolType,
)

SYSTEM_PROMPT = """You are a vulnerability analysis assistant.
Given a security advisory description, identify the specific vulnerable Python functions, methods, or classes.
Output ONLY a valid JSON object matching the schema below. Do not include markdown formatting or commentary.

SCHEMA:
{
  "symbols": [
    {
      "module": "package.submodule",
      "qualified_name": "package.submodule.function_or_method_name",
      "symbol_type": "function" | "method" | "class" | "module",
      "reason": "brief explanation"
    }
  ]
}
"""


class LLMExtractorInterface(Protocol):
    """Protocol for LLM-based fallback symbol extraction."""

    def generate_json_response(self, prompt: str) -> str:
        """Generate raw JSON text from the LLM."""
        ...


class MockLLMExtractor:
    """Mock LLM extractor returning pre-configured JSON responses for testing."""

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        self.responses = responses or {}

    def generate_json_response(self, prompt: str) -> str:
        for key, resp in self.responses.items():
            if key in prompt:
                return resp
        return '{"symbols": []}'


class ASTValidatedLLMExtractor:
    """Extracts candidate symbols using an LLM and verifies their AST existence against actual sources."""

    def __init__(self, llm_client: LLMExtractorInterface) -> None:
        self.llm_client = llm_client

    def extract_symbols(
        self,
        advisory: Advisory,
        package_sources: dict[str, str],  # relative_file_path -> source_code
    ) -> list[AffectedSymbol]:
        """Extract candidate symbols from LLM and validate that they exist in real package AST."""
        # 1. Build an index of all existing symbols across the package's AST
        existing_symbols: set[str] = set()
        pkg_norm = canonicalize_name(advisory.package_name)

        for file_path, source in package_sources.items():
            mod = normalize_module_path(file_path, pkg_norm)
            existing_symbols.add(mod)
            try:
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        existing_symbols.add(f"{mod}.{node.name}")
                    elif isinstance(node, ast.ClassDef):
                        existing_symbols.add(f"{mod}.{node.name}")
                        for item in node.body:
                            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                existing_symbols.add(f"{mod}.{node.name}.{item.name}")
            except SyntaxError:
                continue

        # 2. Query the LLM
        prompt = (
            f"Advisory ID: {advisory.id}\n"
            f"Package: {advisory.package_name}\n"
            f"Summary: {advisory.summary or ''}\n"
            f"Details: {advisory.details or ''}\n"
            f"Available modules: {', '.join(sorted(set(normalize_module_path(p, pkg_norm) for p in package_sources)))}\n"
        )
        raw_response = self.llm_client.generate_json_response(prompt)

        # 3. Parse LLM JSON
        try:
            data = json.loads(raw_response)
            candidate_list = data.get("symbols", [])
        except Exception:
            return []

        # 4. Filter strictly by actual AST existence
        validated: list[AffectedSymbol] = []
        for cand in candidate_list:
            qname = str(cand.get("qualified_name", "")).strip()
            module = str(cand.get("module", "")).strip()
            raw_type = str(cand.get("symbol_type", "function")).lower()

            try:
                sym_type = SymbolType(raw_type)
            except ValueError:
                sym_type = SymbolType.FUNCTION

            # Discard any hallucinated symbol not found in real source AST
            if qname in existing_symbols:
                validated.append(
                    AffectedSymbol(
                        package=pkg_norm,
                        module=module or qname.rsplit(".", 1)[0],
                        qualified_name=qname,
                        symbol_type=sym_type,
                        source_of_evidence=SymbolEvidenceSource.LLM_FALLBACK,
                        confidence=ConfidenceLevel.LOW,  # LLM symbols are ALWAYS LOW confidence
                        is_public_api=not qname.split(".")[-1].startswith("_"),
                        description=f"LLM-extracted and AST-validated: {cand.get('reason', '')}",
                    )
                )

        return validated
