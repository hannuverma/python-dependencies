"""Reachability path search connecting project entry points through dependency chains to vulnerable symbols."""

from __future__ import annotations

from pyreach.models import (
    AffectedSymbol,
    CallGraph,
    CallHop,
    ConfidenceLevel,
    SymbolEvidenceSource,
)


class ReachabilityEngine:
    """Executes multi-source path search and evaluates evidence chain confidence."""

    def __init__(self, call_graph: CallGraph) -> None:
        self.call_graph = call_graph

    def find_reachability_evidence(
        self,
        symbol: AffectedSymbol,
    ) -> tuple[list[CallHop] | None, ConfidenceLevel]:
        """Search for a call path from any project entry point to the affected symbol.

        Handles private vulnerable functions by checking both direct paths and paths through
        public API callers inside the dependency that expose the private function.
        """
        # 1. Search for direct path to the symbol
        path = self.call_graph.find_shortest_call_path_from_any_entry(
            target_package=symbol.package,
            target_module=symbol.module,
            target_qualified_name=symbol.qualified_name,
        )
        if path is not None:
            conf = self._compute_path_confidence(path, symbol)
            return path, conf

        # 2. If private and has public callers, check reachability to any public caller
        if not symbol.is_public_api and symbol.exposed_by_public_callers:
            for pub_caller in symbol.exposed_by_public_callers:
                caller_mod = pub_caller.rsplit(".", 1)[0]
                pub_path = self.call_graph.find_shortest_call_path_from_any_entry(
                    target_package=symbol.package,
                    target_module=caller_mod,
                    target_qualified_name=pub_caller,
                )
                if pub_path is not None:
                    # Append the hop from public caller to private function
                    pub_node = next(
                        (n for n in self.call_graph.nodes.values() if n.qualified_name == pub_caller),
                        None,
                    )
                    internal_hop = CallHop(
                        symbol=symbol.qualified_name,
                        file_path=symbol.file_path or (pub_node.file_path if pub_node else "unknown") or "unknown",
                        line_number=symbol.line_start or (pub_node.line_number if pub_node else 0) or 0,
                        call_type="internal_exposure",
                        snippet=f"Exposed by public API caller '{pub_caller}'",
                    )
                    full_path = [*pub_path, internal_hop]
                    conf = self._compute_path_confidence(full_path, symbol)
                    return full_path, conf

        return None, ConfidenceLevel.HIGH

    def _compute_path_confidence(
        self,
        path: list[CallHop],
        symbol: AffectedSymbol,
    ) -> ConfidenceLevel:
        """Determine path confidence based on symbol provenance and edge types."""
        # Rule: LLM symbols are ALWAYS LOW confidence
        if symbol.source_of_evidence == SymbolEvidenceSource.LLM_FALLBACK:
            return ConfidenceLevel.LOW

        # If any hop is a callback or dynamic resolution, cap at MEDIUM
        has_indirect_hop = any(hop.call_type in ("callback", "dynamic", "internal_exposure") for hop in path)
        if has_indirect_hop or symbol.confidence == ConfidenceLevel.MEDIUM:
            return ConfidenceLevel.MEDIUM

        return ConfidenceLevel.HIGH
