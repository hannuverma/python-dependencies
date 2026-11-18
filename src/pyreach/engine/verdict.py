"""Verdict engine implementing strict soundness rules from docs/architecture.md."""

from __future__ import annotations

import traceback

from packaging.utils import canonicalize_name

from pyreach.analysis.dynamic import DynamicSite, NamespaceTouchAuditor
from pyreach.analysis.reachability import ReachabilityEngine
from pyreach.models import (
    Advisory,
    CallGraph,
    CallHop,
    ConfidenceLevel,
    Finding,
    SymbolEvidenceSource,
    UncertaintyCategory,
    UncertaintyReason,
    Verdict,
)


class VerdictEngine:
    """Evaluates reachability verdicts for advisories adhering strictly to soundness rules."""

    def __init__(self, call_graph: CallGraph, dynamic_sites: list[DynamicSite] | None = None) -> None:
        self.call_graph = call_graph
        self.dynamic_sites = dynamic_sites or []
        self.reachability_engine = ReachabilityEngine(call_graph)

    def evaluate_advisory(
        self,
        advisory: Advisory,
        installed_version: str,
        required_packages: list[str] | None = None,
    ) -> Finding:
        """Evaluate verdict for a single advisory against the current call graph.

        Evaluation Order:
        1. Dependency chain complete?
        2. Entry points confident?
        3. LLM symbols present?
        4. Reachability path search
        5. Touching dynamic sites check
        6. NOT_REACHABLE (HIGH only)
        """
        try:
            return self._evaluate_internal(advisory, installed_version, required_packages)
        except Exception as ex:
            # Step 7: Fail-safe catch-all defaults strictly to UNCERTAIN
            err_reason = UncertaintyReason(
                category=UncertaintyCategory.OTHER,
                location=f"advisory:{advisory.id}",
                details=f"Unexpected internal analysis exception: {str(ex)}\n{traceback.format_exc()}",
            )
            return Finding(
                advisory_id=advisory.id,
                package_name=canonicalize_name(advisory.package_name),
                installed_version=installed_version,
                verdict=Verdict.UNCERTAIN,
                confidence=ConfidenceLevel.LOW,
                affected_symbols=advisory.extracted_symbols,
                uncertainty_reasons=[err_reason],
                summary=f"Analysis encountered unexpected error: {str(ex)}",
            )

    def _evaluate_internal(
        self,
        advisory: Advisory,
        installed_version: str,
        required_packages: list[str] | None,
    ) -> Finding:
        pkg_norm = canonicalize_name(advisory.package_name)

        # -------------------------------------------------------------------
        # Step 1: Closed-World Dependency Chain Completeness Check
        # -------------------------------------------------------------------
        if required_packages:
            missing_reasons = self.call_graph.verify_dependency_chain(required_packages)
            if missing_reasons:
                return Finding(
                    advisory_id=advisory.id,
                    package_name=pkg_norm,
                    installed_version=installed_version,
                    verdict=Verdict.UNCERTAIN,
                    confidence=ConfidenceLevel.HIGH,
                    affected_symbols=advisory.extracted_symbols,
                    uncertainty_reasons=missing_reasons,
                    summary="Dependency chain incomplete: required package missing, unparsed, or failed.",
                )

        # -------------------------------------------------------------------
        # Step 2: Complete Entry Point Coverage Check
        # -------------------------------------------------------------------
        if not self.call_graph.has_confident_entry_points():
            ep_reason = UncertaintyReason(
                category=UncertaintyCategory.UNRESOLVED_ENTRY_POINTS,
                location="project:entry_points",
                details=(
                    "Entry points could not be confidently determined "
                    "(unrecognized framework, incomplete scanning, or missing roots)."
                ),
            )
            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.UNCERTAIN,
                confidence=ConfidenceLevel.HIGH,
                affected_symbols=advisory.extracted_symbols,
                uncertainty_reasons=[ep_reason],
                summary="Entry-point discovery incomplete or unconfident.",
            )

        # -------------------------------------------------------------------
        # Step 3: Check for symbols
        # -------------------------------------------------------------------
        if not advisory.extracted_symbols:
            no_sym_reason = UncertaintyReason(
                category=UncertaintyCategory.IMPRECISE_SYMBOL,
                location=f"advisory:{advisory.id}",
                details="Advisory contains no identified affected symbols in package.",
            )
            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.UNCERTAIN,
                confidence=ConfidenceLevel.LOW,
                uncertainty_reasons=[no_sym_reason],
                summary="No affected symbols could be extracted from fix commits or tags.",
            )

        # -------------------------------------------------------------------
        # Step 4: Multi-Source Path Search to Affected Symbols
        # -------------------------------------------------------------------
        best_path: list[CallHop] | None = None
        best_confidence: ConfidenceLevel = ConfidenceLevel.LOW
        reached_symbol = None

        for sym in advisory.extracted_symbols:
            path, conf = self.reachability_engine.find_reachability_evidence(sym)
            if path is not None:
                if best_path is None or len(path) < len(best_path):
                    best_path = path
                    best_confidence = conf
                    reached_symbol = sym

        if best_path is not None and reached_symbol is not None:
            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.REACHABLE,
                confidence=best_confidence,
                affected_symbols=[reached_symbol],
                call_path=best_path,
                summary=f"Reachable call path found leading to {reached_symbol.qualified_name} in {len(best_path)} hop(s).",
            )

        # -------------------------------------------------------------------
        # Step 5: Dynamic Site Namespace Touch Auditing
        # -------------------------------------------------------------------
        touching_reasons = NamespaceTouchAuditor.audit_dynamic_sites_for_alert(
            self.dynamic_sites, advisory.package_name
        )
        if touching_reasons:
            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.UNCERTAIN,
                confidence=ConfidenceLevel.HIGH,
                affected_symbols=advisory.extracted_symbols,
                uncertainty_reasons=touching_reasons,
                summary=(
                    f"Dynamic constructs in project touch the '{advisory.package_name}' namespace, "
                    "preventing proof of unreachability."
                ),
            )

        # -------------------------------------------------------------------
        # Step 6: Sound Proof of NOT_REACHABLE
        # -------------------------------------------------------------------
        # Rule: If ANY affected symbol was derived from LLM fallback, NOT_REACHABLE is forbidden!
        has_llm_symbol = any(
            sym.source_of_evidence == SymbolEvidenceSource.LLM_FALLBACK
            for sym in advisory.extracted_symbols
        )
        if has_llm_symbol:
            llm_reason = UncertaintyReason(
                category=UncertaintyCategory.IMPRECISE_SYMBOL,
                location=f"advisory:{advisory.id}",
                details="Affected symbols were identified via LLM fallback; unreachability cannot be proven.",
            )
            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.UNCERTAIN,
                confidence=ConfidenceLevel.LOW,
                affected_symbols=advisory.extracted_symbols,
                uncertainty_reasons=[llm_reason],
                summary="Negative verdict cannot be proved because affected symbols rely on LLM fallback.",
            )

        # All soundness conditions satisfied! Emit NOT_REACHABLE at HIGH confidence.
        return Finding(
            advisory_id=advisory.id,
            package_name=pkg_norm,
            installed_version=installed_version,
            verdict=Verdict.NOT_REACHABLE,
            confidence=ConfidenceLevel.HIGH,
            affected_symbols=advisory.extracted_symbols,
            summary=(
                f"Provably NOT_REACHABLE: all entry points covered under over-approximation rules, "
                f"dependency call graph traversed, zero paths found, and zero dynamic constructs "
                f"touch '{advisory.package_name}'."
            ),
        )
