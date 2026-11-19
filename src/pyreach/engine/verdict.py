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
            pkg_norm = canonicalize_name(advisory.package_name)
            # Step 7: Fail-safe catch-all defaults strictly to UNCERTAIN
            err_reason = UncertaintyReason(
                category=UncertaintyCategory.OTHER,
                location=f"advisory:{advisory.id}",
                details=f"Unexpected internal analysis exception: {str(ex)}\n{traceback.format_exc()}",
            )
            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.UNCERTAIN,
                confidence=ConfidenceLevel.LOW,
                affected_symbols=advisory.extracted_symbols,
                uncertainty_reasons=[err_reason],
                distribution_filename=self.call_graph.package_distribution_filenames.get(pkg_norm),
                distribution_tag=self.call_graph.package_distribution_tags.get(pkg_norm),
                summary=f"Analysis encountered unexpected error: {str(ex)}",
            )

    def _evaluate_internal(
        self,
        advisory: Advisory,
        installed_version: str,
        required_packages: list[str] | None,
    ) -> Finding:
        pkg_norm = canonicalize_name(advisory.package_name)
        dist_fn = self.call_graph.package_distribution_filenames.get(pkg_norm)
        dist_tag = self.call_graph.package_distribution_tags.get(pkg_norm)

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
                    distribution_filename=dist_fn,
                    distribution_tag=dist_tag,
                    summary="Dependency chain incomplete: required package missing, unparsed, or failed.",
                )

        # A negative verdict is unsound when symbol extraction produced no valid targets.
        if not advisory.extracted_symbols:
            no_sym_reason = UncertaintyReason(
                category=UncertaintyCategory.NO_AFFECTED_SYMBOLS,
                location=f"advisory:{advisory.id}",
                details=(
                    "No valid affected symbols remained after advisory resolution and "
                    "fix-file filtering."
                ),
            )
            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.UNCERTAIN,
                confidence=ConfidenceLevel.LOW,
                uncertainty_reasons=[no_sym_reason],
                distribution_filename=dist_fn,
                distribution_tag=dist_tag,
                summary="No affected symbols could be identified soundly.",
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
                distribution_filename=dist_fn,
                distribution_tag=dist_tag,
                summary="Entry-point discovery incomplete or unconfident.",
            )

        # -------------------------------------------------------------------
        # Step 3: Check for symbols
        # -------------------------------------------------------------------
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
            # Check if call path passes through a native module
            native_hops = [
                h for h in best_path
                if any(
                    node.module in self.call_graph.native_modules or node.is_native
                    for node_id, node in self.call_graph.nodes.items()
                    if node.qualified_name == h.symbol or node.node_id == h.symbol
                )
            ]
            if native_hops:
                c_path_reason = UncertaintyReason(
                    category=UncertaintyCategory.OTHER,
                    location=f"{native_hops[0].file_path}:{native_hops[0].line_number}",
                    details=(
                        f"Call path to '{reached_symbol.qualified_name}' passes through a compiled "
                        f"native extension node ({native_hops[0].symbol}); reachability cannot be proven statically."
                    ),
                )
                return Finding(
                    advisory_id=advisory.id,
                    package_name=pkg_norm,
                    installed_version=installed_version,
                    verdict=Verdict.UNCERTAIN,
                    confidence=ConfidenceLevel.HIGH,
                    affected_symbols=[reached_symbol],
                    uncertainty_reasons=[c_path_reason],
                    call_path=best_path,
                    distribution_filename=dist_fn,
                    distribution_tag=dist_tag,
                    summary=f"Call path to {reached_symbol.qualified_name} passes through a compiled native extension.",
                )

            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.REACHABLE,
                confidence=best_confidence,
                affected_symbols=[reached_symbol],
                call_path=best_path,
                distribution_filename=dist_fn,
                distribution_tag=dist_tag,
                summary=f"Reachable call path found leading to {reached_symbol.qualified_name} in {len(best_path)} hop(s).",
            )

        # -------------------------------------------------------------------
        # Step 5: Dynamic Site Namespace Touch Auditing
        # -------------------------------------------------------------------
        target_mods = {
            node.module.split(".")[0].lower()
            for node in self.call_graph.nodes.values()
            if canonicalize_name(node.package) == pkg_norm
        }
        if pkg_norm in self.call_graph.package_top_levels:
            target_mods.update(m.lower() for m in self.call_graph.package_top_levels[pkg_norm])
        touching_reasons = NamespaceTouchAuditor.audit_dynamic_sites_for_alert(
            self.dynamic_sites,
            advisory.package_name,
            target_modules=target_mods,
            target_symbols=advisory.extracted_symbols,
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
                distribution_filename=dist_fn,
                distribution_tag=dist_tag,
                summary=(
                    f"Dynamic constructs in project touch the '{advisory.package_name}' namespace, "
                    "preventing proof of unreachability."
                ),
            )

        # -------------------------------------------------------------------
        # Step 6: Sound Proof of NOT_REACHABLE
        # -------------------------------------------------------------------
        # Rule 6a: If ANY affected symbol resides in a compiled native extension (.so/.pyd),
        # AST analysis cannot inspect it; unreachability cannot be proven!
        is_native_symbol = any(
            sym.module in self.call_graph.native_modules
            for sym in advisory.extracted_symbols
        )
        if is_native_symbol:
            c_sym_reason = UncertaintyReason(
                category=UncertaintyCategory.OTHER,
                location=f"advisory:{advisory.id}",
                details=(
                    f"Affected symbol in '{advisory.package_name}' is implemented in a compiled "
                    "native extension (.so/.pyd); unreachability cannot be proven with AST."
                ),
            )
            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.UNCERTAIN,
                confidence=ConfidenceLevel.HIGH,
                affected_symbols=advisory.extracted_symbols,
                uncertainty_reasons=[c_sym_reason],
                distribution_filename=dist_fn,
                distribution_tag=dist_tag,
                summary="Affected symbol lives in compiled native code; cannot prove unreachability.",
            )

        # Rule 6b: If the project calls into a native module in the target package,
        # that native module is a black box that could call the vulnerable code internally!
        project_calls_target_native = any(
            (e.caller_id in self.call_graph.nodes and not self.call_graph.nodes[e.caller_id].is_dependency)
            and any(
                n.package == pkg_norm and (n.module in self.call_graph.native_modules or n.is_native)
                for n in [self.call_graph.nodes.get(e.callee_id)] if n
            )
            for e in self.call_graph.edges
        )
        if project_calls_target_native:
            c_call_reason = UncertaintyReason(
                category=UncertaintyCategory.OTHER,
                location=f"package:{pkg_norm}",
                details=(
                    f"Project calls directly into compiled native extension in '{advisory.package_name}'; "
                    "native control flow cannot be traversed with AST, preventing proof of unreachability."
                ),
            )
            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.UNCERTAIN,
                confidence=ConfidenceLevel.HIGH,
                affected_symbols=advisory.extracted_symbols,
                uncertainty_reasons=[c_call_reason],
                distribution_filename=dist_fn,
                distribution_tag=dist_tag,
                summary="Project calls into compiled native extension of target package.",
            )

        # Rule 6c: If ANY affected symbol was derived from LLM fallback, NOT_REACHABLE is forbidden!
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
                distribution_filename=dist_fn,
                distribution_tag=dist_tag,
                summary="Negative verdict cannot be proved because affected symbols rely on LLM fallback.",
            )

        # Rule 6d: If only platform wheels exist and the package contains platform-conditional Python files,
        # reachability across platforms cannot be soundly verified without universal wheel or sdist!
        if (
            pkg_norm in self.call_graph.package_platform_wheels
            and pkg_norm in self.call_graph.package_has_platform_conditionals
        ):
            plat_whl = self.call_graph.package_platform_wheels[pkg_norm]
            platform_reason = UncertaintyReason(
                category=UncertaintyCategory.PLATFORM_WHEEL,
                location=f"package:{pkg_norm}",
                details=(
                    f"Package '{advisory.package_name}' only provides platform-specific wheel ('{plat_whl}') "
                    "and contains platform-conditional code (sys.platform/os.name); reachability cannot be "
                    "soundly verified across platforms without a universal wheel or sdist."
                ),
            )
            return Finding(
                advisory_id=advisory.id,
                package_name=pkg_norm,
                installed_version=installed_version,
                verdict=Verdict.UNCERTAIN,
                confidence=ConfidenceLevel.HIGH,
                affected_symbols=advisory.extracted_symbols,
                uncertainty_reasons=[platform_reason],
                distribution_filename=dist_fn,
                distribution_tag=dist_tag,
                summary="Only platform wheels available for package with platform-conditional code; cannot prove unreachability.",
            )

        # All soundness conditions satisfied! Emit NOT_REACHABLE at HIGH confidence.
        return Finding(
            advisory_id=advisory.id,
            package_name=pkg_norm,
            installed_version=installed_version,
            verdict=Verdict.NOT_REACHABLE,
            confidence=ConfidenceLevel.HIGH,
            affected_symbols=advisory.extracted_symbols,
            distribution_filename=dist_fn,
            distribution_tag=dist_tag,
            summary=(
                f"Provably NOT_REACHABLE: all entry points covered under over-approximation rules, "
                f"dependency call graph traversed, zero paths found, and zero dynamic constructs "
                f"touch '{advisory.package_name}'."
            ),
        )
