"""OpenVEX generator for NOT_REACHABLE vulnerability findings."""

from __future__ import annotations

from datetime import UTC, datetime

from pyreach.models import (
    Finding,
    OpenVEXDocument,
    Verdict,
    VEXProduct,
    VEXStatement,
    VEXVulnerability,
)


def generate_openvex_for_findings(
    findings: list[Finding],
    author: str = "pyreach vulnerability reachability analyzer",
) -> OpenVEXDocument:
    """Generate an OpenVEX v0.2.0 document strictly for NOT_REACHABLE findings.

    Only vulnerabilities that have been proven unreachable under documented
    soundness rules receive OpenVEX 'not_affected' statements.
    """
    statements: list[VEXStatement] = []

    for f in findings:
        if f.verdict != Verdict.NOT_REACHABLE:
            continue

        purl = f"pkg:pypi/{f.package_name}@{f.installed_version}"
        symbols_str = ", ".join(s.qualified_name for s in f.affected_symbols) or "affected symbols"

        stmt = VEXStatement(
            vulnerability=VEXVulnerability(name=f.advisory_id),
            products=[VEXProduct.from_purl(purl)],
            status="not_affected",
            justification="vulnerable_code_not_in_execute_path",
            impact_statement=(
                f"Static reachability analysis with over-approximation proved that no call path "
                f"from project entry points leads to {symbols_str} in {f.package_name}=={f.installed_version}, "
                f"and zero unresolved dynamic constructs touch the package namespace."
            ),
            status_notes=f.summary,
            timestamp=datetime.now(UTC).isoformat(),
        )
        statements.append(stmt)

    return OpenVEXDocument(
        author=author,
        timestamp=datetime.now(UTC).isoformat(),
        statements=statements,
    )
