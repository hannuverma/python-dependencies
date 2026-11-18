"""Rich terminal reporter and JSON exporter for reachability findings."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from pyreach.models import Finding, Verdict


def render_terminal_report(findings: list[Finding], console: Console | None = None) -> None:
    """Render colored summary tables, call trees, and uncertainty details to the terminal."""
    con = console or Console()

    # 1. Summary Table
    table = Table(title="pyreach Vulnerability Reachability Analysis", show_lines=True)
    table.add_column("Advisory ID", style="cyan", no_wrap=True)
    table.add_column("Package", style="magenta")
    table.add_column("Version", style="blue")
    table.add_column("Verdict", justify="center")
    table.add_column("Confidence", justify="center")
    table.add_column("Summary")

    for f in findings:
        if f.verdict == Verdict.REACHABLE:
            verdict_text = "[bold red]REACHABLE[/]"
        elif f.verdict == Verdict.NOT_REACHABLE:
            verdict_text = "[bold green]NOT_REACHABLE[/]"
        else:
            verdict_text = "[bold yellow]UNCERTAIN[/]"

        conf_color = "green" if f.confidence.value == "high" else ("yellow" if f.confidence.value == "medium" else "red")
        conf_text = f"[{conf_color}]{f.confidence.value.upper()}[/]"

        table.add_row(
            f.advisory_id,
            f.package_name,
            f.installed_version,
            verdict_text,
            conf_text,
            f.summary,
        )

    con.print(table)
    con.print()

    # 2. Detailed Evidence for Reachable Findings
    reachable_findings = [f for f in findings if f.verdict == Verdict.REACHABLE]
    if reachable_findings:
        con.print("[bold red]Reachable Vulnerability Evidence Call Paths:[/]")
        for f in reachable_findings:
            tree = Tree(f"[bold cyan]{f.advisory_id}[/] in [magenta]{f.package_name}=={f.installed_version}[/]")
            curr = tree
            for i, hop in enumerate(f.call_path, 1):
                snippet_info = f" [dim]({hop.snippet.strip()})[/]" if hop.snippet else ""
                hop_node = curr.add(
                    f"[bold yellow]Hop {i}:[/] [white]{hop.symbol}[/] at [dim]{hop.file_path}:{hop.line_number}[/] ({hop.call_type}){snippet_info}"
                )
                curr = hop_node
            con.print(Panel(tree, border_style="red"))
            con.print()

    # 3. Detailed Uncertainty Breakdown
    uncertain_findings = [f for f in findings if f.verdict == Verdict.UNCERTAIN]
    if uncertain_findings:
        con.print("[bold yellow]Uncertain Findings Breakdown (Soundness Guarded):[/]")
        for f in uncertain_findings:
            reasons_text = []
            for r in f.uncertainty_reasons:
                reasons_text.append(f"• [[bold yellow]{r.category.value}[/]] at [dim]{r.location}[/]: {r.details}")
            body = "\n".join(reasons_text) if reasons_text else f.summary
            con.print(Panel(body, title=f"{f.advisory_id} ({f.package_name})", border_style="yellow"))
            con.print()


def export_findings_json(findings: list[Finding], output_path: Path) -> None:
    """Export all finding records to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw = [json.loads(f.model_dump_json()) for f in findings]
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump(raw, out, indent=2)
