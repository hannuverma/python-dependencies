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
    """Render clean, un-truncated summary tables and detailed panels to the terminal."""
    con = console or Console()

    # 1. Clean Summary Table (no truncated columns)
    table = Table(
        title="pyreach Vulnerability Reachability Analysis",
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Advisory ID", style="bold cyan", no_wrap=True, min_width=22)
    table.add_column("Package", style="magenta", no_wrap=True, min_width=12)
    table.add_column("Version", style="blue", no_wrap=True, min_width=10)
    table.add_column("Verdict", justify="center", no_wrap=True, min_width=16)
    table.add_column("Confidence", justify="center", no_wrap=True, min_width=12)

    for f in findings:
        if f.verdict == Verdict.REACHABLE:
            verdict_text = "[bold red]REACHABLE[/]"
        elif f.verdict == Verdict.NOT_REACHABLE:
            verdict_text = "[bold green]NOT_REACHABLE[/]"
        else:
            verdict_text = "[bold yellow]UNCERTAIN[/]"

        conf_color = (
            "green"
            if f.confidence.value == "high"
            else ("yellow" if f.confidence.value == "medium" else "red")
        )
        conf_text = f"[{conf_color}]{f.confidence.value.upper()}[/]"

        table.add_row(
            f.advisory_id,
            f.package_name,
            f.installed_version,
            verdict_text,
            conf_text,
        )

    con.print(table)
    con.print()

    # 2. Detailed Findings Panels (Summary & Evidence)
    for f in findings:
        if f.verdict == Verdict.REACHABLE:
            tree = Tree(
                f"[bold cyan]{f.advisory_id}[/] in [magenta]{f.package_name}=={f.installed_version}[/]"
            )
            curr = tree
            for i, hop in enumerate(f.call_path, 1):
                snippet_info = f" [dim]({hop.snippet.strip()})[/]" if hop.snippet else ""
                hop_node = curr.add(
                    f"[bold yellow]Hop {i}:[/] [white]{hop.symbol}[/] at "
                    f"[dim]{hop.file_path}:{hop.line_number}[/] ({hop.call_type}){snippet_info}"
                )
                curr = hop_node
            con.print(
                Panel(
                    tree,
                    title=f"[bold red]Reachable Evidence Call Path:[/] {f.advisory_id} ({f.package_name})",
                    subtitle=f.summary,
                    border_style="red",
                )
            )
            con.print()

        elif f.verdict == Verdict.NOT_REACHABLE:
            content = (
                f"[bold green]VERDICT: NOT_REACHABLE[/] (Confidence: [green]{f.confidence.value.upper()}[/])\n\n"
                f"[white]{f.summary}[/]\n\n"
                "[dim]• OpenVEX status:[/] [bold]not_affected[/]\n"
                "[dim]• Justification:[/] [bold]vulnerable_code_not_in_execute_path[/]"
            )
            con.print(
                Panel(
                    content,
                    title=f"[bold green]Provably Not Reachable:[/] {f.advisory_id} ({f.package_name})",
                    border_style="green",
                )
            )
            con.print()

        else:
            reasons_lines = []
            for r in f.uncertainty_reasons:
                reasons_lines.append(
                    f"• [[bold yellow]{r.category.value}[/]] at [dim]{r.location}[/]: {r.details}"
                )
            reasons_text = "\n".join(reasons_lines) if reasons_lines else f.summary
            content = (
                f"[bold yellow]VERDICT: UNCERTAIN[/] (Confidence: [{conf_color}]{f.confidence.value.upper()}[/])\n\n"
                f"[white]{f.summary}[/]\n\n"
                f"[bold underline]Uncertainty Reasons (Soundness Guarded):[/]\n{reasons_text}"
            )
            con.print(
                Panel(
                    content,
                    title=f"[bold yellow]Uncertain Finding:[/] {f.advisory_id} ({f.package_name})",
                    border_style="yellow",
                )
            )
            con.print()


def export_findings_json(findings: list[Finding], output_path: Path) -> None:
    """Export all finding records to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw = [json.loads(f.model_dump_json()) for f in findings]
    with open(output_path, "w", encoding="utf-8") as out:
        json.dump(raw, out, indent=2)
