from __future__ import annotations

import csv
import json
import os
import runpy
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name
from typer.testing import CliRunner

from pyreach.advisory.osv_client import HTTPOSVClient, parse_osv_json
from pyreach.advisory.resolver import AdvisorySymbolResolver, HTTPVCSClient
from pyreach.cli import app
from pyreach.isolation.manifest_parser import parse_pipfile_lock, parse_requirements_txt
from pyreach.models import Advisory, ConfidenceLevel, Finding, Verdict


REPOS = [
    {
        "name": "records",
        "repo": "kennethreitz/records",
        "tag": "v0.5.3",
        "path": Path("real_eval/records"),
        "manifest_type": "pipfile",
        "entry_file": "records.py",
        "test_module": "tests.test_records",
    },
    {
        "name": "requests-html",
        "repo": "psf/requests-html",
        "tag": "v0.10.0",
        "path": Path("real_eval/requests-html"),
        "manifest_type": "pipfile",
        "entry_file": "requests_html.py",
        "test_module": "tests.test_requests_html",
    },
    {
        "name": "responder",
        "repo": "kennethreitz/responder",
        "tag": "v1.1.2",
        "path": Path("real_eval/responder"),
        "manifest_type": "pipfile",
        "entry_file": "responder/core.py",
        "test_module": "tests.test_responder",
    },
    {
        "name": "requests",
        "repo": "psf/requests",
        "tag": "v2.20.0",
        "path": Path("real_eval/requests"),
        "manifest_type": "pipfile",
        "entry_file": "requests/api.py",
        "test_module": "tests.test_requests",
    },
    {
        "name": "python-qrcode",
        "repo": "lincolnloop/python-qrcode",
        "tag": "v7.4.2",
        "path": Path("real_eval/python-qrcode"),
        "manifest_type": "requirements",
        "entry_file": "qrcode/main.py",
        "test_module": "qrcode.tests.test_qrcode",
    },
]


def discover_repo_advisories(repo_info: dict[str, Any]) -> list[dict[str, Any]]:
    """Discover real OSV advisories affecting pinned packages, prioritizing fix commits."""
    repo_path = repo_info["path"]
    if repo_info["manifest_type"] == "pipfile":
        lock_path = repo_path / "Pipfile.lock"
        pinned = parse_pipfile_lock(lock_path.read_text(encoding="utf-8"))
    else:
        req_path = repo_path / "requirements.txt"
        pinned = parse_requirements_txt(req_path.read_text(encoding="utf-8"))

    osv_client = HTTPOSVClient()
    advisories_candidates: list[dict[str, Any]] = []

    for pkg in pinned:
        if not pkg.version:
            continue
        norm_name = canonicalize_name(pkg.name)
        if norm_name in ("certifi", "chardet", "idna", "tzdata"):
            continue

        try:
            advs = osv_client.query_advisories(norm_name, pkg.version)
        except Exception:
            continue

        for adv in advs:
            has_fix = len(adv.fix_commits) > 0 or len(adv.fixed_versions) > 0
            advisories_candidates.append({
                "advisory_id": adv.id,
                "package": norm_name,
                "version": pkg.version,
                "has_fix": has_fix,
                "fix_commits": adv.fix_commits,
                "summary": adv.summary or adv.id,
            })

    # Prioritize advisories with fix commits / versions
    advisories_candidates.sort(key=lambda a: not a["has_fix"])

    # Deduplicate and cap at 5
    seen = set()
    selected = []
    for a in advisories_candidates:
        if a["advisory_id"] not in seen:
            seen.add(a["advisory_id"])
            selected.append(a)
            if len(selected) >= 5:
                break

    return selected


def run_pyreach_scan(repo_path: Path, advisory_id: str) -> tuple[Finding | None, float, str | None]:
    """Run pyreach scan via CliRunner, recording wall time and finding details."""
    runner = CliRunner()
    out_dir = repo_path / ".pyreach_eval_out"
    out_dir.mkdir(exist_ok=True)

    t0 = time.perf_counter()
    crash_trace = None
    finding: Finding | None = None
    try:
        res = runner.invoke(app, ["scan", str(repo_path), "-a", advisory_id, "--out", str(out_dir)])
        elapsed = time.perf_counter() - t0
        findings_json = out_dir / "findings.json"
        if findings_json.exists():
            data = json.loads(findings_json.read_text(encoding="utf-8"))
            if data:
                finding = Finding.model_validate(data[0])
        elif res.exit_code != 0:
            crash_trace = res.stdout
    except Exception as e:
        elapsed = time.perf_counter() - t0
        crash_trace = str(e)

    return finding, elapsed, crash_trace


def run_ground_truth_trace(
    repo_info: dict[str, Any],
    target_symbols: list[str],
) -> tuple[str, bool, str | None]:
    """Execute repo entry or tests under sys.setprofile in isolation, reporting executed symbols."""
    repo_path = repo_info["path"]
    entry_file = repo_path / repo_info.get("entry_file", "main.py")
    executed_symbols: set[str] = set()
    caught_exception = None

    def profile_fn(frame, event, arg):  # type: ignore
        if event in ("call", "c_call"):
            func_name = frame.f_code.co_name if hasattr(frame, "f_code") else str(arg)
            for ts in target_symbols:
                target_leaf = ts.split(":")[-1].split(".")[-1]
                if func_name == target_leaf:
                    mod = frame.f_globals.get("__name__", "")
                    executed_symbols.add(f"{mod}:{func_name}")
        return profile_fn

    orig_path = list(sys.path)
    sys.path.insert(0, str(repo_path.resolve()))

    sys.setprofile(profile_fn)
    try:
        if entry_file.exists():
            runpy.run_path(str(entry_file), run_name="__main__")
        else:
            caught_exception = f"Entry file {entry_file} not found"
    except Exception as exc:
        caught_exception = f"{type(exc).__name__}: {exc}"
    finally:
        sys.setprofile(None)
        sys.path = orig_path

    was_called = len(executed_symbols) > 0
    status = "CALLED" if was_called else "NOT CALLED"
    return status, was_called, caught_exception


def main() -> None:
    print("=" * 80)
    print("REAL REPO AUTOMATED EVALUATION HARNESS")
    print("=" * 80)

    rows: list[dict[str, Any]] = []

    for repo_info in REPOS:
        repo_name = repo_info["name"]
        repo_tag = repo_info["tag"]
        repo_path = repo_info["path"]
        print(f"\nEvaluating Repo: {repo_name} @ {repo_tag} ({repo_path})")

        advisories = discover_repo_advisories(repo_info)
        print(f"  Selected {len(advisories)} advisories from OSV.")

        for adv_dict in advisories:
            adv_id = adv_dict["advisory_id"]
            pkg_name = adv_dict["package"]
            print(f"  --> Running pyreach on ({repo_name}, {adv_id} for {pkg_name})...")

            finding, elapsed, crash = run_pyreach_scan(repo_path, adv_id)

            if finding:
                verdict_str = finding.verdict.value
                confidence_str = finding.confidence.value
                reasons = "; ".join(f"[{r.category.value}] {r.location}" for r in finding.uncertainty_reasons)
                targets = [s.qualified_name for s in finding.affected_symbols]
                call_path_hops = len(finding.call_path)
            else:
                verdict_str = "CRASH"
                confidence_str = "N/A"
                reasons = crash or "Scan failed without finding JSON"
                targets = []
                call_path_hops = 0

            # Ground truth trace
            status, called, exc = run_ground_truth_trace(repo_info, targets)

            # Check flags:
            # HARD FAIL: pyreach said NOT_REACHABLE but tracer saw symbol execute
            is_hard_fail = (verdict_str == Verdict.NOT_REACHABLE.value and called)
            # Suspicious: REACHABLE with implausible path or UNCERTAIN with apparent name collision
            is_suspicious = False
            suspicious_note = ""
            if verdict_str == Verdict.REACHABLE.value and not called:
                is_suspicious = True
                suspicious_note = "Statically reachable but dynamic tracer did not exercise symbol"
            elif verdict_str == Verdict.UNCERTAIN.value and any("pil" in r.lower() for r in finding.uncertainty_reasons if finding):
                is_suspicious = True
                suspicious_note = "Uncertainty triggered by potential name collision (e.g. pil vs PIL)"

            print(f"      Verdict: {verdict_str} ({confidence_str}) in {elapsed:.2f}s | Tracer: {status}")
            if is_hard_fail:
                print("      [!!! HARD FAIL DETECTED !!!]")
            if is_suspicious:
                print(f"      [SUSPICIOUS: {suspicious_note}]")

            rows.append({
                "repo": repo_name,
                "tag": repo_tag,
                "advisory_id": adv_id,
                "package": pkg_name,
                "verdict": verdict_str,
                "confidence": confidence_str,
                "uncertain_reasons": reasons,
                "call_path_hops": call_path_hops,
                "runtime_tracer_status": status,
                "runtime_exception": exc or "None",
                "wall_time_seconds": f"{elapsed:.3f}",
                "hard_fail": is_hard_fail,
                "suspicious": is_suspicious,
                "suspicious_note": suspicious_note,
                "crash_or_traceback": crash or "None",
            })

    # Write CSV
    csv_file = Path("real_eval/evaluation_results.csv")
    if rows:
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nWritten {len(rows)} evaluation rows to {csv_file.resolve()}")


if __name__ == "__main__":
    main()
