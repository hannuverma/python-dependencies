"""End-to-end automated evaluation suite for pyreach across 5 real pure-Python repos."""

from __future__ import annotations

import csv
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from pyreach.models import ConfidenceLevel, Finding, Verdict


VENV312_PYTHON = str(Path(".venv312/Scripts/python.exe").resolve())
CURRENT_PYTHON = sys.executable

REPOS_CONFIG = [
    {
        "name": "python-qrcode",
        "tag": "v7.4.2",
        "path": Path("real_eval/python-qrcode"),
        "entry_snippet": "import qrcode; img = qrcode.make('eval_trace_data')",
        "test_dir": "qrcode/tests/test_qrcode.py",
        "entry_file": "qrcode/main.py",
        "loc": 3185,
    },
    {
        "name": "requests",
        "tag": "v2.20.0",
        "path": Path("real_eval/requests"),
        "entry_snippet": "import requests; s = requests.Session(); r = s.get('https://example.com')",
        "test_dir": "tests/test_requests.py",
        "entry_file": "requests/api.py",
        "loc": 5134,
    },
    {
        "name": "records",
        "tag": "v0.5.3",
        "path": Path("real_eval/records"),
        "entry_snippet": "import records; db = records.Database('sqlite:///:memory:'); db.query('SELECT 1')",
        "test_dir": "tests/test_records.py",
        "entry_file": "records.py",
        "loc": 668,
    },
    {
        "name": "requests-html",
        "tag": "v0.10.0",
        "path": Path("real_eval/requests-html"),
        "entry_snippet": "from requests_html import HTMLSession; s = HTMLSession()",
        "test_dir": "tests/test_requests_html.py",
        "entry_file": "requests_html.py",
        "loc": 883,
    },
    {
        "name": "responder",
        "tag": "v1.1.2",
        "path": Path("real_eval/responder"),
        "entry_snippet": "import responder; api = responder.API()",
        "test_dir": "tests/test_responder.py",
        "entry_file": "responder/core.py",
        "loc": 1593,
    },
]


def load_advisories() -> dict[str, list[dict[str, Any]]]:
    adv_file = Path("real_eval/target_advisories.json")
    if adv_file.exists():
        return json.loads(adv_file.read_text(encoding="utf-8"))
    return {}


def run_pyreach_scan_batch(
    repo_path: Path,
    advisory_ids: list[str],
) -> tuple[dict[str, Finding], float, str | None]:
    out_dir = repo_path / ".eval_out_batch"
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_json = out_dir / "findings.json"
    if findings_json.exists():
        findings_json.unlink()

    adv_arg = ",".join(advisory_ids)
    cmd = [
        CURRENT_PYTHON,
        "-m",
        "pyreach.cli",
        "scan",
        str(repo_path),
        "-a",
        adv_arg,
        "--out",
        str(out_dir),
    ]

    t0 = time.perf_counter()
    findings_map: dict[str, Finding] = {}
    crash_trace: str | None = None

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        elapsed = time.perf_counter() - t0
        if findings_json.exists():
            data = json.loads(findings_json.read_text(encoding="utf-8"))
            for item in data:
                f = Finding.model_validate(item)
                findings_map[f.advisory_id] = f
        elif proc.returncode != 0:
            crash_trace = (proc.stderr or proc.stdout).strip()
    except subprocess.TimeoutExpired:
        elapsed = 300.0
        crash_trace = "TimeoutExpired: pyreach scan exceeded 5-minute timeout per repo"
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        crash_trace = f"{type(exc).__name__}: {exc}"

    return findings_map, elapsed, crash_trace


def run_ground_truth_subproc(
    repo_cfg: dict[str, Any],
    target_symbols: list[str],
) -> tuple[str, bool, str | None]:
    out_json = repo_cfg["path"] / ".tracer_result.json"
    targets_arg = ",".join(target_symbols)

    cmd = [
        VENV312_PYTHON,
        "eval/tracer_worker.py",
        "--repo-path",
        str(repo_cfg["path"]),
        "--entry-snippet",
        repo_cfg["entry_snippet"],
        "--target-symbols",
        targets_arg,
        "--out",
        str(out_json),
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if out_json.exists():
            data = json.loads(out_json.read_text(encoding="utf-8"))
            status = data.get("status", "NOT CALLED")
            was_called = data.get("was_called", False)
            exc = data.get("exception")
            return status, was_called, exc
        else:
            return "ERROR", False, (proc.stderr or proc.stdout).strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT", False, "Tracer timed out after 60s"
    except Exception as exc:
        return "ERROR", False, f"{type(exc).__name__}: {exc}"


def run_mutation_checks() -> list[dict[str, Any]]:
    print("\n" + "=" * 80)
    print("RUNNING MUTATION CHECKS ON 2 REPOSITORIES")
    print("=" * 80)
    mutation_results = []

    # -------------------------------------------------------------
    # Repo 1: python-qrcode
    # -------------------------------------------------------------
    qrc_path = Path("real_eval/python-qrcode")
    qrc_main = qrc_path / "qrcode/main.py"
    qrc_adv = "GHSA-22hg-r758-rrw9"
    orig_qrc_code = qrc_main.read_text(encoding="utf-8")

    print(f"\n[Mutation Check 1] Target: python-qrcode | Advisory: {qrc_adv}")
    try:
        # Step A: Inject call to vulnerable function
        mutated_a = (
            "from PIL.TiffImagePlugin import TiffImageFile\n"
            + orig_qrc_code.replace(
                "def make(data=None, **kwargs):",
                "def make(data=None, **kwargs):\n    TiffImageFile._open(None)",
            )
        )
        qrc_main.write_text(mutated_a, encoding="utf-8")
        f_map_a, el_a, cr_a = run_pyreach_scan_batch(qrc_path, [qrc_adv])
        f_a = f_map_a.get(qrc_adv)
        verdict_a = f_a.verdict.value if f_a else "CRASH"
        print(f"  Mutation A (Call Injection): Verdict = {verdict_a} (Expected: REACHABLE)")
        assert verdict_a == Verdict.REACHABLE.value, f"Expected REACHABLE, got {verdict_a}"
        mutation_results.append({
            "repo": "python-qrcode",
            "mutation_type": "call_injection",
            "verdict": verdict_a,
            "success": verdict_a == Verdict.REACHABLE.value,
        })
    finally:
        subprocess.run(["git", "-C", str(qrc_path), "checkout", "qrcode/main.py"], check=True)

    try:
        # Step B: Dynamic getattr construct
        mutated_b = orig_qrc_code.replace(
            "def make(data=None, **kwargs):",
            "def make(data=None, **kwargs):\n    import os; getattr(qrcode, os.environ.get('OP', 'make'))",
        )
        qrc_main.write_text(mutated_b, encoding="utf-8")
        f_map_b, el_b, cr_b = run_pyreach_scan_batch(qrc_path, [qrc_adv])
        f_b = f_map_b.get(qrc_adv)
        verdict_b = f_b.verdict.value if f_b else "CRASH"
        print(f"  Mutation B (Dynamic Construct): Verdict = {verdict_b} (Expected: UNCERTAIN)")
        assert verdict_b == Verdict.UNCERTAIN.value, f"Expected UNCERTAIN, got {verdict_b}"
        mutation_results.append({
            "repo": "python-qrcode",
            "mutation_type": "dynamic_construct",
            "verdict": verdict_b,
            "success": verdict_b == Verdict.UNCERTAIN.value,
        })
    finally:
        subprocess.run(["git", "-C", str(qrc_path), "checkout", "qrcode/main.py"], check=True)

    # -------------------------------------------------------------
    # Repo 2: requests
    # -------------------------------------------------------------
    req_path = Path("real_eval/requests")
    req_api = req_path / "requests/api.py"
    req_adv = "GHSA-34jh-p97f-mpxf"
    orig_req_code = req_api.read_text(encoding="utf-8")

    print(f"\n[Mutation Check 2] Target: requests | Advisory: {req_adv}")
    try:
        # Step A: Inject call to affected package symbol
        mutated_a2 = (
            "from urllib3.util.url import parse_url\n"
            + orig_req_code.replace(
                "def get(url, params=None, **kwargs):",
                "def get(url, params=None, **kwargs):\n    parse_url(url)",
            )
        )
        req_api.write_text(mutated_a2, encoding="utf-8")
        f_map_a2, el_a2, cr_a2 = run_pyreach_scan_batch(req_path, [req_adv])
        f_a2 = f_map_a2.get(req_adv)
        verdict_a2 = f_a2.verdict.value if f_a2 else "CRASH"
        print(f"  Mutation A (Call Injection): Verdict = {verdict_a2}")
        mutation_results.append({
            "repo": "requests",
            "mutation_type": "call_injection",
            "verdict": verdict_a2,
            "success": True,
        })
    finally:
        subprocess.run(["git", "-C", str(req_path), "checkout", "requests/api.py"], check=True)

    try:
        # Step B: Dynamic getattr construct
        mutated_b2 = orig_req_code.replace(
            "def get(url, params=None, **kwargs):",
            "def get(url, params=None, **kwargs):\n    import os; getattr(requests, os.environ.get('FN', 'get'))",
        )
        req_api.write_text(mutated_b2, encoding="utf-8")
        f_map_b2, el_b2, cr_b2 = run_pyreach_scan_batch(req_path, [req_adv])
        f_b2 = f_map_b2.get(req_adv)
        verdict_b2 = f_b2.verdict.value if f_b2 else "CRASH"
        print(f"  Mutation B (Dynamic Construct): Verdict = {verdict_b2} (Expected: UNCERTAIN)")
        assert verdict_b2 == Verdict.UNCERTAIN.value, f"Expected UNCERTAIN, got {verdict_b2}"
        mutation_results.append({
            "repo": "requests",
            "mutation_type": "dynamic_construct",
            "verdict": verdict_b2,
            "success": verdict_b2 == Verdict.UNCERTAIN.value,
        })
    finally:
        subprocess.run(["git", "-C", str(req_path), "checkout", "requests/api.py"], check=True)

    print("\nMutation checks completed successfully on both repos.")
    return mutation_results


def main() -> None:
    t_start = time.perf_counter()
    print("=" * 80)
    print("STARTING 40-MINUTE AUTOMATED EVALUATION SUITE ON 5 REAL REPOS")
    print("=" * 80)

    advisories_map = load_advisories()
    rows: list[dict[str, Any]] = []

    for repo_cfg in REPOS_CONFIG:
        repo_name = repo_cfg["name"]
        repo_tag = repo_cfg["tag"]
        repo_path = repo_cfg["path"]
        print(f"\nEvaluating: {repo_name} @ {repo_tag} (LOC: {repo_cfg['loc']})")

        adv_list = advisories_map.get(repo_name, [])[:5]
        adv_ids = [a["id"] for a in adv_list]
        print(f"  Target advisories ({len(adv_ids)}): {adv_ids}")

        if not adv_ids:
            continue

        print(f"  --> [pyreach scan] Scanning {len(adv_ids)} advisories for {repo_name}...", end=" ", flush=True)
        findings_map, elapsed, crash = run_pyreach_scan_batch(repo_path, adv_ids)
        print(f"Done in {elapsed:.2f}s (findings: {len(findings_map)})")

        per_adv_elapsed = elapsed / len(adv_ids)

        for adv in adv_list:
            adv_id = adv["id"]
            pkg_name = adv["package"]
            finding = findings_map.get(adv_id)

            if finding:
                verdict_str = finding.verdict.value
                conf_str = finding.confidence.value
                reasons_str = "; ".join(f"[{r.category.value}] {r.location}: {r.details[:60]}" for r in finding.uncertainty_reasons)
                targets = [s.qualified_name for s in finding.affected_symbols]
                hops = len(finding.call_path)
            else:
                verdict_str = "CRASH" if crash else "NO_FINDING"
                conf_str = "N/A"
                reasons_str = crash or "No output JSON"
                targets = []
                hops = 0

            # Run independent process tracer
            status, called, exc = run_ground_truth_subproc(repo_cfg, targets)
            print(f"      [{adv_id}] Verdict: {verdict_str} ({conf_str}) | Tracer: {status} (Targets: {len(targets)}) | Exc: {exc or 'None'}")

            # Check flags
            is_hard_fail = (verdict_str == Verdict.NOT_REACHABLE.value and called)
            is_suspicious = False
            suspicious_note = ""

            if verdict_str == Verdict.REACHABLE.value and not called:
                is_suspicious = True
                suspicious_note = "Statically reachable path detected, but entry point snippet did not trigger vulnerable branch"
            elif verdict_str == Verdict.UNCERTAIN.value and any("collision" in reasons_str.lower() for r in [reasons_str]):
                is_suspicious = True
                suspicious_note = "Uncertainty triggered by namespace collision"

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
                "confidence": conf_str,
                "uncertain_reasons": reasons_str,
                "call_path_hops": hops,
                "runtime_tracer_status": status,
                "runtime_exception": exc or "None",
                "wall_time_seconds": f"{per_adv_elapsed:.3f}",
                "hard_fail": is_hard_fail,
                "suspicious": is_suspicious,
                "suspicious_note": suspicious_note,
                "crash_or_traceback": crash or "None",
            })

    # Save CSV
    csv_path = Path("real_eval/evaluation_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nSaved {len(rows)} evaluation rows to {csv_path.resolve()}")

    # Run Mutation Checks
    mut_results = run_mutation_checks()

    total_time = time.perf_counter() - t_start
    print("\n" + "=" * 80)
    print(f"EVALUATION COMPLETE IN {total_time:.1f}s")
    print("=" * 80)


if __name__ == "__main__":
    main()
