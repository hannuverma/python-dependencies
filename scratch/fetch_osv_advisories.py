from __future__ import annotations

import json
from pathlib import Path
import httpx
from packaging.utils import canonicalize_name
from packaging.version import parse as parse_version

from pyreach.isolation.manifest_parser import parse_pipfile_lock, parse_requirements_txt


REPOS = [
    {
        "name": "records",
        "repo": "kennethreitz/records",
        "tag": "v0.5.3",
        "path": Path("real_eval/records"),
        "manifest_type": "pipfile",
    },
    {
        "name": "requests-html",
        "repo": "psf/requests-html",
        "tag": "v0.10.0",
        "path": Path("real_eval/requests-html"),
        "manifest_type": "pipfile",
    },
    {
        "name": "responder",
        "repo": "kennethreitz/responder",
        "tag": "v1.1.2",
        "path": Path("real_eval/responder"),
        "manifest_type": "pipfile",
    },
    {
        "name": "requests",
        "repo": "psf/requests",
        "tag": "v2.20.0",
        "path": Path("real_eval/requests"),
        "manifest_type": "pipfile",
    },
    {
        "name": "python-qrcode",
        "repo": "lincolnloop/python-qrcode",
        "tag": "v7.4.2",
        "path": Path("real_eval/python-qrcode"),
        "manifest_type": "requirements",
    },
]


def query_osv_batch(queries: list[dict]) -> list[dict]:
    url = "https://api.osv.dev/v1/querybatch"
    resp = httpx.post(url, json={"queries": queries}, timeout=30.0)
    resp.raise_for_status()
    return resp.json().get("results", [])


def main() -> None:
    results: dict[str, list[dict]] = {}

    for repo_info in REPOS:
        repo_name = repo_info["name"]
        repo_path = repo_info["path"]
        print(f"=== Discovering advisories for {repo_name} ===")

        if repo_info["manifest_type"] == "pipfile":
            lock_path = repo_path / "Pipfile.lock"
            pinned = parse_pipfile_lock(lock_path.read_text(encoding="utf-8"))
        else:
            req_path = repo_path / "requirements.txt"
            pinned = parse_requirements_txt(req_path.read_text(encoding="utf-8"))

        queries = []
        pkg_map = {}
        for p in pinned:
            if not p.version:
                continue
            queries.append({
                "package": {"name": p.name, "ecosystem": "PyPI"},
                "version": p.version,
            })
            pkg_map[canonicalize_name(p.name)] = p.version

        print(f"  Sending {len(queries)} queries to OSV batch API...")
        batch_res = query_osv_batch(queries)

        advisories_found = []
        for i, q_res in enumerate(batch_res):
            pkg_name = queries[i]["package"]["name"]
            pkg_ver = queries[i]["version"]
            # Exclude data-only packages like certifi
            if canonicalize_name(pkg_name) in ("certifi", "chardet", "idna", "tzdata"):
                continue

            vulns = q_res.get("vulns", [])
            for v in vulns:
                adv_id = v.get("id")
                # Look for fix commit in references
                fix_commits = []
                for ref in v.get("references", []):
                    u = ref.get("url", "")
                    if "/commit/" in u and ("github.com" in u or "gitlab.com" in u):
                        fix_commits.append(u)

                # Check summary or details
                summary = v.get("summary") or v.get("details", "")[:120]
                advisories_found.append({
                    "id": adv_id,
                    "package": pkg_name,
                    "version": pkg_ver,
                    "summary": summary,
                    "fix_commits": fix_commits,
                    "has_fix_commit": len(fix_commits) > 0,
                    "raw_vuln": v,
                })

        # Sort: prioritize advisories that have a fix commit
        advisories_found.sort(key=lambda x: not x["has_fix_commit"])

        # Deduplicate and cap at 5
        seen = set()
        capped = []
        for a in advisories_found:
            if a["id"] not in seen:
                seen.add(a["id"])
                capped.append(a)
                if len(capped) >= 5:
                    break

        print(f"  Found {len(advisories_found)} total advisories. Selected top {len(capped)}:")
        for c in capped:
            fix_str = " [FIX COMMIT]" if c["has_fix_commit"] else ""
            print(f"    • {c['id']} ({c['package']}=={c['version']}){fix_str}: {c['summary'][:60]}")

        results[repo_name] = capped

    out_file = Path("real_eval/target_advisories.json")
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nSaved target advisories to {out_file.resolve()}")


if __name__ == "__main__":
    main()
