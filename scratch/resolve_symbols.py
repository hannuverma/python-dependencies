from __future__ import annotations

import json
from pathlib import Path

from pyreach.advisory.resolver import AdvisorySymbolResolver, HTTPVCSClient
from pyreach.models import Advisory


def main() -> None:
    advisories_file = Path("real_eval/target_advisories.json")
    data = json.loads(advisories_file.read_text(encoding="utf-8"))

    vcs_client = HTTPVCSClient()
    resolver = AdvisorySymbolResolver(vcs_client=vcs_client)

    resolved_data = {}
    for repo_name, adv_list in data.items():
        print(f"\n=== Resolving symbols for {repo_name} ===")
        resolved_list = []
        for item in adv_list:
            adv_id = item["id"]
            pkg = item["package"]
            print(f"  Resolving {adv_id} ({pkg})...")
            adv = Advisory(id=adv_id, package_name=pkg)
            try:
                syms = resolver.resolve(adv)
                item["resolved_symbols"] = [
                    {
                        "symbol": s.qualified_name,
                        "type": s.symbol_type.value,
                        "source": s.source_of_evidence.value,
                        "confidence": s.confidence.value,
                    }
                    for s in syms
                ]
                print(f"    -> Extracted {len(syms)} symbol(s): {[s.qualified_name for s in syms]}")
            except Exception as e:
                item["resolved_symbols"] = []
                print(f"    -> Resolution failed: {e}")
            resolved_list.append(item)
        resolved_data[repo_name] = resolved_list

    out_file = Path("real_eval/resolved_advisories.json")
    out_file.write_text(json.dumps(resolved_data, indent=2), encoding="utf-8")
    print(f"\nSaved resolved advisories to {out_file.resolve()}")


if __name__ == "__main__":
    main()
