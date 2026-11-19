"""Independent process tracer for running repo entry points and tests under sys.setprofile."""

from __future__ import annotations

import argparse
import json
import os
import runpy
import sys
import unittest
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Trace function calls during execution.")
    parser.add_argument("--repo-path", required=True, help="Path to repo directory.")
    parser.add_argument("--entry-file", help="Relative path to entry file to execute.")
    parser.add_argument("--entry-snippet", help="Python code snippet to execute as entry.")
    parser.add_argument("--test-dir", help="Relative path to test directory or test file.")
    parser.add_argument("--target-symbols", default="", help="Comma-separated target symbols to check.")
    parser.add_argument("--out", required=True, help="Output JSON path.")
    args = parser.parse_args()

    repo_path = Path(args.repo_path).resolve()
    target_symbols = [s.strip() for s in args.target_symbols.split(",") if s.strip()]

    # Normalize targets: track full qualnames and leaf function names
    target_leaves = {s.split(":")[-1].split(".")[-1]: s for s in target_symbols}

    executed_calls: set[str] = set()
    hit_targets: set[str] = set()
    caught_exception: str | None = None

    def trace_func(frame, event, arg):  # type: ignore
        if event in ("call", "c_call"):
            code = getattr(frame, "f_code", None)
            func_name = code.co_name if code else str(arg)
            qual_name = getattr(code, "co_qualname", func_name) if code else func_name
            mod_name = frame.f_globals.get("__name__", "")
            call_sig = f"{mod_name}.{qual_name}" if mod_name else qual_name
            executed_calls.add(call_sig)

            # Check if this call matches any target symbol with module-level precision
            for ts in target_symbols:
                # Match full qualified name or module:qualname
                if call_sig == ts or call_sig.endswith(f".{ts}") or ts == f"{mod_name}.{func_name}":
                    hit_targets.add(ts)
                elif ":" in ts:
                    ts_mod, ts_qual = ts.split(":", 1)
                    if mod_name == ts_mod and (qual_name == ts_qual or func_name == ts_qual):
                        hit_targets.add(ts)

        return trace_func

    # Prepare environment
    orig_cwd = os.getcwd()
    orig_path = list(sys.path)
    os.chdir(repo_path)
    if str(repo_path) not in sys.path:
        sys.path.insert(0, str(repo_path))

    sys.setprofile(trace_func)
    try:
        if args.entry_snippet:
            exec(args.entry_snippet, {"__name__": "__main__"})
        elif args.entry_file:
            entry_full = (repo_path / args.entry_file).resolve()
            if entry_full.exists():
                runpy.run_path(str(entry_full), run_name="__main__")
            else:
                caught_exception = f"FileNotFoundError: {entry_full}"
        elif args.test_dir:
            test_full = (repo_path / args.test_dir).resolve()
            loader = unittest.TestLoader()
            if test_full.is_file():
                suite = loader.discover(str(test_full.parent), pattern=test_full.name)
            else:
                suite = loader.discover(str(test_full))
            runner = unittest.TextTestRunner(stream=open(os.devnull, "w"), verbosity=0)
            runner.run(suite)
    except Exception as exc:
        caught_exception = f"{type(exc).__name__}: {exc}"
    finally:
        sys.setprofile(None)
        os.chdir(orig_cwd)
        sys.path = orig_path

    was_called = len(hit_targets) > 0
    result = {
        "repo": repo_path.name,
        "target_symbols": target_symbols,
        "hit_targets": list(hit_targets),
        "total_calls_recorded": len(executed_calls),
        "status": "CALLED" if was_called else "NOT CALLED",
        "was_called": was_called,
        "exception": caught_exception,
    }

    out_p = Path(args.out)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Tracer finished: status={result['status']}, hit_targets={result['hit_targets']}, exc={caught_exception}")


if __name__ == "__main__":
    main()
