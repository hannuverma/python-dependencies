"""Direct runtime tracer for Pillow demo cases running under Python 3.12 without C-extension mocking."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path


def trace_case(case_name: str, entry_file: Path) -> None:
    executed_targets: list[str] = []
    print(f"\n--- Running {case_name} ({entry_file}) ---")

    def tracer(frame, event, arg):  # type: ignore
        if event == "call":
            fn = frame.f_code.co_name
            if fn == "eval":
                mod = frame.f_globals.get("__name__", "")
                executed_targets.append(f"{mod}:{fn} at line {frame.f_lineno}")
        return tracer

    sys.settrace(tracer)
    try:
        runpy.run_path(str(entry_file), run_name="__main__")
        print("Execution completed normally without uncaught exceptions.")
    except Exception as exc:
        print(f"Exception caught during execution: {type(exc).__name__}: {exc}")
    finally:
        sys.settrace(None)

    print(f"Traced calls to 'eval': {executed_targets}")
    print(f"Result: {'CALLED (EXECUTED)' if executed_targets else 'NOT CALLED (DID NOT EXECUTE)'}")


def main() -> None:
    cases = [
        ("case1_pillow_reachable", Path("demo/case1_reachable/main.py")),
        ("case2_pillow_not_reachable", Path("demo/case2_not_reachable/main.py")),
        ("case3_pillow_uncertain", Path("demo/case3_uncertain/main.py")),
    ]
    for name, path in cases:
        trace_case(name, path)


if __name__ == "__main__":
    main()
