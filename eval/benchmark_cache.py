"""Benchmark cold vs cached analysis timing with 5 runs each using time.perf_counter."""

from __future__ import annotations

import shutil
import statistics
import time
from pathlib import Path

from typer.testing import CliRunner

from pyreach.cli import app


def run_benchmark(target_project: Path, advisory_id: str, runs: int = 5) -> dict[str, list[float]]:
    runner = CliRunner()
    cache_root = Path.home() / ".cache" / "pyreach"

    cold_timings: list[float] = []
    print(f"--- Running {runs} Cold Analysis Iterations ---")
    for i in range(1, runs + 1):
        if cache_root.exists():
            shutil.rmtree(cache_root, ignore_errors=True)

        t0 = time.perf_counter()
        result = runner.invoke(app, ["scan", str(target_project), "-a", advisory_id])
        elapsed = time.perf_counter() - t0

        if result.exit_code != 0:
            raise RuntimeError(f"Cold run {i} failed: {result.stdout}")

        cold_timings.append(elapsed)
        print(f"  Cold Run {i}: {elapsed:.4f}s")

    cached_timings: list[float] = []
    print(f"\n--- Running {runs} Cached Analysis Iterations ---")
    for i in range(1, runs + 1):
        t0 = time.perf_counter()
        result = runner.invoke(app, ["scan", str(target_project), "-a", advisory_id])
        elapsed = time.perf_counter() - t0

        if result.exit_code != 0:
            raise RuntimeError(f"Cached run {i} failed: {result.stdout}")

        cached_timings.append(elapsed)
        print(f"  Cached Run {i}: {elapsed:.4f}s")

    cold_mean = statistics.mean(cold_timings)
    cold_stdev = statistics.stdev(cold_timings) if len(cold_timings) > 1 else 0.0
    cached_mean = statistics.mean(cached_timings)
    cached_stdev = statistics.stdev(cached_timings) if len(cached_timings) > 1 else 0.0
    speedup = cold_mean / cached_mean if cached_mean > 0 else 0.0

    print("\n--- Benchmark Results Summary ---")
    print(f"Cold runs ({runs}):   mean = {cold_mean:.3f}s ± {cold_stdev:.3f}s (min: {min(cold_timings):.3f}s, max: {max(cold_timings):.3f}s)")
    print(f"Cached runs ({runs}): mean = {cached_mean:.3f}s ± {cached_stdev:.3f}s (min: {min(cached_timings):.3f}s, max: {max(cached_timings):.3f}s)")
    print(f"Cache speedup:      {speedup:.1f}x faster")

    return {
        "cold": cold_timings,
        "cached": cached_timings,
    }


if __name__ == "__main__":
    run_benchmark(Path("demo/case1_reachable"), "GHSA-3f63-hfp8-52jq", runs=5)
