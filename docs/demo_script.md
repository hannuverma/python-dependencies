# pyreach: 5-Minute Hackathon Presentation & Live Demo Script

**Total Duration:** 5 minutes (300 seconds)  
**Presenter:** Antigravity Team Lead / Senior Staff Engineer  
**Core Thesis:** Python security scanners flood maintainers with CVE alerts for code they never call. Go has `govulncheck`, but Python had nothing maintained because 99.9% of PyPA advisories lack machine-readable symbol names. `pyreach` bridges this gap: it mines Git fix commit diffs with AST analysis to identify affected symbols, constructs an inter-procedural call graph across project and transitive dependencies with Class Hierarchy Analysis (CHA), enforces uncompromising soundness over precision, and emits cryptographically verifiable OpenVEX statements.

---

## Timeline & Live Terminal Walkthrough

```
[0:00 - 0:45] The Problem & The Solution
[0:45 - 2:00] Live Demo: Case 1 (REACHABLE) & Case 2 (Provably NOT_REACHABLE + OpenVEX)
[2:00 - 3:00] Live Demo: Case 3 (UNCERTAIN - Dynamic Reflection) & Performance Cache
[3:00 - 4:00] Real-World Open-Source Evaluation & Empirical Ground Truth
[4:00 - 5:00] Production Integration: Docker Sandbox, PR Agent & Q&A Hook
```

---

### Minute 1: The Problem & The Core Philosophy [0:00 - 0:45]
**Talking Points:**
> "Every maintainer knows the alert fatigue of software supply chain security: your scanner flags 50 critical CVEs across your lockfile, but your application only imports 3 functions. You spend days triaging or end up ignoring alerts entirely.
> 
> In Go, `govulncheck` solved this by proving reachability. In Python, nobody has done it because advisory databases don't name affected functions.
> 
> We built `pyreach`. `pyreach` is guided by one cardinal rule: **Soundness over precision**. We NEVER mark a reachable vulnerability as unreachable. When dynamic Python features prevent proof of unreachability, we label it `UNCERTAIN` with the exact file and line reason. And when it is provably uncalled, we emit an OpenVEX statement allowing your security team to automatically silence the alert."

---

### Minute 2: Live Demo — Case 1 (REACHABLE) & Case 2 (NOT_REACHABLE) [0:45 - 2:00]

**Action 1:** Run Case 1 (`demo/case1_reachable`).
```powershell
pyreach scan demo/case1_reachable -a GHSA-3f63-hfp8-52jq
```
**Screen Output:**
- Terminal renders clean Rich table: `GHSA-3f63-hfp8-52jq | pillow | 10.1.0 | REACHABLE | HIGH`.
- Evidence Panel below displays:
  `Hop 1: case1_reachable.main.run at main.py:11 (direct)`
  `Hop 2: PIL.ImageMath.eval at main.py:6 (direct)`

**Talking Points:**
> "Here is Case 1. Our application calls `ImageMath.eval` from `main()`. `pyreach` downloads the Pillow wheel, extracts the AST, traces the execution roots, and discovers the multi-hop path into the vulnerable symbol in 2 hops with high confidence."

**Action 2:** Run Case 2 (`demo/case2_not_reachable`).
```powershell
pyreach scan demo/case2_not_reachable -a GHSA-3f63-hfp8-52jq -o demo/case2_not_reachable/out
```
**Screen Output:**
- Table renders: `GHSA-3f63-hfp8-52jq | pillow | 10.1.0 | NOT_REACHABLE | HIGH`.
- Green Panel confirms: `all entry points covered, call graph traversed, zero paths found, zero dynamic constructs touch pillow.`
- Generates `demo/case2_not_reachable/out/openvex.json`.

**Talking Points:**
> "Now look at Case 2. The project imports Pillow and calls safe `Image.new()`. The vulnerable `ImageMath.eval()` call exists inside a dead helper function that is never called.
> 
> `pyreach` traverses the full dependency call graph, proves that no execution path exists from any recognized application entry point, and emits an OpenVEX statement with status `not_affected` and justification `vulnerable_code_not_in_execute_path`. Your enterprise scanner can now ingest this machine-readable VEX to dismiss the CVE automatically."

---

### Minute 3: Case 3 (UNCERTAIN) & SQLite Cache Acceleration [2:00 - 3:00]

**Action 3:** Run Case 3 (`demo/case3_uncertain`).
```powershell
pyreach scan demo/case3_uncertain -a GHSA-3f63-hfp8-52jq
```
**Screen Output:**
- Table renders: `GHSA-3f63-hfp8-52jq | pillow | 10.1.0 | UNCERTAIN | HIGH`.
- Yellow Breakdown Panel displays:
  `• [getattr_non_constant] at main.py:8: Condition A triggered: Package 'pillow' is imported in module 'main' containing dynamic construct 'getattr_non_constant'.`

**Talking Points:**
> "In Case 3, the application uses runtime reflection: `getattr(ImageMath, os.environ.get('PIXEL_OP', 'eval'))`. Other tools guess or pretend this is unreachable.
> 
> `pyreach` never lies. Our `NamespaceTouchAuditor` checks whether reflection touches the imported namespace. Because an attacker or runtime environment could supply 'eval', `pyreach` fails safe to `UNCERTAIN` and highlights line 8 for human review."

**Action 4:** Highlight Performance Speedup.
```powershell
# Show summary cache hit log: ⚡ Package summary cache hit for pillow==10.1.0
```
> "Notice the lightning bolt: `⚡ Package summary cache hit`. On repeated scans, our SQLite package-summary cache eliminates AST re-parsing, going from 670ms to under 1ms—over 600x faster."

---

### Minute 4: Hardened Empirical Ground Truth & Real Open-Source Evaluation [3:00 - 4:00]

**Action 5:** Run the Ground Truth Tracer across all 18 benchmark cases.
```powershell
python eval/ground_truth_tracer.py
```
**Screen Output:**
- Rich table displays 18/18 benchmark and adversarial cases.
- Runtime profiler (`sys.settrace`) compares actual runtime execution against static reachability verdicts.
- Summary table: `Correct Verdicts: 18 / 18 (100.0%) | Unsound Verdicts: 0`.

**Talking Points:**
> "We don't just assert our verdicts; we prove them empirically. We built a runtime execution tracer that executes each fixture under `sys.settrace` in an isolated throwaway environment. If any vulnerable function executes at runtime and `pyreach` had marked it NOT_REACHABLE, our harness fails immediately with a soundness violation.
> 
> Across 18 adversarial scenarios—including subclass overrides, entry-point plugins, import-time execution, and multi-hop re-exports—`pyreach` achieved 100% accuracy with zero unsound false negatives."

---

### Minute 5: Real Project Audit, Hermetic Docker & PR Triage Agent [4:00 - 5:00]

**Action 6:** Highlight Real Project Audit (`python-qrcode`).
> "We tested `pyreach` against real-world production open-source software: `python-qrcode` (3.5k+ stars). When pinned to Pillow 10.1.0, `pyreach` flagged `UNCERTAIN` and pinpointed the exact lines where `python-qrcode` performs dynamic plugin loading (`console_scripts.py:154`) and `__getattr__` delegation (`image/pil.py:54`)."

**Action 7:** Wrap Up with Docker & PR Agent.
> "For enterprise deployment:
> 1. **Hermetic Docker Sandbox**: Executes static analysis inside an isolated container with `--network none` and non-root execution.
> 2. **FastAPI & PR Triage Agent**: Connects to GitHub Actions to comment on PRs. When developers push back claiming false positives, our agent strictly interrogates the stored call path evidence and refuses to compromise soundness rules.
> 
> `pyreach` is ready today to turn Python vulnerability management from alert fatigue into verifiable, evidence-backed security."
