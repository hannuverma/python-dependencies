# pyreach: Architecture Specification & Core Design Decisions

## (a) Fix Commit to Vulnerable Functions and Confidence Scoring

Python vulnerability advisories in the PyPA and OSV databases almost never provide machine-readable affected function names. `pyreach` resolves vulnerable symbols directly from upstream fix commits:

1. **Advisory Ingestion & Commit Mining**:
   - Parses the OSV advisory JSON record, extracting fix commit URLs from `references` (e.g. `github.com/org/repo/commit/<sha>`).
   - Fetches the raw git patch and filters out non-code files (documentation, tests, CI workflows, packaging manifests).
2. **AST Pre-Fix Mining**:
   - Analyzes the source code *prior* to the fix to discover the vulnerable constructs that existed in affected versions.
   - Maps the patch hunk line intervals (lines deleted or modified) to enclosing AST nodes: `FunctionDef`, `AsyncFunctionDef`, and `ClassDef`.
   - Normalizes function signatures into canonical 3-tuples: `(package, module, qualified_name)`.
3. **Confidence Scoring Rules**:
   - `HIGH`: Direct git commit diff parsed; AST uniquely identified the enclosing function or method definition.
   - `MEDIUM`: Patch hunk modified module-level statements or class body definitions rather than a single function; target symbols are conservatively expanded to the module's public API.
   - `LOW`: AST extraction was ambiguous or relied on the offline LLM fallback miner.
   - **Soundness Invariant**: If *any* target symbol for an alert was derived via LLM fallback or imprecise heuristics, `NOT_REACHABLE` is strictly forbidden (the best possible negative verdict is `UNCERTAIN`).

---

## (b) Handling Dynamic Python Features Without Pretending Certainty

Dynamic Python constructs (`getattr`, `setattr`, `__import__`, `eval`, `exec`, `entry_points()`, monkey-patching) cannot be completely resolved statically when attribute or module names are non-constant. Instead of pretending certainty (which causes false negatives), `pyreach` implements a **Namespace Touch Auditor** enforcing documented over-approximation rules:

Let $D$ be a target dependency package with an active advisory, and $\mathcal{N}(D)$ denote its namespace:

- **Condition A (Import & Dynamic Import Scope)**:
  - **A.1**: Target package $D$ is imported in the same file/scope containing an unresolvable dynamic construct.
  - **A.3**: An unresolvable dynamic import occurs (`__import__(expr)`, `importlib.import_module(expr)`), where $expr$ is non-constant and could resolve to $D$.
- **Condition B (Object Origin & Provenance)**:
  - **B.1**: The receiver object originates from an instantiation or return value of $D$, or is passed as an untyped parameter into a scope using $D$.
- **Condition C (Non-Constant Reflection)**:
  - **C.1**: `getattr(target, attr_name)` has a non-constant attribute expression and operates on a receiver whose candidate type set includes classes or modules in $D$.
  - **C (Monkey-Patching)**: Assignment modifies attributes of an imported module or class belonging to $D$ (`vuln_pkg.func = patch`).
- **Precision Refinement (Candidate Attribute Set Pruning)**:
  - If a delegating `__getattr__` operates on a receiver of known type whose candidate attribute set cannot contain the vulnerable symbol (e.g. `self._img` of type `PIL.Image.Image` when the vulnerable symbol is `PIL.ImageMath.eval`), it does **not** touch the namespace and does not block `NOT_REACHABLE`.

**The Soundness Firewall**: If any dynamic site touching $\mathcal{N}(D)$ is reachable from project entry points, `Verdict(D) != NOT_REACHABLE`. The verdict **must** be `UNCERTAIN` (Confidence: `HIGH`, because the existence of the dynamic construct was verified), citing the exact `file:line` location and triggered condition.

---

## (c) Caching of Popular Packages and Invalidation Mechanics

Re-parsing large third-party dependencies on every scan adds significant latency. `pyreach` implements a deterministic on-disk SQLite cache (`~/.cache/pyreach/summary_cache.db`):

$$\text{CacheKey} = \text{SHA256}\Big(\text{canonicalize\_name}(pkg) \,\|\, version \,\|\, \text{wheel\_sha256} \,\|\, \text{analyzer\_version}\Big)$$

### Cache Architecture & Invalidation Mechanics:
1. **Pre-Computed Package Summaries**: Stores indexed `CallGraphNode` models, intramodule `CallGraphEdge` lists, detected `native_modules` (`.so`/`.pyd`), and declared `top_level_modules` from wheel metadata (`top_level.txt` / `RECORD`).
2. **Wheel Hash Invalidation**: If an upstream package archive is re-uploaded with the same version but altered contents, the wheel SHA-256 shifts, immediately triggering a cache miss and re-download.
3. **Analyzer Version Invalidation**: Incrementing `pyreach`'s version string (e.g. `0.1.0` -> `0.2.0`) invalidates all cached summaries instantly, preventing stale AST representations from persisting across algorithm enhancements.
4. **Measured Performance (5-run benchmark measured via `time.perf_counter`)**:
   - Existing benchmark record: cold `Pillow==10.1.0` indexing **11.293s ± 0.981s**; cached analysis **2.407s ± 0.118s**.
   - These numbers are historical measurements from the repository benchmark and should be refreshed after analyzer changes.
   - A current local three-run scan of `demo/case1_reachable` measured **10.329s**, **7.782s**, and **5.264s**; no aggregate or speedup claim is inferred from these three runs.

## (d) Soundness guards added after the initial design

- An advisory with no valid affected symbols is always `UNCERTAIN (no_affected_symbols)` and never produces OpenVEX.
- Fixes changing native source are `UNCERTAIN (c_extension)`.
- Django discovery fails closed when settings, URL configuration, and bootstrap roots are not all identifiable.
- Sdist namespace fallback excludes utility directories and preserves standalone modules such as `six.py`.
