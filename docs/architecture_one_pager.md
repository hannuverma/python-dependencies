# pyreach: Architecture Specification & Core Design Decisions

## 1. How does pyreach balance soundness vs. precision in Python without an explicit call graph?

Python lacks compile-time type manifests and explicit entry points. To solve this without producing false negatives or succumbing to unbounded false positives, `pyreach` implements a tiered static analysis architecture:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Advisory Resolution: OSV JSON -> Git Fix Patch -> AST Pre-Fix Mining      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. Unified Inter-Procedural Call Graph Builder spanning:                     │
│    Application Code  ──>  Direct Dependencies  ──>  Transitive Dependencies │
│    • ModuleInit nodes execute on import (import pkg -> pkg:<module_init>)   │
│    • Forward references, decorators, and callbacks tracked as call edges    │
│    • Class Hierarchy Analysis (CHA): polymorphic method over-approximation  │
│    • Multi-source Breadth-First Search (BFS) originating from ALL roots     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. Soundness Firewall (NamespaceTouchAuditor & VerdictEngine)                │
│    • Condition A (Scope), Condition B (Provenance), Condition C (Reflection)│
│    • If ANY uncertainty exists -> UNCERTAIN (NEVER false NOT_REACHABLE)     │
│    • If provably disjoint and call path is empty -> NOT_REACHABLE + OpenVEX │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Core Soundness Guarantees:
1. **Multi-Source BFS**: Reachability is not checked from a single arbitrary file; BFS initiates simultaneously from all registered application entry points (`__main__` guards, CLI scripts, FastAPI/Flask/Django routes, Celery tasks, or package public APIs).
2. **Zero-Hop Paths**: When an entry point is itself the vulnerable target, reachability returns a 1-hop path and is never evaluated falsy.
3. **Class Hierarchy Analysis (CHA)**: When a method is invoked on a base class reference (`obj.handle()`), `pyreach` indexes all known subclasses and over-approximates edges to every subclass override that implements `handle()`.
4. **Decoy Differentiation**: Target matching enforces a 3-tuple `(package, module, qualified_name)`, preventing collision with functions of the same name in different packages.

---

## 2. How does pyreach handle dynamic Python features?

Dynamic Python constructs (`getattr`, `setattr`, `__import__`, `eval`, `exec`, `entry_points()`, monkey-patching) are handled through a mathematical formulation of **Namespace Touch Auditing**:

Let $D$ be a target dependency with active vulnerability alerts, and $\mathcal{N}(D)$ denote its namespace. A dynamic site $S$ touches $\mathcal{N}(D)$ if and only if:
- **Condition A (Scope Reachability)**: $D$ is imported in the enclosing module, and the dynamic site is unresolvable or an unresolved dynamic import (`__import__(expr)`).
  - *Precision exception*: If the dynamic receiver is an explicit, imported module (such as `sys`, `math`, `json`) provably disjoint from $D$, calls on it (e.g. `getattr(sys, "version")`) are directed away and do **not** poison $D$.
- **Condition B (Object Origin & Provenance)**: The receiver object originates from an instantiation or return value of $D$, or is passed as an untyped parameter into a scope importing $D$.
- **Condition C (Non-Constant Reflection)**: A `getattr(target, attr_name)` has a non-constant attribute expression and operates on a receiver whose candidate type set includes classes in $D$.
- **Condition 0 (Monkey-Patching)**: An assignment modifies attributes of an imported module or class belonging to $D$ (`vuln_pkg.func = lambda: ...`).

**The Soundness Invariant:** If any dynamic site touching $\mathcal{N}(D)$ is reachable from project entry points, `Verdict(D) != NOT_REACHABLE`. The verdict **must** be `UNCERTAIN`, citing the exact `file:line` location and triggered condition.

---

## 3. How does the system scale to enterprise monorepos and manage cache invalidation?

Analyzing thousands of dependencies across large codebases requires sub-second incremental execution. `pyreach` deploys a four-part deterministic SQLite on-disk cache located at `~/.cache/pyreach/summary_cache.db`:

$$\text{CacheKey} = \text{SHA256}\Big(\text{canonicalize\_name}(pkg) \,\|\, version \,\|\, \text{wheel\_sha256} \,\|\, \text{analyzer\_version}\Big)$$

### Cache Architecture & Invalidation Mechanics:
1. **Pre-Computed Package Summaries**: Stores indexed `CallGraphNode` models, inter-module `CallGraphEdge` lists, detected `native_modules` (`.so`/`.pyd`), and declared `top_level_modules` from wheel metadata (`top_level.txt` / `RECORD`).
2. **Wheel Hash Invalidation**: If an upstream dependency is re-uploaded or tampered with without a version bump, the SHA-256 hash of the archive shifts, immediately triggering a cache miss and re-parse.
3. **Analyzer Version Bump**: Updating `pyreach` (e.g. `0.1.0` -> `0.2.0`) invalidates all cached summaries instantly, preventing stale AST representations from persisting across algorithm enhancements.
4. **Performance**: Cold parsing and AST indexing of a large package (Pillow 10.1.0, 114 files) takes ~670ms; cache retrieval completes in **0.98ms**—a **682x speedup**, enabling fast scans in CI/CD pipelines.
