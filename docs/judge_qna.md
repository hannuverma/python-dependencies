# pyreach: 15 Hard Judge Questions & Honest Senior-Staff Answers

### Q1: "Reachable is not exploitable." If a project calls a vulnerable function with hardcoded, sanitized arguments, why flag it REACHABLE?
**Answer:** Static reachability analysis answers: *can program execution flow into the vulnerable function body?* Proving that arguments are sanitized requires full symbolic execution, abstract interpretation, or satisfiability modulo theories (SMT), which are computationally undecidable at scale and prone to subtle bypasses. Calling a vulnerable function with hardcoded inputs today does not prevent a developer from adding user input tomorrow. We report `REACHABLE` with the exact call path and confidence level, giving security engineers the evidence to decide exploitability, while ensuring zero false negatives.

### Q2: How does pyreach handle native C/Rust extensions (.so/.pyd) that execute Python callbacks internally?
**Answer:** This is a documented, fundamental limitation of AST-level static analysis. If a Python application calls into a compiled native extension (e.g. `PIL._imaging`), the internal behavior of the compiled binary is a black box. If the vulnerable symbol lives inside native code, or if the discovered call path passes through a native module, `pyreach` marks the finding `UNCERTAIN (c_extension)`. We never falsely claim `NOT_REACHABLE` when a native bridge exists in the call path.

### Q3: How do you handle star imports (`from pkg import *`) where symbol bindings are ambiguous?
**Answer:** In `extract_module_imports`, `from pkg import *` statements are tracked in `star_imports`. When resolving call targets, if a symbol cannot be resolved locally or via explicit imports, the analyzer searches all public exported symbols (`__all__` or non-underscored names) of star-imported modules. If the target matches an export from a star-imported module, an edge is created. If ambiguous, the presence of star imports touching the target package triggers `UNCERTAIN`.

### Q4: What about runtime monkey-patching? Can an upstream library or middleware replace functions before they are called?
**Answer:** In `NamespaceTouchAuditor`, Condition 0 specifically audits assignment targets (`ast.Assign`) where the receiver expression is an imported module or class. If any code in the project executes `vuln_pkg.func = custom_impl`, this is flagged as monkey-patching. If the target package is patched, `pyreach` emits `UNCERTAIN (monkey_patch)` because static AST edges can no longer be guaranteed at runtime.

### Q5: Why mark dynamic plugin loading via `pkg_resources` or `importlib.metadata.entry_points()` as UNCERTAIN?
**Answer:** Plugin registries are open-world dispatchers: packages register plugins via `setup.py` / `pyproject.toml`, and applications load and execute whatever is installed in the Python environment without naming the classes in Python code. If an application calls `entry_points(group=...)` and invokes the loaded plugins, any installed dependency could be invoked. Proving unreachability under dynamic plugin discovery is unsound, so `pyreach` emits `UNCERTAIN (entry_point_plugin)`.

### Q6: If a transitive dependency listed in the lockfile cannot be downloaded or parsed, why not assume it is dead code?
**Answer:** Assuming missing code is uncalled violates the cardinal rule of soundness over precision. A missing dependency in a call chain could be the re-exporter or intermediary connecting the application to the vulnerable function (e.g. `Project -> requests -> urllib3`). If any package in the dependency tree fails to fetch or parse (`files_failed > 0`), `pyreach` fails safe to `UNCERTAIN (missing_dependency_source / parse_error)`.

### Q7: If a single file in a dependency package has a Python 2 syntax error, why fail the whole package to UNCERTAIN?
**Answer:** In Python packages, a syntax error means the AST cannot be generated. We cannot know whether that file contained the single public function the project called or re-exported. Skipping the file creates an invisible hole in the graph. `pyreach` tracks `files_total`, `files_parsed`, and `files_failed` per package: if `files_failed > 0`, proof of unreachability is forfeited, and the verdict remains `UNCERTAIN`.

### Q8: Class Hierarchy Analysis (CHA) over-approximates all subclass method overrides. Doesn't this cause high false positives?
**Answer:** CHA intentionally trades some precision for absolute soundness in object-oriented dispatch. When code calls `handler.process()`, Rapid Type Analysis (RTA) or points-to analysis requires whole-program closed-world analysis. In libraries or modular frameworks, subclasses are instantiated dynamically. By over-approximating all subclass implementations of `process()`, we guarantee we never miss a path where a subclass override calls vulnerable code.

### Q9: Why does wheel selection for static source analysis not depend on the host operating system or local Python ABI tag?
**Answer:** Static analysis parses Python source code text into ASTs; it does not execute machine bytecode. When an engineer on Windows analyzes an application deployed to Linux, downloading only Windows wheels would fail for Linux-only packages. `HTTPPyPIClient` prioritizes universal pure-Python wheels (`none-any.whl`), accepts any platform wheel containing Python source files, and falls back to sdist `.tar.gz`, ensuring identical analysis across all platforms.

### Q10: Why do LLM-extracted advisory symbols strictly forbid a NOT_REACHABLE verdict?
**Answer:** LLMs are probabilistic models prone to hallucinations and omissions. If an advisory had no fix commit and we used an LLM to guess which function was vulnerable, and the LLM guessed wrong or missed a function, our static analyzer would "prove" that function was not called and falsely emit an OpenVEX statement claiming the application is safe. Therefore, under `pyreach` soundness rules, any symbol originating from LLM fallback (`SymbolEvidenceSource.LLM_FALLBACK`) caps the best negative verdict at `UNCERTAIN`.

### Q11: How do you prevent cache poisoning if an author modifies a package release on a private index without bumping the version?
**Answer:** The cache key does not rely solely on `package_name` and `version`. The key is a SHA-256 digest of `(canonical_name, version, wheel_sha256, analyzer_version)`. If the wheel contents change by a single byte, its SHA-256 hash changes, producing an automatic cache miss and forcing a clean re-index.

### Q12: How are `eval()` and `exec()` calls handled?
**Answer:** `eval()` and `exec()` execute arbitrary Python code from string expressions at runtime. If an application contains `eval()` or `exec()` in a module that imports the target dependency, `NamespaceTouchAuditor` marks it as `UNCERTAIN (eval_exec)`. Static analysis cannot inspect runtime string concatenation.

### Q13: What if an application calls a function in Package A, which imports and re-exports a function from vulnerable Package B?
**Answer:** `CallGraphBuilder` shares a global module import table (`all_module_imports`). When `_resolve_direct_call` or `_resolve_attribute_call` resolves an imported symbol, it recursively follows the alias chain across module and package boundaries until it reaches the originating definition in Package B, ensuring transitive re-exports are linked in the call graph.

### Q14: How are generated OpenVEX statements validated and structured?
**Answer:** OpenVEX documents are emitted strictly for `NOT_REACHABLE` findings with `status: "not_affected"` and `justification: "vulnerable_code_not_in_execute_path"`. The output adheres to the OpenVEX v0.2.0 JSON-LD specification, including author metadata, RFC 3339 timestamps, target package Package URLs (purl, e.g. `pkg:pypi/pillow@10.1.0`), and impact statements citing static call graph analysis under CHA rules.

### Q15: How does pyreach compare to Go's govulncheck, and what are Python's theoretical limits?
**Answer:** `govulncheck` benefits from Go's statically typed, compiled nature, explicit package exports, and standard advisory database maintained by the Go security team with exact symbol coordinates. Python has dynamic typing, monkey-patching, `__getattr__`, meta-programming, and a PyPA advisory database where less than 0.1% of advisories identify affected functions. `pyreach` demonstrates that by mining Git commit diffs and enforcing strict namespace touch auditing, sound vulnerability reachability analysis in Python is not only theoretically viable, but fast and practical.
