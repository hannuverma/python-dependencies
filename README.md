# pyreach: Sound Python Vulnerability Reachability Analyzer

A sound, static analysis reachability analyzer for Python package dependencies.
Inspired by Go's `govulncheck`, `pyreach` analyzes Python projects against OSV vulnerability advisories, proving whether vulnerable dependency code is actually in the application's execution path.

## Key Features
- **Soundness over precision**: Never marks reachable vulnerable code as unreachable. When in doubt, emits `UNCERTAIN`.
- **Inter-procedural Call Graph**: Multi-source BFS traversal across application entry points, direct dependencies, and transitive packages.
- **Dynamic Feature Classification**: Detects `getattr`, `eval`, `exec`, dynamic imports, plugin loaders (`entry_points()`), and monkey-patching.
- **Class Hierarchy Analysis (CHA)**: Over-approximates polymorphic subclass method overrides.
- **C-Extension Isolation**: Pinpoints compiled `.so`/`.pyd` boundaries without blacklisting pure-Python code in mixed packages.
- **Hermetic Docker Sandbox**: Executes static analysis inside an isolated container with `--network none`.
- **OpenVEX Statement Generation**: Emits cryptographically verifiable VEX documents (`not_affected`, `vulnerable_code_not_in_execute_path`) strictly for `NOT_REACHABLE` findings.

## Quick Start
```bash
# Scan a project directory against OSV advisory IDs
pyreach scan /path/to/project -a GHSA-3f63-hfp8-52jq -o ./out

# Inspect findings report
pyreach explain ./out/findings.json
```
