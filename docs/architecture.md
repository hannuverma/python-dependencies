# pyreach Architecture & Soundness Specification

## Definition: When a Dynamic Site "Touches" a Dependency Namespace

A central requirement of sound vulnerability reachability analysis in Python is determining whether an unresolvable dynamic construct could plausibly execute code within a third-party dependency.

Let $D$ be a target dependency package (e.g. `urllib3`).
Let $\mathcal{N}(D)$ denote the namespace of $D$, defined as the set of all modules, classes, functions, and attributes belonging to $D$ or re-exported by $D$.

A dynamic site $S$ in project or intermediate dependency code is said to **touch the dependency namespace** $\mathcal{N}(D)$ if and only if at least one of the following three conditions holds:

---

### Condition A: Import or Re-export Scope Reachability
The dynamic site $S$ occurs in a scope (module or callable) where:
1. Module $D$ or any submodule $D.m$ is imported (directly or via aliasing: `import D`, `from D import x`, `import D as alias`).
2. Any module that re-exports symbols from $D$ is imported in that scope (e.g. `requests.packages.urllib3`).
3. An unresolved dynamic import occurs (`importlib.import_module(expr)`, `__import__(expr)`), where $expr$ is non-constant or evaluates to a candidate string whose prefix matches $D$ or an alias of $D$.

---

### Condition B: Object Origin and Dataflow Taint
The dynamic site $S$ operates on a receiver object $O$ whose type or provenance cannot be proven to exclude $\mathcal{N}(D)$:
1. **Direct Instance Origin**: $O$ is an instance or reference returned by a function, method, or class instantiated from $D$ (e.g. `client = urllib3.PoolManager(); getattr(client, method_name)`).
2. **Inter-procedural Parameter Taint**: $O$ is passed as an argument into the enclosing function from an external caller, and points-to analysis cannot eliminate instances of classes defined in $D$ from the candidate set of $O$.
3. **Container / Collection Extraction**: $O$ is retrieved from a heterogeneous container (`dict`, `list`, registry) into which any object from $D$ was stored.

---

### Condition C: Non-Constant Reflection with Plausible Target Set
The dynamic site $S$ invokes reflection (`getattr(target, attr_name)`, `setattr`, `hasattr`, or dictionary lookup on `globals()` / `sys.modules`) where:
1. $attr_name$ is a non-constant runtime expression (variable, function return value, user input).
2. The receiver $target$ is:
   - A module belonging to $D$,
   - An object originating from $D$ (per Condition B), or
   - An unresolved object whose plausible type set includes classes in $D$.
3. When constant string analysis or enum propagation cannot narrow the possible values of $attr_name$ to a finite set of known safe attributes disjoint from the affected symbols of $D$.

---

## Soundness Rule Enforced by This Definition

If any dynamic site $S$ reachable from project entry points satisfies **Condition A, Condition B, or Condition C** for a dependency $D$ with an active advisory:

$$\text{Verdict}(D) \neq \text{NOT\_REACHABLE}$$

The analyzer **must** emit `UNCERTAIN`, logging:
- The exact syntactic location (`file:line`),
- The specific condition triggered (A, B, or C),
- The dynamic construct category (e.g. `getattr_non_constant`, `dynamic_import`, `reflection`), and
- The receiver and attribute expressions involved.
