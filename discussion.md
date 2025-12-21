# Discussion / Report Notes (living document)

This file is a running collection of **high-signal points to mention in the report + practical discussion**:
design decisions, guarantees, limitations, and how to justify tradeoffs.

---

## Tool overview (what it does)

- **Goal**: detect potentially dangerous information flows (taint flows) from **sources** to **sinks**, and record whether the flow is **explicit** or **implicit**, and which **sanitizers** intercepted the flow.
- **Inputs**:
  - a Python slice (`.py`)
  - a JSON list of vulnerability patterns (`.patterns.json`)
- **Output**: `./output/<slice>.output.json` listing vulnerabilities per **(pattern, source occurrence, sink occurrence)**, including:
  - `flows`: `["explicit"|"implicit", [[sanitizer, line], ...]]`

---

## Patterns (how configuration affects the analysis)

- **Patterns define policy**:
  - which names count as **sources**, **sanitizers**, and **sinks**
  - whether **implicit** flows should be considered (`implicit: "yes"` vs `"no"`)
- **Why this matters**: the *same slice* can yield different reported vulnerabilities depending on the pattern file.
- **Sanitizers**:
  - We treat “sanitization” as **name-based interception** (the data is returned by a sanitizer function), and still report the vulnerability but with sanitizers listed.
  - **Limitation**: name-based sanitization is not semantic validation; a sanitizer can be misused or insufficient.

---

## Flow model (explicit vs implicit)

- **Explicit flows**: flow from a source into an expression/variable through data dependencies (assignments, expression composition, call arguments, etc.).
- **Implicit flows**: flow from a source into a value through **control dependence** (e.g., branches/loops whose conditions depend on tainted data).
- **PC (“program counter”) taint**:
  - Track taint of conditions dominating the current region (ifs/whiles/for) and incorporate it as **implicit** influence on assignments and calls inside that region.

### Key example to explain implicit flow (IfExp)

- Even if both branches are constants, the choice is influenced by a tainted condition:
  - `x = "safe" if a == "1" else "ok"`
  - If `a` comes from a source, then `x` is **implicitly** influenced by that source.
  - If pattern has `implicit: "yes"`, calling a sink with `x` should be reported as an **implicit** flow.

---

## Loop analysis: bounded fixpoint (precision/soundness tradeoff)

- **Why loops are hard**: potentially infinite paths; naive full path enumeration is impossible.
- **Approach**: bounded **fixpoint iteration** for `while` and `for`:
  - Start with the pre-loop state (0 iterations possible).
  - Iterate: analyze the body, join the body’s resulting labelling back to the loop head.
  - Stop when either:
    - labels **stabilize** (no changes), or
    - a max iteration bound is reached.
- **Why it helps**:
  - **Precision**: stops early when additional iterations don’t change labels (avoids over-propagating effects).
  - **Soundness within bound**: captures effects that only appear after a few iterations, better than a single-pass approximation.
- **Limitation**: still an approximation; if behavior requires more iterations than the bound, it may be missed (false negatives).

---

## Testing strategy (what to emphasize)

- **Official fixtures**: tool matches all provided slices under `specification-master/slices/**`.
- **Local regression suite**: added `my_tests/` with focused tests covering:
  - `AugAssign`, `For`, literals (`list/tuple/set/dict`), `IfExp`, kwargs, sanitizer chains, attributes, subscripts.
- **Runner**: `run_tests.py` compares JSON structure (ignoring whitespace) to catch regressions.
- **Realistic pattern demos**: added `real_patterns_tests/` with 5 small slices (XSS/SQLi/CommandInjection/PathTraversal/SSRF) that demonstrate:
  - an **unsanitized** flow and a **sanitized** flow for each pattern (sanitizer should appear in `flows`).
- **Beyond sanitized vs unsanitized**: extended `real_patterns_tests/` with additional scenarios:
  - implicit-flow examples (`implicit: "yes"`) where the sink argument is constant but control-dependent on tainted input
  - sanitizer misuse (sanitizer called but return value not used → still unsanitized)
  - extra vulnerability types (e.g., insecure deserialization, open redirect) via dedicated pattern files
- **Important caveat (test oracle)**:
  - If you auto-generate “expected outputs” by running your own analyser, the tests mainly protect against **regressions**, not against the analyser being wrong.
  - To claim correctness, manually review a few key expected outputs and include targeted tests where the expected result is obvious (unsanitized must be reported; sanitized must list sanitizer; implicit depends on the `implicit` flag).

---

## Known limitations (good material for critical analysis)

- **Alias analysis not implemented**:
  - multiple names referring to the same object can cause missed/extra flows.
- **Dynamic dispatch / reflection not modeled**:
  - `getattr`, `eval`, dynamic imports, monkey patching, etc.
- **Semantic sanitizer validation not implemented**:
  - sanitizer correctness depends on meaning, not only name.
- **Approximate control flow**:
  - bounded fixpoint for loops; limited treatment of less common constructs.
- **Python scope/model simplifications**:
  - no precise modeling of functions, returns, call stacks, or object heap beyond simple attributes/subscripts.

---

## Suggested “what I would do next” (optional, for bonus/robustness)

- Add more constructs: `Return`, `Break/Continue`, `Try/Except`, comprehensions, f-strings.
- Add a CLI option/env var for loop bound and/or fixpoint max iterations.
- Add optional debugging mode: dump intermediate labellings per line to aid explanation.


