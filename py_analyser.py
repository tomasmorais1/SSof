#!/usr/bin/env python3
from __future__ import annotations

"""
py_analyser.py

Static taint analysis for Python *slices* (small code fragments) according to vulnerability patterns.

High-level pipeline:
  1) Load vulnerability patterns from JSON -> Pattern/Policy
  2) Parse the slice into a Python AST (ast.parse)
  3) Walk the AST:
       - eval_expr(...) returns a MultiLabel: taint flows carried by an expression value
       - exec_stmt(...) updates a MultiLabelling: map from variable-like names -> MultiLabel
       - detect sinks on calls and assignment targets, recording flows in Vulnerabilities
  4) Write JSON output to ./output/<slice>.output.json

Key ideas:
  - Labels track *flows* from (source name, line) to sinks, with a list of sanitizers that intercepted them.
  - Implicit flows are modeled via a "program counter" taint (pc): taint of enclosing conditions/guards.
  - Loops are approximated by a bounded fixpoint: iterate until labels stabilize or we hit a max bound.
"""

import ast
import json
import os
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


FlowKind = str  # "explicit" | "implicit"
SanitizerOcc = Tuple[str, int]  # (name, lineno)
SanitizerSeq = Tuple[SanitizerOcc, ...]
SourceOcc = Tuple[str, int]  # (name, lineno)
SinkOcc = Tuple[str, int]  # (name, lineno)
Flow = Tuple[FlowKind, SourceOcc, SanitizerSeq]


# -----------------------------------------------------------------------------
# Debug tracing (opt-in)
#
# IMPORTANT: The project spec expects the analyser to write ONLY the JSON output
# file and not print extra output. For that reason, debug prints are guarded by
# an environment variable and go to stderr.
#
# Usage:
#   PY_ANALYSER_DEBUG=1 python3 ./py_analyser.py <slice.py> <patterns.json>
# -----------------------------------------------------------------------------

_DEBUG = os.environ.get("PY_ANALYSER_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
_DEBUG_LEVEL = int(os.environ.get("PY_ANALYSER_DEBUG_LEVEL", "1").strip() or "1") if _DEBUG else 0
_DBG_DEPTH = 0
_DBG_EVENT = 0
_DBG_OUT = sys.stderr


def _dbg(msg: str) -> None:
    if not _DEBUG:
        return
    if _DEBUG_LEVEL <= 0:
        return
    global _DBG_EVENT
    _DBG_EVENT += 1
    indent = "    " * _DBG_DEPTH
    # Print an extra blank line after each log entry for readability.
    print(f"{_DBG_EVENT:05d} {indent}{msg}", file=_DBG_OUT)
    print("", file=_DBG_OUT)


class _DbgScope:
    def __init__(self, title: str) -> None:
        self._title = title

    def __enter__(self) -> None:
        global _DBG_DEPTH
        _dbg(f"ENTER {self._title}")
        _DBG_DEPTH += 1

    def __exit__(self, exc_type, exc, tb) -> None:
        global _DBG_DEPTH
        _DBG_DEPTH = max(0, _DBG_DEPTH - 1)
        if exc_type is not None:
            _dbg(f"EXIT  {self._title} (EXC {exc_type.__name__}: {exc})")
        else:
            _dbg(f"EXIT  {self._title}")


def _dbg_init() -> None:
    """
    Configure debug output.

    - Default: stderr
    - If PY_ANALYSER_DEBUG_LOG is set: write to that file (creating parent dirs).
    - You can increase verbosity with PY_ANALYSER_DEBUG_LEVEL=2.
    """
    global _DBG_OUT
    if not _DEBUG or _DEBUG_LEVEL <= 0:
        return
    path = os.environ.get("PY_ANALYSER_DEBUG_LOG", "").strip()
    if not path:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    _DBG_OUT = open(path, "w", encoding="utf-8")  # intentionally not closed (process exit)
    _dbg(f"Debug log file: {path}")


def _ml_summary(ml: "MultiLabel") -> str:
    # small, stable summary: number of flows per vulnerability
    parts = []
    for v in ml._policy.vulnerability_names:
        parts.append(f"{v}:{len(ml.label_for(v).flows())}")
    return "{" + ", ".join(parts) + "}"


def _label_dump(label: "Label") -> str:
    return "[" + ", ".join(f"{kind}:{src[0]}@{src[1]} sans={list(sans)}" for (kind, src, sans) in label.flows()) + "]"


def _ml_dump(ml: "MultiLabel") -> str:
    parts = []
    for v in ml._policy.vulnerability_names:
        parts.append(f"{v}={_label_dump(ml.label_for(v))}")
    return "{ " + "; ".join(parts) + " }"


def _lab_summary(lab: "MultiLabelling") -> str:
    keys = sorted(lab._map.keys())
    if len(keys) > 10:
        keys = keys[:10] + ["..."]
    return f"keys={keys}"


def _lab_dump(lab: "MultiLabelling") -> str:
    parts = []
    for name in sorted(lab._map.keys()):
        ml, uninit = lab._map[name]
        parts.append(f"{name} (uninit={uninit}) = {_ml_dump(ml)}")
    return "\\n".join(parts) if parts else "<empty>"


@dataclass(frozen=True)
class Pattern:
    """One vulnerability pattern: sources/sanitizers/sinks + whether to consider implicit flows."""
    vulnerability: str
    sources: Tuple[str, ...]
    sanitizers: Tuple[str, ...]
    sinks: Tuple[str, ...]
    implicit: bool

    def is_source(self, name: str) -> bool:
        return name in self.sources

    def is_sanitizer(self, name: str) -> bool:
        return name in self.sanitizers

    def is_sink(self, name: str) -> bool:
        return name in self.sinks


class Policy:
    """
    Pattern database / policy helper.

    Given a name (e.g., "execute"), quickly answers:
      - for which vulnerabilities is it a source?
      - for which vulnerabilities is it a sanitizer?
      - for which vulnerabilities is it a sink?
    """
    def __init__(self, patterns: Sequence[Pattern]) -> None:
        self._patterns: Dict[str, Pattern] = {p.vulnerability: p for p in patterns}

    @property
    def vulnerability_names(self) -> List[str]:
        return list(self._patterns.keys())

    def pattern(self, vulnerability: str) -> Pattern:
        return self._patterns[vulnerability]

    def vulns_with_source(self, name: str) -> List[str]:
        return [v for v, p in self._patterns.items() if p.is_source(name)]

    def vulns_with_sanitizer(self, name: str) -> List[str]:
        return [v for v, p in self._patterns.items() if p.is_sanitizer(name)]

    def vulns_with_sink(self, name: str) -> List[str]:
        return [v for v, p in self._patterns.items() if p.is_sink(name)]

    def allows_implicit(self, vulnerability: str) -> bool:
        return self._patterns[vulnerability].implicit


class Label:
    """
    A label is an ordered set of flows:
      (explicit|implicit, (source_name, source_lineno), ((san_name, san_lineno), ...))

    Order matters to match the reference outputs; we deduplicate while preserving insertion order.
    """

    def __init__(self, flows: Optional[Iterable[Flow]] = None) -> None:
        self._flows: List[Flow] = []
        self._seen: Set[Flow] = set()
        if flows:
            for f in flows:
                self._add_flow(f)

    def copy(self) -> "Label":
        return Label(self._flows)

    def flows(self) -> List[Flow]:
        return list(self._flows)

    def fingerprint(self) -> Tuple[Tuple[FlowKind, str, int, Tuple[Tuple[str, int], ...]], ...]:
        return tuple((kind, src[0], src[1], tuple(sans)) for (kind, src, sans) in self._flows)

    def is_empty(self) -> bool:
        return not self._flows

    def add_source(self, source_name: str, lineno: int, kind: FlowKind = "explicit") -> None:
        self._add_flow((kind, (source_name, lineno), ()))

    def apply_sanitizer(self, sanitizer_name: str, lineno: int) -> "Label":
        out = Label()
        for (kind, src, sans) in self._flows:
            occ = (sanitizer_name, lineno)
            # Match the reference fixtures: repeated interception by the same sanitizer
            # at the same source location does not add extra duplicates to the report.
            if occ in sans:
                out._add_flow((kind, src, sans))
            else:
                seq = list(sans) + [occ]
                # Reference outputs order sanitizers by where they appear in the code.
                # (Python's sort is stable, so equal-line sanitizers keep discovery order.)
                seq.sort(key=lambda x: x[1])
                out._add_flow((kind, src, tuple(seq)))
        return out

    def to_implicit(self) -> "Label":
        out = Label()
        for (_kind, src, sans) in self._flows:
            out._add_flow(("implicit", src, sans))
        return out

    def combine(self, other: "Label") -> "Label":
        out = Label(self._flows)
        for f in other._flows:
            out._add_flow(f)
        return out

    def _add_flow(self, f: Flow) -> None:
        if f in self._seen:
            return
        self._seen.add(f)
        self._flows.append(f)


class MultiLabel:
    """
    A "label per vulnerability": maps vulnerability_name -> Label.

    This is how we track multiple vulnerabilities simultaneously while traversing the AST.
    """
    def __init__(self, policy: Policy) -> None:
        self._policy = policy
        self._labels: Dict[str, Label] = {v: Label() for v in policy.vulnerability_names}

    def copy(self) -> "MultiLabel":
        out = MultiLabel(self._policy)
        out._labels = {v: lbl.copy() for v, lbl in self._labels.items()}
        return out

    def label_for(self, vulnerability: str) -> Label:
        return self._labels[vulnerability]

    def is_empty(self) -> bool:
        return all(self._labels[v].is_empty() for v in self._labels)

    def add_source_all(self, source_name: str, lineno: int, kind: FlowKind = "explicit") -> None:
        for v in self._labels:
            self._labels[v].add_source(source_name, lineno, kind=kind)

    def add_source_filtered(self, source_name: str, lineno: int, kind: FlowKind = "explicit") -> None:
        for v in self._policy.vulns_with_source(source_name):
            self._labels[v].add_source(source_name, lineno, kind=kind)

    def apply_sanitizer_filtered(self, sanitizer_name: str, lineno: int) -> "MultiLabel":
        out = self.copy()
        for v in self._policy.vulns_with_sanitizer(sanitizer_name):
            out._labels[v] = out._labels[v].apply_sanitizer(sanitizer_name, lineno)
        return out

    def to_implicit(self) -> "MultiLabel":
        out = self.copy()
        for v in out._labels:
            out._labels[v] = out._labels[v].to_implicit()
        return out

    def combine(self, other: "MultiLabel") -> "MultiLabel":
        out = self.copy()
        for v in out._labels:
            out._labels[v] = out._labels[v].combine(other._labels[v])
        return out

    def fingerprint(self) -> Tuple[Tuple[str, Tuple[Tuple[FlowKind, str, int, Tuple[Tuple[str, int], ...]], ...]], ...]:
        # Preserve policy order for determinism
        return tuple((v, self._labels[v].fingerprint()) for v in self._policy.vulnerability_names)


class MultiLabelling:
    """
    Variable store for the analysis.

    Maps a (string) name to a MultiLabel. Names include:
      - variables: "x"
      - attributes (flattened): "obj.field"

    It also tracks whether a name may be uninitialized on some path (used to model the
    project spec rule: "non-instantiated variables/fields are sources by default").
    """
    def __init__(self, policy: Policy) -> None:
        self._policy = policy
        # name -> (multilabel, may_be_uninitialized)
        self._map: Dict[str, Tuple[MultiLabel, bool]] = {}

    def has(self, name: str) -> bool:
        return name in self._map

    def may_be_uninitialized(self, name: str) -> bool:
        entry = self._map.get(name)
        return bool(entry[1]) if entry is not None else True

    def get(self, name: str) -> MultiLabel:
        entry = self._map.get(name)
        return entry[0] if entry is not None else MultiLabel(self._policy)

    def set(self, name: str, multilabel: MultiLabel) -> None:
        # Along this path, an assignment initializes the name.
        self._map[name] = (multilabel, False)

    def copy(self) -> "MultiLabelling":
        out = MultiLabelling(self._policy)
        out._map = {k: (v.copy(), uninit) for k, (v, uninit) in self._map.items()}
        return out

    def combine(self, other: "MultiLabelling") -> "MultiLabelling":
        out = MultiLabelling(self._policy)
        keys = set(self._map.keys()) | set(other._map.keys())
        for k in keys:
            ml = self.get(k).combine(other.get(k))
            uninit = (
                (k not in self._map)
                or (k not in other._map)
                or (self._map.get(k, (MultiLabel(self._policy), True))[1])
                or (other._map.get(k, (MultiLabel(self._policy), True))[1])
            )
            out._map[k] = (ml, uninit)
        return out

    def fingerprint(self) -> Tuple[Tuple[str, bool, Tuple], ...]:
        items = []
        for name in sorted(self._map.keys()):
            ml, uninit = self._map[name]
            items.append((name, bool(uninit), ml.fingerprint()))
        return tuple(items)


class Vulnerabilities:
    """
    Accumulates all detected illegal flows to sinks, and formats them for final output.

    Output records are grouped by vulnerability base name (e.g., "XSS") and numbered
    incrementally to match fixture expectations ("XSS_1", "XSS_2", ...).
    """
    def __init__(self) -> None:
        self._counters: Dict[str, int] = {}
        # Output ordering in the provided fixtures is grouped by vulnerability base name,
        # in the order in which each base is first encountered during analysis.
        self._base_order: List[str] = []
        self._records_by_base: Dict[str, List[dict]] = {}
        self._by_key: Dict[Tuple[str, SourceOcc, SinkOcc], dict] = {}

    def records(self) -> List[dict]:
        out: List[dict] = []
        for base in self._base_order:
            out.extend(self._records_by_base.get(base, []))
        return out

    def add_illegal_flows(
        self,
        vulnerability_base: str,
        sink: SinkOcc,
        flows: Sequence[Flow],
    ) -> None:
        if _DEBUG and _DEBUG_LEVEL > 0:
            _dbg(f"VULN add_illegal_flows base={vulnerability_base} sink={sink}")
            if _DEBUG_LEVEL >= 2:
                _dbg(f"  flows={[(k, s, list(sa)) for (k, s, sa) in flows]}")
        # Group by source occurrence, preserving first-seen order.
        grouped: Dict[SourceOcc, List[Tuple[FlowKind, SanitizerSeq]]] = {}
        source_order: List[SourceOcc] = []
        for (kind, src, sans) in flows:
            if src not in grouped:
                grouped[src] = []
                source_order.append(src)
            entry = (kind, sans)
            if entry not in grouped[src]:
                grouped[src].append(entry)

        for src in source_order:
            key = (vulnerability_base, src, sink)
            rec = self._by_key.get(key)
            if rec is None:
                n = self._counters.get(vulnerability_base, 0) + 1
                self._counters[vulnerability_base] = n
                rec = {
                    "vulnerability": f"{vulnerability_base}_{n}",
                    "source": [src[0], src[1]],
                    "sink": [sink[0], sink[1]],
                    "flows": [],
                }
                self._by_key[key] = rec
                if vulnerability_base not in self._records_by_base:
                    self._records_by_base[vulnerability_base] = []
                if vulnerability_base not in self._base_order:
                    self._base_order.append(vulnerability_base)
                self._records_by_base[vulnerability_base].append(rec)

            for (kind, sans) in grouped[src]:
                flow_item = [kind, [[sname, sln] for (sname, sln) in sans]]
                if flow_item not in rec["flows"]:
                    rec["flows"].append(flow_item)


def _func_name(func: ast.expr) -> Optional[str]:
    """Return the function name for Name(...) or Attribute(...). For complex calls, return None."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _base_expr_of_call(func: ast.expr) -> Optional[ast.expr]:
    if isinstance(func, ast.Attribute):
        return func.value
    return None


def _target_names(t: ast.expr) -> Tuple[Optional[str], Optional[str]]:
    """
    For an assignment target, return (base_name, attr_name).
    - Name          -> (id, None)
    - Attribute     -> (base, attr) where base is a best-effort string if base is Name
    """
    if isinstance(t, ast.Name):
        return (t.id, None)
    if isinstance(t, ast.Attribute):
        base = t.value.id if isinstance(t.value, ast.Name) else None
        return (base, t.attr)
    return (None, None)


def eval_expr(
    node: ast.AST,
    policy: Policy,
    lab: MultiLabelling,
    vulns: Vulnerabilities,
    pc: MultiLabel,
) -> MultiLabel:
    """
    Expression semantics: returns a MultiLabel describing taint carried by the value of `node`.

    Rules of thumb used here:
      - Constants carry no taint.
      - Names read taint from the current MultiLabelling, but can also be sources according to patterns.
      - Non-instantiated names/fields are treated as sources for *all* vulnerabilities (project spec).
      - Composite expressions combine taint of their parts (e.g., BinOp combines left+right).
      - Calls:
          * combine taint from args (+ receiver for method calls)
          * apply sanitizer if function name is in pattern sanitizers
          * detect sink if function name is in pattern sinks
    """
    if _DEBUG and _DEBUG_LEVEL > 0:
        node_type = type(node).__name__
        lineno = getattr(node, "lineno", None)
        with _DbgScope(f"eval_expr {node_type} lineno={lineno} pc={_ml_summary(pc)} lab[{_lab_summary(lab)}]"):
            out = _eval_expr_impl(node, policy, lab, vulns, pc)
            _dbg(f"RETURN eval_expr -> {_ml_summary(out)}")
            if _DEBUG_LEVEL >= 2:
                _dbg(f"  RETURN full -> {_ml_dump(out)}")
            return out
    return _eval_expr_impl(node, policy, lab, vulns, pc)


def _eval_expr_impl(
    node: ast.AST,
    policy: Policy,
    lab: MultiLabelling,
    vulns: Vulnerabilities,
    pc: MultiLabel,
) -> MultiLabel:
    if isinstance(node, ast.Constant):
        return MultiLabel(policy)

    if isinstance(node, ast.Name):
        base = lab.get(node.id) if lab.has(node.id) else None

        ml = base.copy() if base is not None else MultiLabel(policy)

        # Pattern-defined sources: any occurrence of a name that is declared as a source
        # for some vulnerability patterns contributes to taint, even if the name is instantiated.
        ml = ml.combine(_source_from_callname(policy, node.id, node.lineno))

        # Default source: any uninstantiated variable is a source for all vulnerabilities.
        if base is None or lab.may_be_uninitialized(node.id):
            ml.add_source_all(node.id, node.lineno)

        return ml

    if isinstance(node, ast.Attribute):
        base_ml = eval_expr(node.value, policy, lab, vulns, pc)
        # Attribute-specific label if we ever assigned to "<base>.<attr>"
        if isinstance(node.value, ast.Name):
            key = f"{node.value.id}.{node.attr}"
            if lab.has(key):
                base_ml = base_ml.combine(lab.get(key))
        return base_ml

    if isinstance(node, ast.Subscript):
        base = eval_expr(node.value, policy, lab, vulns, pc)
        # In subscripts, both the container and the index can carry information.
        # (See provided fixture 3d-expr-subscript.)
        slc = node.slice
        if isinstance(slc, ast.AST):
            idx = eval_expr(slc, policy, lab, vulns, pc)
            return base.combine(idx)
        return base

    if isinstance(node, ast.UnaryOp):
        return eval_expr(node.operand, policy, lab, vulns, pc)

    if isinstance(node, ast.BinOp):
        left = eval_expr(node.left, policy, lab, vulns, pc)
        right = eval_expr(node.right, policy, lab, vulns, pc)
        return left.combine(right)

    if isinstance(node, ast.BoolOp):
        acc = MultiLabel(policy)
        for v in node.values:
            acc = acc.combine(eval_expr(v, policy, lab, vulns, pc))
        return acc

    if isinstance(node, ast.IfExp):
        # Expression-level branching can encode implicit flows from the condition.
        cond_ml = eval_expr(node.test, policy, lab, vulns, pc)
        pc2 = cond_ml.to_implicit().combine(pc)
        # The result is control-dependent on the condition, even if both branches are constants.
        # So the resulting value must inherit the (implicit) pc-level taint.
        branches = eval_expr(node.body, policy, lab, vulns, pc2).combine(
            eval_expr(node.orelse, policy, lab, vulns, pc2)
        )
        return branches.combine(pc2)

    if isinstance(node, ast.Compare):
        acc = eval_expr(node.left, policy, lab, vulns, pc)
        for c in node.comparators:
            acc = acc.combine(eval_expr(c, policy, lab, vulns, pc))
        return acc

    if isinstance(node, ast.Call):
        fn = _func_name(node.func)
        if fn is None:
            return MultiLabel(policy)
        _dbg(f"Call fn={fn} lineno={getattr(node, 'lineno', None)}")

        # 1) combine argument labels in order
        args_ml = MultiLabel(policy)
        for a in node.args:
            args_ml = args_ml.combine(eval_expr(a, policy, lab, vulns, pc))
        for kw in node.keywords:
            if kw.value is not None:
                args_ml = args_ml.combine(eval_expr(kw.value, policy, lab, vulns, pc))
        _dbg(f"  args_ml(after args)={_ml_summary(args_ml)}")
        if _DEBUG_LEVEL >= 2:
            _dbg(f"  args_ml(after args) full={_ml_dump(args_ml)}")

        # Calls are executed under the current program counter; the returned value (and the
        # information reaching a sink through arguments) may be implicitly influenced by it.
        # This is important for the "regions/guards" fixture where sanitizers in guards
        # can intercept implicit flows.
        args_ml = args_ml.combine(pc.to_implicit())
        _dbg(f"  args_ml(after pc)={_ml_summary(args_ml)}")

        # 2) add function-name-as-source (filtered by patterns)
        # (This ordering matches the provided fixtures: args sources first, then call-name sources)
        args_ml = args_ml.combine(_source_from_callname(policy, fn, node.lineno))
        _dbg(f"  args_ml(after callname-as-source)={_ml_summary(args_ml)}")

        # 3) include receiver/base object label (e.g., `b` in `b.m()`)
        base_expr = _base_expr_of_call(node.func)
        if base_expr is not None:
            args_ml = args_ml.combine(eval_expr(base_expr, policy, lab, vulns, pc))
            _dbg(f"  args_ml(after receiver)={_ml_summary(args_ml)}")

        # 4) sanitizer application (filtered)
        out_ml = args_ml
        if policy.vulns_with_sanitizer(fn):
            _dbg(f"  apply_sanitizer_filtered sanitizer={fn} lineno={node.lineno} to vulns={policy.vulns_with_sanitizer(fn)}")
            out_ml = out_ml.apply_sanitizer_filtered(fn, node.lineno)
            _dbg(f"  out_ml(after sanitizer)={_ml_summary(out_ml)}")
            if _DEBUG_LEVEL >= 2:
                _dbg(f"  out_ml(after sanitizer) full={_ml_dump(out_ml)}")

        # 5) sink detection: implicit flows are already included in out_ml (via pc above)
        if policy.vulns_with_sink(fn):
            _dbg(f"  detect sink={fn} lineno={node.lineno} for vulns={policy.vulns_with_sink(fn)}")
        _detect_sink_call(policy, vulns, fn, node.lineno, out_ml)

        return out_ml

    if isinstance(node, ast.List):
        acc = MultiLabel(policy)
        for elt in node.elts:
            acc = acc.combine(eval_expr(elt, policy, lab, vulns, pc))
        return acc

    if isinstance(node, ast.Tuple):
        acc = MultiLabel(policy)
        for elt in node.elts:
            acc = acc.combine(eval_expr(elt, policy, lab, vulns, pc))
        return acc

    if isinstance(node, ast.Set):
        acc = MultiLabel(policy)
        for elt in node.elts:
            acc = acc.combine(eval_expr(elt, policy, lab, vulns, pc))
        return acc

    if isinstance(node, ast.Dict):
        acc = MultiLabel(policy)
        for k in node.keys:
            if k is not None:
                acc = acc.combine(eval_expr(k, policy, lab, vulns, pc))
        for v in node.values:
            if v is not None:
                acc = acc.combine(eval_expr(v, policy, lab, vulns, pc))
        return acc

    # Fallback: unknown expression node types are treated as producing no taint.
    return MultiLabel(policy)


def _source_from_callname(policy: Policy, fn: str, lineno: int) -> MultiLabel:
    ml = MultiLabel(policy)
    ml.add_source_filtered(fn, lineno)
    return ml


def _detect_sink_call(
    policy: Policy,
    vulns: Vulnerabilities,
    sink_name: str,
    sink_lineno: int,
    ml: MultiLabel,
) -> None:
    """If `sink_name` is a sink for some patterns, record flows that reached it."""
    sink: SinkOcc = (sink_name, sink_lineno)
    for v in policy.vulns_with_sink(sink_name):
        flows = ml.label_for(v).flows()
        if not policy.allows_implicit(v):
            flows = [f for f in flows if f[0] == "explicit"]

        if flows:
            _dbg(f"  SINK-HIT vuln={v} sink={sink} flows={[(k, s, list(sa)) for (k, s, sa) in flows]}")
            vulns.add_illegal_flows(v, sink, flows)


def exec_stmt_list(
    stmts: Sequence[ast.stmt],
    policy: Policy,
    lab: MultiLabelling,
    vulns: Vulnerabilities,
    pc: MultiLabel,
    *,
    while_unroll: int = 3,
) -> MultiLabelling:
    """Execute a list of statements in order, threading the MultiLabelling through."""
    cur = lab
    for s in stmts:
        cur = exec_stmt(s, policy, cur, vulns, pc, while_unroll=while_unroll)
    return cur


def exec_stmt(
    node: ast.stmt,
    policy: Policy,
    lab: MultiLabelling,
    vulns: Vulnerabilities,
    pc: MultiLabel,
    *,
    while_unroll: int = 3,
) -> MultiLabelling:
    if _DEBUG and _DEBUG_LEVEL > 0:
        node_type = type(node).__name__
        lineno = getattr(node, "lineno", None)
        with _DbgScope(f"exec_stmt {node_type} lineno={lineno} pc={_ml_summary(pc)} lab[{_lab_summary(lab)}]"):
            out = _exec_stmt_impl(node, policy, lab, vulns, pc, while_unroll=while_unroll)
            _dbg(f"RETURN exec_stmt -> lab[{_lab_summary(out)}]")
            if _DEBUG_LEVEL >= 2:
                _dbg("  lab dump:")
                for line in _lab_dump(out).splitlines():
                    _dbg("  " + line)
            return out
    return _exec_stmt_impl(node, policy, lab, vulns, pc, while_unroll=while_unroll)


def _exec_stmt_impl(
    node: ast.stmt,
    policy: Policy,
    lab: MultiLabelling,
    vulns: Vulnerabilities,
    pc: MultiLabel,
    *,
    while_unroll: int = 3,
) -> MultiLabelling:
    """
    Statement semantics: updates and returns the MultiLabelling after executing `node`.

    Most important cases:
      - Assign / AugAssign: update the target's label from RHS label + pc implicit label.
      - If: fork the labelling, analyze both branches under pc updated with condition taint, then join.
      - While / For: bounded fixpoint iteration (join-back) to approximate unbounded repetition.
      - Expr: evaluate for sink detection side effects (e.g., a call used as a statement).
    """
    if isinstance(node, ast.Expr):
        _ = eval_expr(node.value, policy, lab, vulns, pc)
        return lab

    if isinstance(node, ast.Assign):
        value_ml = eval_expr(node.value, policy, lab, vulns, pc)
        # Any assignment under a tainted guard should be implicitly tainted by that guard (pc).
        incoming = value_ml.combine(pc.to_implicit())
        _dbg(f"Assign incoming={_ml_summary(incoming)}")

        # support multiple targets; slices mostly use 1
        for tgt in node.targets:
            base, attr = _target_names(tgt)

            # Update labelling map for assignments
            if isinstance(tgt, ast.Name):
                lab.set(tgt.id, incoming)
                _dbg(f"  set {tgt.id} = { _ml_summary(incoming) }")
            elif isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name):
                # attribute key
                lab.set(f"{tgt.value.id}.{tgt.attr}", incoming)
                _dbg(f"  set {tgt.value.id}.{tgt.attr} = { _ml_summary(incoming) }")
                # do not auto-instantiate the base object label (per fixtures)
            elif isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
                # Writing to a subscript updates the container, and information can flow
                # from the index into the container.
                container = tgt.value.id
                idx_ml = eval_expr(tgt.slice, policy, lab, vulns, pc) if isinstance(tgt.slice, ast.AST) else MultiLabel(policy)
                prev_container = lab.get(container) if lab.has(container) else MultiLabel(policy)
                new_container = prev_container.combine(idx_ml).combine(incoming)
                lab.set(container, new_container)
                _dbg(f"  set {container} (subscript write) = { _ml_summary(new_container) }")
                _detect_sink_assignment(policy, vulns, container, getattr(tgt, "lineno", node.lineno), new_container, pc)
                continue

            # Sink detection on assignment targets:
            # - If assigning to attribute, check attr name first (field sink), then base name (object sink)
            if attr is not None:
                _detect_sink_assignment(policy, vulns, attr, getattr(tgt, "lineno", node.lineno), incoming, pc)
            if base is not None:
                _detect_sink_assignment(policy, vulns, base, getattr(tgt, "lineno", node.lineno), incoming, pc)

        return lab

    if isinstance(node, ast.AugAssign):
        # Treat like: target = target <op> value
        target_ml = eval_expr(node.target, policy, lab, vulns, pc)
        value_ml = eval_expr(node.value, policy, lab, vulns, pc)
        incoming = target_ml.combine(value_ml).combine(pc.to_implicit())

        tgt = node.target
        base, attr = _target_names(tgt)
        if isinstance(tgt, ast.Name):
            lab.set(tgt.id, incoming)
        elif isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name):
            lab.set(f"{tgt.value.id}.{tgt.attr}", incoming)
        elif isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
            container = tgt.value.id
            idx_ml = eval_expr(tgt.slice, policy, lab, vulns, pc) if isinstance(tgt.slice, ast.AST) else MultiLabel(policy)
            prev_container = lab.get(container) if lab.has(container) else MultiLabel(policy)
            new_container = prev_container.combine(idx_ml).combine(incoming)
            lab.set(container, new_container)
            _detect_sink_assignment(policy, vulns, container, getattr(tgt, "lineno", node.lineno), new_container, pc)
            return lab

        if attr is not None:
            _detect_sink_assignment(policy, vulns, attr, getattr(tgt, "lineno", node.lineno), incoming, pc)
        if base is not None:
            _detect_sink_assignment(policy, vulns, base, getattr(tgt, "lineno", node.lineno), incoming, pc)
        return lab

    if isinstance(node, ast.If):
        cond_ml = eval_expr(node.test, policy, lab, vulns, pc)
        # New guards (conditions) dominate the region they enclose; to match the reference
        # outputs, prioritize the newly-added implicit flows ahead of outer pc flows.
        pc2 = cond_ml.to_implicit().combine(pc)
        _dbg(f"If pc2={_ml_summary(pc2)}")

        then_lab = exec_stmt_list(node.body, policy, lab.copy(), vulns, pc2, while_unroll=while_unroll)
        else_lab = exec_stmt_list(node.orelse, policy, lab.copy(), vulns, pc2, while_unroll=while_unroll) if node.orelse else lab.copy()
        return then_lab.combine(else_lab)

    if isinstance(node, ast.While):
        # Bounded fixpoint:
        # - out_lab: states that may be observed after 0 or more iterations (exit points)
        # - cur: over-approx state at loop head for "some number of iterations"
        out_lab = lab.copy()  # 0-iteration path
        cur = lab.copy()

        for _ in range(max(0, while_unroll)):
            before = cur.fingerprint()
            _dbg(f"While iter: cur={_lab_summary(cur)}")

            cond_ml = eval_expr(node.test, policy, cur, vulns, pc)
            pc2 = cond_ml.to_implicit().combine(pc)
            _dbg(f"  while pc2={_ml_summary(pc2)}")
            body_lab = exec_stmt_list(node.body, policy, cur.copy(), vulns, pc2, while_unroll=while_unroll)

            out_lab = out_lab.combine(body_lab)  # may exit after this iteration
            cur = cur.combine(body_lab)  # may continue; join back to head

            if cur.fingerprint() == before:
                _dbg("  while fixpoint reached; break")
                break

        return out_lab

    if isinstance(node, ast.For):
        # Bounded fixpoint for for-loops.
        out_lab = lab.copy()  # 0-iteration path
        cur = lab.copy()

        for _ in range(max(0, while_unroll)):
            before = cur.fingerprint()

            iter_ml = eval_expr(node.iter, policy, cur, vulns, pc)
            pc2 = iter_ml.to_implicit().combine(pc)

            # each iteration assigns the loop target from the iterable's information
            if isinstance(node.target, ast.Name):
                cur.set(node.target.id, iter_ml.combine(pc2))
            elif isinstance(node.target, ast.Tuple):
                # basic destructuring: assign same label to all names in the tuple
                for elt in node.target.elts:
                    if isinstance(elt, ast.Name):
                        cur.set(elt.id, iter_ml.combine(pc2))

            body_lab = exec_stmt_list(node.body, policy, cur.copy(), vulns, pc2, while_unroll=while_unroll)
            out_lab = out_lab.combine(body_lab)
            cur = cur.combine(body_lab)

            if cur.fingerprint() == before:
                break

        if node.orelse:
            else_lab = exec_stmt_list(node.orelse, policy, cur.copy(), vulns, pc, while_unroll=while_unroll)
            out_lab = out_lab.combine(else_lab)

        return out_lab

    # Unhandled statement types: return lab unchanged.
    return lab


def _detect_sink_assignment(
    policy: Policy,
    vulns: Vulnerabilities,
    sink_name: str,
    sink_lineno: int,
    incoming: MultiLabel,
    pc: MultiLabel,
) -> None:
    """Sink detection for assignment targets (variable names or attribute names)."""
    sink: SinkOcc = (sink_name, sink_lineno)
    for v in policy.vulns_with_sink(sink_name):
        flows = incoming.label_for(v).flows()
        if not policy.allows_implicit(v):
            flows = [f for f in flows if f[0] == "explicit"]
        if flows:
            vulns.add_illegal_flows(v, sink, flows)


def _load_patterns(path: str) -> List[Pattern]:
    """Load patterns from JSON file -> list[Pattern]. Assumes input file is well-formed."""
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    patterns: List[Pattern] = []
    for obj in raw:
        patterns.append(
            Pattern(
                vulnerability=str(obj["vulnerability"]),
                sources=tuple(obj.get("sources", [])),
                sanitizers=tuple(obj.get("sanitizers", [])),
                sinks=tuple(obj.get("sinks", [])),
                implicit=str(obj.get("implicit", "no")).lower() == "yes",
            )
        )
    return patterns


def main(argv: List[str]) -> int:
    """
    CLI entry point.

    Usage:
      python ./py_analyser.py <slice.py> <patterns.json>

    Writes:
      ./output/<slice>.output.json
    """
    if len(argv) != 3:
        print("Usage: python ./py_analyser.py <path_to_slice.py> <path_to_patterns.json>", file=sys.stderr)
        return 2

    slice_path = argv[1]
    patterns_path = argv[2]

    _dbg_init()
    _dbg(f"MAIN slice={slice_path} patterns={patterns_path}")
    with open(slice_path, "r", encoding="utf-8") as f:
        code = f.read()

    patterns = _load_patterns(patterns_path)
    policy = Policy(patterns)
    _dbg(f"Loaded patterns: {[p.vulnerability for p in patterns]}")
    if _DEBUG_LEVEL >= 2:
        for p in patterns:
            _dbg(f"  Pattern {p.vulnerability} sources={list(p.sources)} sanitizers={list(p.sanitizers)} sinks={list(p.sinks)} implicit={p.implicit}")

    tree = ast.parse(code)
    vulns = Vulnerabilities()
    lab = MultiLabelling(policy)
    pc = MultiLabel(policy)
    if _DEBUG_LEVEL >= 2:
        _dbg(f"Initial pc={_ml_dump(pc)}")
        _dbg(f"Initial lab={_lab_dump(lab)}")

    if isinstance(tree, ast.Module):
        _ = exec_stmt_list(tree.body, policy, lab, vulns, pc)

    out_dir = os.path.join(".", "output")
    os.makedirs(out_dir, exist_ok=True)

    base = os.path.basename(slice_path)
    if base.endswith(".py"):
        base = base[:-3]
    out_path = os.path.join(out_dir, f"{base}.output.json")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(vulns.records(), f, indent=4)
        f.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))


