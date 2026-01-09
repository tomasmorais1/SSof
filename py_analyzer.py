#!/usr/bin/env python3
from __future__ import annotations

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


@dataclass(frozen=True)
class Pattern:
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

        # 1) combine argument labels in order
        args_ml = MultiLabel(policy)
        for a in node.args:
            args_ml = args_ml.combine(eval_expr(a, policy, lab, vulns, pc))
        for kw in node.keywords:
            if kw.value is not None:
                args_ml = args_ml.combine(eval_expr(kw.value, policy, lab, vulns, pc))

        # Calls are executed under the current program counter; the returned value (and the
        # information reaching a sink through arguments) may be implicitly influenced by it.
        # This is important for the "regions/guards" fixture where sanitizers in guards
        # can intercept implicit flows.
        args_ml = args_ml.combine(pc.to_implicit())

        # 2) add function-name-as-source (filtered by patterns)
        # (This ordering matches the provided fixtures: args sources first, then call-name sources)
        args_ml = args_ml.combine(_source_from_callname(policy, fn, node.lineno))

        # 3) include receiver/base object label (e.g., `b` in `b.m()`)
        base_expr = _base_expr_of_call(node.func)
        if base_expr is not None:
            args_ml = args_ml.combine(eval_expr(base_expr, policy, lab, vulns, pc))

        # 4) sanitizer application (filtered)
        out_ml = args_ml
        if policy.vulns_with_sanitizer(fn):
            out_ml = out_ml.apply_sanitizer_filtered(fn, node.lineno)

        # 5) sink detection: implicit flows are already included in out_ml (via pc above)
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
    sink: SinkOcc = (sink_name, sink_lineno)
    for v in policy.vulns_with_sink(sink_name):
        flows = ml.label_for(v).flows()
        if not policy.allows_implicit(v):
            flows = [f for f in flows if f[0] == "explicit"]

        if flows:
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
    if isinstance(node, ast.Expr):
        _ = eval_expr(node.value, policy, lab, vulns, pc)
        return lab

    if isinstance(node, ast.Assign):
        value_ml = eval_expr(node.value, policy, lab, vulns, pc)
        incoming = value_ml.combine(pc.to_implicit())

        # support multiple targets; slices mostly use 1
        for tgt in node.targets:
            base, attr = _target_names(tgt)

            # Update labelling map for assignments
            if isinstance(tgt, ast.Name):
                lab.set(tgt.id, incoming)
            elif isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name):
                # attribute key
                lab.set(f"{tgt.value.id}.{tgt.attr}", incoming)
                # do not auto-instantiate the base object label (per fixtures)
            elif isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
                # Writing to a subscript updates the container, and information can flow
                # from the index into the container.
                container = tgt.value.id
                idx_ml = eval_expr(tgt.slice, policy, lab, vulns, pc) if isinstance(tgt.slice, ast.AST) else MultiLabel(policy)
                prev_container = lab.get(container) if lab.has(container) else MultiLabel(policy)
                new_container = prev_container.combine(idx_ml).combine(incoming)
                lab.set(container, new_container)
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

            cond_ml = eval_expr(node.test, policy, cur, vulns, pc)
            pc2 = cond_ml.to_implicit().combine(pc)
            body_lab = exec_stmt_list(node.body, policy, cur.copy(), vulns, pc2, while_unroll=while_unroll)

            out_lab = out_lab.combine(body_lab)  # may exit after this iteration
            cur = cur.combine(body_lab)  # may continue; join back to head

            if cur.fingerprint() == before:
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
    sink: SinkOcc = (sink_name, sink_lineno)
    for v in policy.vulns_with_sink(sink_name):
        flows = incoming.label_for(v).flows()
        if not policy.allows_implicit(v):
            flows = [f for f in flows if f[0] == "explicit"]
        if flows:
            vulns.add_illegal_flows(v, sink, flows)


def _load_patterns(path: str) -> List[Pattern]:
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
    if len(argv) != 3:
        print("Usage: python ./py_analyser.py <path_to_slice.py> <path_to_patterns.json>", file=sys.stderr)
        return 2

    slice_path = argv[1]
    patterns_path = argv[2]

    with open(slice_path, "r", encoding="utf-8") as f:
        code = f.read()

    patterns = _load_patterns(patterns_path)
    policy = Policy(patterns)

    tree = ast.parse(code)
    vulns = Vulnerabilities()
    lab = MultiLabelling(policy)
    pc = MultiLabel(policy)

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
