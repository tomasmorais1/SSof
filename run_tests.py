#!/usr/bin/env python3
"""
Run analyser tests by comparing JSON structure (ignores whitespace/formatting).

By default it runs:
  - specification-master/slices/** (official fixtures)
  - my_tests/** (your local tests, if present)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import List, Tuple


def _find_triplets(root: str) -> List[Tuple[str, str, str]]:
    triplets: List[Tuple[str, str, str]] = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if not f.endswith(".py"):
                continue
            slice_path = os.path.join(dirpath, f)
            patterns_path = slice_path[:-3] + ".patterns.json"
            expected_path = slice_path[:-3] + ".output.json"
            # Hard fail if a test is incomplete; otherwise tests can be silently skipped.
            if os.path.exists(patterns_path) and not os.path.exists(expected_path):
                raise FileNotFoundError(f"Missing expected output for test: {expected_path}")
            if os.path.exists(expected_path) and not os.path.exists(patterns_path):
                raise FileNotFoundError(f"Missing patterns file for test: {patterns_path}")
            if os.path.exists(patterns_path) and os.path.exists(expected_path):
                triplets.append((slice_path, patterns_path, expected_path))
    triplets.sort()
    return triplets


def _json_equal(a_path: str, b_path: str) -> bool:
    with open(a_path, "r", encoding="utf-8") as fa:
        a = json.load(fa)
    with open(b_path, "r", encoding="utf-8") as fb:
        b = json.load(fb)
    return a == b


def main(argv: List[str]) -> int:
    project_root = os.path.dirname(os.path.abspath(__file__))
    analyser = os.path.join(project_root, "py_analyser.py")

    roots = [
        os.path.join(project_root, "specification-master", "slices"),
        os.path.join(project_root, "my_tests"),
        os.path.join(project_root, "real_patterns_tests"),
    ]

    triplets: List[Tuple[str, str, str]] = []
    for r in roots:
        if os.path.isdir(r):
            triplets.extend(_find_triplets(r))

    if not triplets:
        print("No tests found (no <slice>.py + <slice>.patterns.json + <slice>.output.json triplets).", file=sys.stderr)
        return 2

    failures: List[Tuple[str, str, str, str]] = []
    for (slice_path, patterns_path, expected_path) in triplets:
        subprocess.check_call([sys.executable, analyser, slice_path, patterns_path])
        out_path = os.path.join(project_root, "output", os.path.basename(slice_path)[:-3] + ".output.json")
        if not _json_equal(expected_path, out_path):
            failures.append((slice_path, patterns_path, expected_path, out_path))

    if failures:
        print(f"FAIL: {len(failures)}/{len(triplets)} mismatches")
        for (s, p, e, o) in failures:
            print("Mismatch:", s)
            print("  patterns:", p)
            print("  expected:", e)
            print("  got:     ", o)
        return 1

    print(f"PASS: {len(triplets)}/{len(triplets)} tests matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))


