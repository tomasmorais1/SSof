#!/usr/bin/env python3
"""
Generate expected outputs for tests under ./real_patterns_tests by running py_analyser.py
and copying ./output/<slice>.output.json -> ./real_patterns_tests/<slice>.output.json
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys


def main() -> int:
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tests_dir = os.path.join(project_root, "real_patterns_tests")
    analyser = os.path.join(project_root, "py_analyser.py")
    out_dir = os.path.join(project_root, "output")
    os.makedirs(out_dir, exist_ok=True)

    # Find tests recursively, to support the community-style folder structure:
    #   real_patterns_tests/T24-01/<slice>.py
    #   real_patterns_tests/T24-01/<slice>.patterns.json
    #   real_patterns_tests/T24-01/<slice>.output.json
    slices = []
    for dirpath, _, files in os.walk(tests_dir):
        for f in files:
            if not f.endswith(".py"):
                continue
            if f == "gen_expected.py" or f.startswith("_"):
                continue
            py_path = os.path.join(dirpath, f)
            base = py_path[:-3]
            patterns_path = base + ".patterns.json"
            if os.path.exists(patterns_path):
                slices.append(base)  # store full base path without extension
    slices.sort()

    if not slices:
        print("No real_patterns_tests/*.py slices found.", file=sys.stderr)
        return 2

    for base in slices:
        slice_path = base + ".py"
        patterns_path = base + ".patterns.json"
        if not os.path.exists(patterns_path):
            print(f"Missing patterns for {base}: {patterns_path}", file=sys.stderr)
            return 2

        subprocess.check_call([sys.executable, analyser, slice_path, patterns_path])
        produced = os.path.join(out_dir, os.path.basename(base) + ".output.json")
        expected = base + ".output.json"
        shutil.copyfile(produced, expected)
        print("Wrote", expected)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


