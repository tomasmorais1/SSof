#!/usr/bin/env python3
"""
Generate expected outputs for tests under ./my_tests by running py_analyser.py
and copying ./output/<slice>.output.json -> ./my_tests/<slice>.output.json
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys


def main() -> int:
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    my_tests = os.path.join(project_root, "my_tests")
    analyser = os.path.join(project_root, "py_analyser.py")
    out_dir = os.path.join(project_root, "output")
    os.makedirs(out_dir, exist_ok=True)

    slices = []
    for f in os.listdir(my_tests):
        if f.endswith(".py") and not f.startswith("_") and f != "gen_expected.py":
            base = f[:-3]
            slices.append(base)
    slices.sort()

    if not slices:
        print("No my_tests/*.py slices found.", file=sys.stderr)
        return 2

    for base in slices:
        slice_path = os.path.join(my_tests, base + ".py")
        patterns_path = os.path.join(my_tests, base + ".patterns.json")
        if not os.path.exists(patterns_path):
            print(f"Missing patterns for {base}: {patterns_path}", file=sys.stderr)
            return 2

        subprocess.check_call([sys.executable, analyser, slice_path, patterns_path])
        produced = os.path.join(out_dir, base + ".output.json")
        expected = os.path.join(my_tests, base + ".output.json")
        shutil.copyfile(produced, expected)
        print("Wrote", expected)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


