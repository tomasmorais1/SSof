#!/usr/bin/env python3
"""
Run tests under ./chatgpt_tests.

Note: These files were pasted from ChatGPT and their expected *.output.json may not match
this project's exact analyser semantics/output format. This runner can:
  - run the analyser for each test
  - optionally compare produced output to the provided expected output
  - write a *.produced.json next to each test for inspection

Usage:
  python3 ./run_chatgpt_tests.py              # run + compare + write *.produced.json
  python3 ./run_chatgpt_tests.py --no-compare # run + write *.produced.json only
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import List, Tuple


def _find_tests(folder: str) -> List[Tuple[str, str, str]]:
    tests: List[Tuple[str, str, str]] = []
    for f in os.listdir(folder):
        if not f.endswith(".py"):
            continue
        base = os.path.join(folder, f[:-3])
        py = base + ".py"
        patterns = base + ".patterns.json"
        expected = base + ".output.json"
        if not os.path.exists(patterns):
            raise FileNotFoundError(f"Missing patterns file for test: {patterns}")
        if not os.path.exists(expected):
            raise FileNotFoundError(f"Missing expected output for test: {expected}")
        tests.append((py, patterns, expected))
    tests.sort()
    return tests


def _json_load(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-compare", action="store_true", help="Do not compare produced vs expected JSON")
    ap.add_argument("--no-write-produced", action="store_true", help="Do not write *.produced.json files")
    args = ap.parse_args(argv[1:])

    project_root = os.path.dirname(os.path.abspath(__file__))
    folder = os.path.join(project_root, "chatgpt_tests")
    analyser = os.path.join(project_root, "py_analyser.py")
    out_dir = os.path.join(project_root, "output")
    os.makedirs(out_dir, exist_ok=True)

    tests = _find_tests(folder)
    if not tests:
        print("No tests found in ./chatgpt_tests", file=sys.stderr)
        return 2

    mismatches = 0
    for (py, patterns, expected) in tests:
        base = os.path.splitext(os.path.basename(py))[0]
        subprocess.check_call([sys.executable, analyser, py, patterns])

        produced_global = os.path.join(out_dir, base + ".output.json")
        produced_local = os.path.join(folder, base + ".produced.json")

        if not args.no_write_produced:
            shutil.copyfile(produced_global, produced_local)

        if not args.no_compare:
            exp = _json_load(expected)
            got = _json_load(produced_global)
            if exp != got:
                mismatches += 1
                print(f"FAIL {base}")
            else:
                print(f"PASS {base}")
        else:
            print(f"RAN  {base}")

    total = len(tests)
    if args.no_compare:
        print(f"Done: ran {total}/{total} tests")
        return 0

    if mismatches:
        print(f"Done: {total - mismatches}/{total} matched, {mismatches} mismatched")
        return 1

    print(f"Done: {total}/{total} matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))


