#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_all.py — run every WeEngine check against one target and print a matrix.

Each check lives in its own script and can be run standalone; this runner only
shells out to them so the output can be compared side by side.

Usage:
    python3 run_all.py -u http://127.0.0.1:8084
    python3 run_all.py -u https://target -m some_module
    python3 run_all.py -u https://target -m m1 -m m2 --json
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

CHECKS = [
    ("WE7-1", "we7_1_cloud_dock_rce.py", "CWE-306 -> 434/94  unauth file write -> RCE", "1.7.2-1.7.7"),
    ("WE7-2", "we7_2_wxcode_ssrf.py", "CWE-918  SSRF with response echo", "1.7.2-1.7.7"),
    ("WE7-3", "we7_3_file_upload.py", "CWE-434  unauth upload endpoint", "1.7.2-1.7.7"),
    ("WE7-4", "we7_4_module_enum.py", "CWE-200  module enumeration", "1.7.2-2.9.13"),
    ("WE7-6", "we7_6_verifycode_trigger.py", "CWE-799  unauth code trigger", "1.7.2-2.9.13"),
]


def run_one(script, base, module_args, extra):
    cmd = [sys.executable, os.path.join(HERE, script), "-u", base, "--json"] + extra
    if script.startswith("we7_5"):
        for m in module_args:
            cmd += ["-m", m]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return json.loads(out.stdout or "{}"), out.returncode
    except Exception as e:
        return {"error": str(e)}, 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-m", "--module", action="append", default=[])
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    base = a.url if "://" in a.url else "http://" + a.url

    results = []
    for vid, script, kind, affected in CHECKS:
        r, rc = run_one(script, base, a.module, [])
        results.append({"id": vid, "kind": kind, "affected": affected,
                        "script": script, "verdict": r.get("verdict", r.get("error", "n/a")),
                        "rc": rc, "detail": r})
    if a.module:
        r, rc = run_one("we7_5_module_entry_bypass.py", base, a.module, [])
        results.append({"id": "WE7-5", "kind": "CWE-862  missing authorization (module entry)",
                        "affected": "1.7.2-2.9.13", "script": "we7_5_module_entry_bypass.py",
                        "verdict": r.get("verdict", r.get("error", "n/a")), "rc": rc, "detail": r})

    if a.json:
        print(json.dumps({"target": base, "results": results}, ensure_ascii=False, indent=2))
        return 0

    print(f"target: {base}\n")
    print(f"{'id':<7}{'type':<44}{'affected':<14}{'verdict'}")
    print("-" * 110)
    for r in results:
        print(f"{r['id']:<7}{r['kind']:<44}{r['affected']:<14}{r['verdict'][:48]}")
    hit = [r["id"] for r in results if r["rc"] == 1]
    print()
    print("vulnerable: " + (", ".join(hit) if hit else "none"))
    if "WE7-5" not in [r["id"] for r in results]:
        print("note: WE7-5 needs a module name -> -m <module>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
