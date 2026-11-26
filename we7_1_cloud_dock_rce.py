#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WE7-1 — Unauthenticated settings overwrite in the cloud dock controller
========================================================================
Type      : CWE-306 Missing Authentication for Critical Function
            (leads to CWE-434 unrestricted file write / CWE-94 code injection)
Component : web/source/cloud/dock.ctrl.php  (actions: callback + download)
Affected  : 1.7.2 – 1.7.7   (fixed in 2.9.13)
Severity  : Critical — a complete chain gives remote code execution

Why it works
------------
1) `do=callback` is handled *before* the cloud-availability guard and exits
   immediately, so it is never authenticated:
       $site = json_decode(base64_decode($_GPC['token']), true);
       setting_save($site, 'site');          // writes site.key / site.token
2) `do=download` authenticates its payload with
       md5(md5($file) . $ret['path'] . $_W['setting']['site']['token'])
   i.e. with the key that step 1 just overwrote -> the attacker signs his own
   payload and the check passes.
3) The destination is `IA_ROOT . $ret['path']` with no path/extension
   restriction, and `@mkdirs()` creates missing directories.

What this detector does (NON-DESTRUCTIVE)
-----------------------------------------
It only asks the legacy `download` handler to process an EMPTY payload. The
vulnerable branch then replies `failed <site-token>`; the hardened 2.9.13
branch replies `cloud service is unavailable.` or plain `failed`. Nothing is
written, nothing is overwritten, no settings are changed — the `callback`
action (which would modify site settings) is deliberately never touched.

Caveat: the legacy reply echoes the site token. This script masks it (shows
only its length and first 4 characters) so it cannot be used as a token
harvester.

Exit codes: 0 = not vulnerable · 1 = vulnerable · 2 = inconclusive

Usage:
    python3 we7_1_cloud_dock_rce.py -u http://127.0.0.1:8080
    python3 we7_1_cloud_dock_rce.py -u https://target --json
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
    url = f"{base.rstrip('/')}/web/index.php?c=cloud&a=dock&do=download"
    status, body = http_get(url, timeout)
    text = body.decode("utf-8", "replace").strip()
    out = {"target": base, "check": "WE7-1 cloud dock unauthenticated download handler",
           "url": url, "status": status, "bytes": len(body), "sample": text[:80]}

    # 1.7.x: exit("failed$post " . site_token)
    legacy = text.startswith("failed") and len(text) > len("failed")
    if legacy:
        leaked = text[len("failed"):].strip()
        out["verdict"] = "VULNERABLE (legacy handler answers unauthenticated and echoes the site token)"
        out["site_token"] = {"length": len(leaked), "masked": (leaked[:4] + "*" * max(0, len(leaked) - 4)) if leaked else ""}
        out["note"] = ("Full chain: do=callback (base64 JSON) overwrites site.key/site.token, then "
                       "do=download signs its own payload and writes any file under the web root. "
                       "That step is NOT performed by this detector.")
    elif status == 200 and "cloud service is unavailable" in text:
        out["verdict"] = "not vulnerable (hardened build: cloud guard reached before the download branch)"
    elif status == 200 and text == "failed":
        out["verdict"] = "not vulnerable (hardened build: 'failed' without the token echo)"
    else:
        out["verdict"] = "inconclusive"
    return out


def main():
    ap = argparse.ArgumentParser(description="WE7-1 detector (non-destructive)")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    base = a.url if "://" in a.url else "http://" + a.url
    r = check(base, a.timeout)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"[WE7-1] {r['target']}")
        print(f"  type    : CWE-306 -> CWE-434 / CWE-94 (unauthenticated file write -> RCE)")
        print(f"  affected: 1.7.2 - 1.7.7   (fixed in 2.9.13)")
        print(f"  request : GET {r['url']}  (empty payload)")
        print(f"  response: HTTP {r['status']} / {r['bytes']} bytes: {r['sample'][:60]}")
        print(f"  verdict : {r['verdict']}")
        if "site_token" in r:
            print(f"  token   : length={r['site_token']['length']} masked={r['site_token']['masked']}")
        if "note" in r:
            print(f"  note    : {r['note']}")
    return 1 if r["verdict"].startswith("VULNERABLE") else (0 if "not vulnerable" in r["verdict"] else 2)


if __name__ == "__main__":
    sys.exit(main())
