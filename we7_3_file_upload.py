#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WE7-3 — Unauthenticated file-upload endpoint (content not validated)
=====================================================================
Type      : CWE-434 Unrestricted Upload of File with Dangerous Type
Component : web/source/utility/file.ctrl.php  (do=upload)
Affected  : 1.7.2 – 1.7.7   (fixed in 2.9.13: `file` removed from the direct ACL)
Severity  : Medium — extension whitelist only, PHP executables rejected, but
            arbitrary content lands under the site's attachment directory
            (stored XSS from the site's own origin, file hosting, chain material)

Why it works
------------
`utility` keeps an unauthenticated `direct` allow-list in
web/common/permission.inc.php, and in 1.7.x it contains `file`:

    'utility' => array('direct' => array('verifycode', 'code', 'file', ...))

`file_upload()` then validates only the extension, never the content
(magic bytes / image structure), and stores the result under
`attachment/images/<uniacid>/...`. In 2.9.13 `file` was moved to the
authenticated (vice-founder/owner) part of the ACL.

What this detector does (NON-DESTRUCTIVE)
-----------------------------------------
It sends a GET to the upload action with **no file attached** and only reads
the reply. A reachable handler answers with its own JSON error; a hardened
build answers 302 to the login page. **Nothing is uploaded.** The check exists
to tell you whether the endpoint is exposed; do not turn it into an upload
test on systems you do not own.

Exit codes: 0 = not exposed · 1 = exposed · 2 = inconclusive

Usage:
    python3 we7_3_file_upload.py -u http://127.0.0.1:8080
    python3 we7_3_file_upload.py -u https://target --json
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(NoRedirect)


def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(300000)
    except urllib.error.HTTPError as e:
        return e.code, (e.read(300000) if e.fp else b"")
    except Exception as e:
        return None, str(e).encode()


def check(base, timeout=15):
    url = f"{base.rstrip('/')}/web/index.php?c=utility&a=file&do=upload"
    status, body = http_get(url, timeout)
    text = body.decode("utf-8", "replace")
    exposed = status == 200 and ('"error"' in text or "上传失败" in text or '"message"' in text)
    if exposed:
        verdict = "EXPOSED (upload handler answers without a session; nothing was uploaded)"
    elif status in (301, 302, 303, 307):
        verdict = "not exposed (redirects to the login page - endpoint requires authentication)"
    else:
        verdict = "inconclusive"
    return {"target": base, "check": "WE7-3 unauthenticated upload endpoint", "url": url,
            "status": status, "bytes": len(body), "sample": text[:80], "verdict": verdict}


def main():
    ap = argparse.ArgumentParser(description="WE7-3 detector (non-destructive)")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    base = a.url if "://" in a.url else "http://" + a.url
    r = check(base, a.timeout)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"[WE7-3] {r['target']}")
        print(f"  type    : CWE-434 unrestricted upload (content not validated)")
        print(f"  affected: 1.7.2 - 1.7.7   (fixed in 2.9.13)")
        print(f"  request : GET {r['url']}  (no file attached)")
        print(f"  response: HTTP {r['status']} / {r['bytes']} bytes: {r['sample'][:60]}")
        print(f"  verdict : {r['verdict']}")
    return 1 if r["verdict"].startswith("EXPOSED") else (0 if "not exposed" in r["verdict"] else 2)


if __name__ == "__main__":
    sys.exit(main())
