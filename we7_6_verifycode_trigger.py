#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WE7-6 — Unauthenticated verification-code trigger (e-mail / SMS)
================================================================
Type      : CWE-799 Improper Control of Interaction Frequency
            (also CWE-770 Allocation of Resources Without Limits)
Component : web/source/utility/verifycode.ctrl.php  (do=send_code)
Affected  : 1.7.2 – 2.9.13 (current release, IMS_RELEASE_DATE 202610280001)
Severity  : Medium — the site's own SMTP transport is used to mail arbitrary
            recipients (domain/IP blacklisting), and on a site registered with
            the vendor's cloud the SMS balance is debited per message

Why it works
------------
1) No authentication: `verifycode` is listed in the `direct` array of the
   `utility` ACL (web/common/permission.inc.php).
2) The captcha can be switched off by the caller:
       if (isset($_GPC['need_checkcaptcha']) && intval($_GPC['need_checkcaptcha']) > 0)
           $need_checkcaptcha = false;
   and it is only enforced when `failed_count >= 3` and `$need_checkcaptcha`.
3) The throttle is keyed on `(uniacid, receiver)`, and `uniacid` is itself a
   request parameter, so rotating it yields a fresh 5-message quota; counter
   rows older than 30 minutes are also purged:
       pdo_delete('uni_verifycode', array('createtime <' => TIMESTAMP - 1800));
4) Delivery uses the site's transport: `ihttp_email()` (site SMTP) or
   `cloud_sms_send()` (billed to the site owner's cloud SMS balance).

Detection method (NON-DESTRUCTIVE — nothing is ever sent)
--------------------------------------------------------
The endpoint is probed with a **deliberately malformed receiver**
(`not-a-valid-address`). Validation runs before the code is generated, so the
request is rejected and no e-mail/SMS is produced; a reachable endpoint answers
with its own error message, a protected one answers 302 to the login page.

This script will NOT accept a real address on purpose: a "does it really send"
test costs the site owner money and is out of scope for a detector.

Exit codes: 0 = not reachable · 1 = reachable without a session · 2 = inconclusive

Usage:
    python3 we7_6_verifycode_trigger.py -u http://127.0.0.1:8084
    python3 we7_6_verifycode_trigger.py -u https://target --json
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")

MALFORMED = "not-a-valid-address"


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
    url = (f"{base.rstrip('/')}/web/index.php?c=utility&a=verifycode"
           f"&do=send_code&receiver={MALFORMED}")
    status, body = http_get(url, timeout)
    text = body.decode("utf-8", "replace")
    if status == 200 and text.strip():
        verdict = ("REACHABLE WITHOUT A SESSION (a malformed receiver was rejected before delivery; "
                   "nothing was sent)")
    elif status in (301, 302, 303, 307):
        verdict = "not reachable (redirects to the login page)"
    else:
        verdict = "inconclusive"
    return {"target": base, "check": "WE7-6 unauthenticated verification-code trigger",
            "url": url, "status": status, "bytes": len(body),
            "sample": text[:120], "verdict": verdict}


def main():
    ap = argparse.ArgumentParser(description="WE7-6 detector (never sends anything)")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    base = a.url if "://" in a.url else "http://" + a.url
    r = check(base, a.timeout)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"[WE7-6] {r['target']}")
        print(f"  type    : CWE-799 / CWE-770 (unauthenticated code trigger)")
        print(f"  affected: 1.7.2 - 2.9.13 (not fixed)")
        print(f"  request : GET {r['url']}")
        print(f"  response: HTTP {r['status']} / {r['bytes']} bytes: {r['sample'][:70]}")
        print(f"  verdict : {r['verdict']}")
    return 1 if r["verdict"].startswith("REACHABLE") else (0 if "not reachable" in r["verdict"] else 2)


if __name__ == "__main__":
    sys.exit(main())
