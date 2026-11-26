#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fp_target.py — an adversarial target for FALSE-POSITIVE testing.

It is NOT WeEngine. It answers the exact URLs the detectors probe, with
responses that look superficially similar to vulnerable WeEngine replies
(HTML pages that contain the words "failed", "message", "items", a 302, big
HTML bodies ...). A detector that reports VULNERABLE against this server has a
false positive.

Run:  python3 fp_target.py 8099
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

BIG_HTML = "<!DOCTYPE html><html><head><title>Service status</title></head><body>" + \
           ("<p>status ok</p>" * 60) + "</body></html>"

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path
        # WE7-1 worst case: a body that literally starts with "failed"
        if "a=dock" in p and "do=download" in p:
            return self._send(200, "failed to fetch package from cloud mirror", "text/plain")
        # WE7-2 worst case: a large HTML page (looks like an echoed fetch)
        if "a=wxcode" in p:
            return self._send(200, BIG_HTML)
        # WE7-3 worst case: 200 + JSON-ish error containing "message"
        if "a=file" in p:
            return self._send(200, '{"status":500,"message":"upload service temporarily busy"}',
                              "application/json")
        # WE7-4 worst case: HTML that contains the word "items"
        if "a=modules" in p:
            return self._send(200, "<html><body><h1>Inventory</h1><ul><li>items: 42</li></ul></body></html>")
        # WE7-5 worst case: direct=0 redirects somewhere, direct=1 returns a big page
        if "a=entry" in p:
            if "direct=0" in p:
                self.send_response(302)
                self.send_header("Location", "/news/index.html")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self._send(200, BIG_HTML)
        # WE7-6 worst case: 200 with a long HTML page
        if "a=verifycode" in p:
            return self._send(200, BIG_HTML)
        return self._send(404, "<html><body>not found</body></html>")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    print(f"adversarial FP target on http://127.0.0.1:{port}")
    HTTPServer(("0.0.0.0", port), H).serve_forever()
