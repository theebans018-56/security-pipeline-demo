#!/usr/bin/env python3
"""
SAMPLE vulnerable web app (stdlib only) — the running target for DAST / FUZZ / ASA.
Deliberately insecure so the dynamic tests have something to find. Not a real product.
Run: python sample_app/webapp.py [port]   (default 8099)
"""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# exam id -> {owner, patient}
EXAMS = {
    "1001": {"owner": "sonoA", "patient": {"firstName": "Ann", "lastName": "Lee", "patientId": "P1"}},
    "1002": {"owner": "sonoB", "patient": {"firstName": "Ben", "lastName": "Ray", "patientId": "P2"}},
}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body, ctype="application/json"):
        data = json.dumps(body).encode() if ctype == "application/json" else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # VULN (ASA): no security headers (no CSP / HSTS / X-Content-Type-Options)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try: return json.loads(self.rfile.read(n) or b"{}")
        except Exception: return {}

    def do_POST(self):
        p = self.path.split("?")[0]
        if p == "/login":
            b = self._body()
            # accepts any credentials, returns a token naming the user
            return self._send(200, {"token": "tok-" + str(b.get("user", "anon"))})
        if p == "/api/patient":
            b = self._body()
            fn, ln = str(b.get("firstName", "")), str(b.get("lastName", ""))
            # VULN (DAST): empty identity accepted; duplicate patientId silently overwritten
            return self._send(200, {"saved": True, "firstName": fn, "lastName": ln, "patientId": b.get("patientId")})
        self._send(404, {"error": "not found"})

    def do_GET(self):
        p = self.path.split("?")[0]
        auth = self.headers.get("Authorization", "")
        if p.startswith("/api/exams/"):
            eid = p.rsplit("/", 1)[1]
            if not auth.startswith("Bearer "):
                return self._send(401, {"error": "auth required"})
            ex = EXAMS.get(eid)
            if not ex:
                return self._send(404, {"error": "no exam"})
            # VULN (DAST IDOR): role/token checked but NOT ownership -> any user reads any exam
            return self._send(200, {"exam": eid, "owner": ex["owner"], "patient": ex["patient"]})
        if p.startswith("/api/frame/"):
            eid = p.rsplit("/", 1)[1]
            # VULN (DAST): frame data served with NO authentication at all
            return self._send(200, {"frame": eid, "data": "PHI-like-frame-bytes"})
        if p.startswith("/api/qty/"):
            v = p.rsplit("/", 1)[1]
            # VULN (FUZZ): unbounded int -> unhandled error (500) on out-of-range / wrong type
            n = int(v)                      # raises on non-int -> 500
            if n > 2_147_483_647:
                raise ValueError("int overflow")   # unhandled -> 500
            return self._send(200, {"qty": n})
        if p == "/" or p == "/health":
            return self._send(200, {"status": "ok"})
        self._send(404, {"error": "not found"})

    def do_500(self): pass


def run(port):
    print(f"sample vulnerable app on :{port}")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


if __name__ == "__main__":
    run(int(sys.argv[1]) if len(sys.argv) > 1 else 8099)
