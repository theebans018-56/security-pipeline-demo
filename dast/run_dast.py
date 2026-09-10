#!/usr/bin/env python3
"""DAST — authenticated dynamic checks against the running app (mirrors the v2.1.0 method:
log in per role, then business-logic / privilege-escalation checks). Each recipe = a request
+ an expected safe response; a deviation is a finding. Credentials come from env/Secrets.
Writes findings in the pipeline's format."""
import json, os, sys, urllib.request, argparse

def http(method, url, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, method=method, data=data,
        headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        r = urllib.request.urlopen(req, timeout=8)
        return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try: b = json.loads(e.read() or b"{}")
        except Exception: b = {}
        return e.code, b
    except Exception as e:
        return 0, {"error": str(e)}

def login(base, user):
    pw = os.environ.get("DAST_PASS", "test")   # from Secrets in CI
    _, b = http("POST", base + "/login", body={"user": user, "pass": pw})
    return b.get("token")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8099")
    ap.add_argument("--out", default="dast_findings.json")
    a = ap.parse_args()
    base = a.url.rstrip("/")
    tokA = login(base, "sonoA")   # two disposable test accounts / roles
    tokB = login(base, "sonoB")
    findings = []

    def check(cond_open, cwe, sev, loc, summary):
        # cond_open == True  => the control is broken (finding)
        print(f"  [{'FAIL' if cond_open else 'PASS'}] {summary[:60]}")
        if cond_open:
            findings.append({"type": "DAST", "tool": "dast-recipes", "cve": "", "cwe": cwe,
                             "severity": sev, "location": loc, "summary": summary})

    # 1) IDOR / BOLA — sonoA reads an exam owned by sonoB
    st, b = http("GET", base + "/api/exams/1002", token=tokA)
    check(st == 200 and b.get("owner") == "sonoB", "CWE-639", "Critical",
          "GET /api/exams/{id}", "object-level authorization not enforced (sonoA read sonoB's exam)")

    # 2) Unauthenticated data endpoint (socket.io-style)
    st, b = http("GET", base + "/api/frame/1002", token=None)
    check(st == 200 and "data" in b, "CWE-306", "Medium",
          "GET /api/frame/{id}", "frame/PHI endpoint reachable without authentication")

    # 3) Empty patient identity accepted
    st, b = http("POST", base + "/api/patient", token=tokA,
                 body={"firstName": "", "lastName": "  ", "patientId": "P9"})
    check(st == 200 and b.get("saved"), "CWE-20", "Medium",
          "POST /api/patient", "empty/whitespace patient identity accepted (unattributable record)")

    # 4) Duplicate patientId silently overwritten (data integrity)
    http("POST", base + "/api/patient", token=tokA, body={"firstName": "Ann", "lastName": "Lee", "patientId": "P1"})
    st, b = http("POST", base + "/api/patient", token=tokA, body={"firstName": "X", "lastName": "Y", "patientId": "P1"})
    check(st == 200 and b.get("saved"), "CWE-20", "High",
          "POST /api/patient", "duplicate patientId silently overwrites demographics")

    json.dump(findings, open(a.out, "w"), indent=2)
    print(f"--- DAST: {len(findings)} findings -> {a.out}")

if __name__ == "__main__":
    main()
