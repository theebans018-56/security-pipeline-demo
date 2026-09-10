#!/usr/bin/env python3
"""ASA — attack-surface checks against the running app (mirrors v2.1.0: enumerate the exposed
surface and inspect responses). Checks the reachable port and the security headers the server
returns; a missing control is a finding."""
import json, urllib.request, argparse

REQUIRED_HEADERS = {
    "Content-Security-Policy": ("CWE-693", "Medium", "missing Content-Security-Policy header"),
    "Strict-Transport-Security": ("CWE-319", "Low", "missing HSTS header"),
    "X-Content-Type-Options": ("CWE-693", "Low", "missing X-Content-Type-Options header"),
}

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--url", default="http://127.0.0.1:8099")
    ap.add_argument("--out", default="asa_findings.json"); a = ap.parse_args()
    base = a.url.rstrip("/"); findings = []
    try:
        r = urllib.request.urlopen(base + "/health", timeout=8); hdrs = {k.lower(): v for k, v in r.headers.items()}
        print(f"  service reachable at {base} (HTTP {r.status})")
    except Exception as e:
        print("  service not reachable:", e); hdrs = {}
    for h, (cwe, sev, desc) in REQUIRED_HEADERS.items():
        present = h.lower() in hdrs
        print(f"  [{'PASS' if present else 'FAIL'}] header {h}")
        if not present:
            findings.append({"type": "ASA", "tool": "surface-scan", "cve": "", "cwe": cwe, "severity": sev,
                             "location": f"{base} response headers", "summary": desc})
    json.dump(findings, open(a.out, "w"), indent=2)
    print(f"--- ASA: {len(findings)} findings -> {a.out}")

if __name__ == "__main__":
    main()
