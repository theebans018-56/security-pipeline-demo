#!/usr/bin/env python3
"""FUZZ — boundary / type fuzzing of the running API (mirrors v2.1.0: malformed input,
verdict = controlled 422 vs unhandled 500). Each case sends a crafted value and flags a finding
when the server returns an unhandled error instead of a clean validation response."""
import json, urllib.request, argparse

CASES = [
    ("/api/qty/99999999999999", "CWE-190", "Low", "integer far out of range"),
    ("/api/qty/abc", "CWE-20", "Low", "wrong type where integer expected"),
    ("/api/qty/-1", "CWE-20", "Low", "negative where positive expected"),
]

def get(url):
    try:
        r = urllib.request.urlopen(url, timeout=8); return r.status
    except urllib.error.HTTPError as e: return e.code
    except Exception: return 500   # connection reset / unhandled -> treat as server error

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--url", default="http://127.0.0.1:8099")
    ap.add_argument("--out", default="fuzz_findings.json"); a = ap.parse_args()
    base = a.url.rstrip("/"); findings = []
    for path, cwe, sev, desc in CASES:
        st = get(base + path)
        unhandled = st >= 500 or st == 0
        print(f"  [{'FAIL' if unhandled else 'PASS'}] {desc[:50]:<50} status={st}")
        if unhandled:
            findings.append({"type": "FUZZ", "tool": "fuzzer", "cve": "", "cwe": cwe, "severity": sev,
                             "location": path, "summary": f"{desc} -> unhandled server error (HTTP {st or 'reset'})"})
    json.dump(findings, open(a.out, "w"), indent=2)
    print(f"--- FUZZ: {len(findings)} findings -> {a.out}")

if __name__ == "__main__":
    main()
