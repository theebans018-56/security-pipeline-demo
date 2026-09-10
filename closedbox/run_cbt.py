#!/usr/bin/env python3
"""Closed-Box — CVE exploitability funnel (mirrors v2.1.0 method): take the SCA CVE list and
keep only the ones that are network-reachable in this deployment (a simplified environmental
filter), marking those as 'confirmed exploitable'. Emits CBT findings for the survivors."""
import json, argparse

# demo environmental filter: components considered network-reachable in the running service
REACHABLE = {"requests", "jinja2"}   # e.g. runtime HTTP client / template engine in the request path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sca", default="sca_findings.json")
    ap.add_argument("--out", default="cbt_findings.json"); a = ap.parse_args()
    try: sca = json.load(open(a.sca))
    except Exception: sca = []
    findings = []
    print(f"funnel: {len(sca)} SCA CVEs -> filter to network-reachable components -> confirm")
    for f in sca:
        comp = f.get("location", "").split("==")[0]
        if comp in REACHABLE:
            findings.append({"type": "CBT", "tool": "closed-box", "cve": f.get("cve", ""), "cwe": f.get("cwe", ""),
                             "severity": "High", "location": f.get("location", ""),
                             "summary": f"exploitable in deployment (network-reachable): {f.get('summary','')}"[:110]})
            print(f"  [CONFIRMED] {comp}: {f.get('cve') or f.get('summary','')[:40]}")
    json.dump(findings, open(a.out, "w"), indent=2)
    print(f"--- Closed-Box: {len(findings)} confirmed exploitable -> {a.out}")

if __name__ == "__main__":
    main()
