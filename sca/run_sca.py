#!/usr/bin/env python3
"""SCA — real dependency CVE scan with pip-audit (mirrors v2.1.0 method) on a sample manifest.
Normalizes pip-audit JSON into the pipeline's findings format."""
import json, subprocess, sys, os, argparse

def sev_from_id(vid):
    return "High"  # demo: pip-audit doesn't always give CVSS; label High for visibility

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--req", default=os.path.join(os.path.dirname(__file__), "requirements-sample.txt"))
    ap.add_argument("--out", default="sca_findings.json"); a = ap.parse_args()
    # run pip-audit against the requirements file (no install, JSON output)
    try:
        p = subprocess.run([sys.executable, "-m", "pip_audit", "-r", a.req, "-f", "json", "--progress-spinner", "off"],
                           capture_output=True, text=True, timeout=180)
        data = json.loads(p.stdout or "{}")
    except Exception as e:
        print("pip-audit error:", e); data = {}
    findings = []
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    for d in deps:
        name = d.get("name", "?"); ver = d.get("version", "")
        for v in d.get("vulns", []):
            vid = v.get("id", ""); cve = vid if vid.startswith("CVE") else ""
            findings.append({"type": "SCA", "tool": "pip-audit", "cve": cve, "cwe": "",
                             "severity": sev_from_id(vid), "location": f"{name}=={ver}",
                             "summary": f"{name} {ver}: {vid} ({','.join(v.get('fix_versions', []) or ['no fix'])})"[:110]})
    json.dump(findings, open(a.out, "w"), indent=2)
    print(f"--- SCA: {len(findings)} dependency-CVE findings -> {a.out}")

if __name__ == "__main__":
    main()
