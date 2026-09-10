#!/usr/bin/env python3
"""Convert a real Bandit SAST report (JSON) into the pipeline's findings format.
Usage: python normalize_bandit.py bandit.json > scan_findings.json"""
import sys, json

SEV = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}


def convert(bandit_json):
    data = json.load(open(bandit_json, encoding="utf-8"))
    out = []
    for r in data.get("results", []):
        cwe = ""
        c = r.get("issue_cwe")
        if isinstance(c, dict) and c.get("id"):
            cwe = f"CWE-{c['id']}"
        out.append({
            "type": "SAST",
            "tool": "bandit",
            "cve": "",
            "cwe": cwe,
            "severity": SEV.get(str(r.get("issue_severity", "LOW")).upper(), "Low"),
            "location": f"{r.get('filename','')}:{r.get('line_number','')}",
            "summary": f"{r.get('test_id','')} {r.get('test_name','')}: {r.get('issue_text','')}"[:110],
        })
    return out


if __name__ == "__main__":
    print(json.dumps(convert(sys.argv[1]), indent=2))
