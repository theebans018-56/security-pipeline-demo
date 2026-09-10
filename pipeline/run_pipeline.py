#!/usr/bin/env python3
"""
Security compliance pipeline — DEMO with SYNTHETIC DATA ONLY.
Demonstrates: scan -> ledger -> triage/score -> generate register -> verify.
Generic sample application. No real product, no real findings.
"""
import json, os, argparse, datetime, re
HERE = os.path.dirname(os.path.abspath(__file__))
SEV = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Very Low": 1}


def load_findings(path):
    """Synthetic scanner output (dependency + code findings)."""
    return json.load(open(path, encoding="utf-8"))


def load_host_results(path):
    """Results from the SSH compliance test step (PASS/FAIL + observed value)."""
    if path and os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    return []


def build_ledger(findings, host_results):
    rows = []
    for i, f in enumerate(findings, start=1):
        rows.append({
            "id": f"FND-{i:04d}", "category": f.get("type", "SCA"),
            "scanner": {"cwe": f.get("cwe", ""), "cve": f.get("cve", ""), "severity": f.get("severity", "Medium"),
                        "location": f.get("location", ""), "observed": f.get("summary", ""), "verdict": "OPEN"},
            "human": {}, "evidence": {"tool": f.get("tool", "scanner"), "ts": now()}}
        )
    for j, h in enumerate(host_results, start=1):
        rows.append({
            "id": f"CTRL-{j:04d}", "category": "COMPLIANCE",
            "scanner": {"cwe": h.get("cwe", ""), "cve": "", "severity": h.get("severity", "Medium"),
                        "location": h.get("command", ""), "observed": h.get("observed", ""), "verdict": h.get("verdict", "PASS")},
            "human": {}, "evidence": {"test_id": h.get("test_id", ""), "host": h.get("host", ""), "ts": now()}}
        )
    return rows


def triage(rows):
    for r in rows:
        s = r["scanner"]; sev = SEV.get(s["severity"], 3)
        lik = 3 if s["verdict"] in ("OPEN", "FAIL") else 2
        score = sev * lik
        band = "Low" if score <= 6 else "Moderate" if score <= 12 else "High"
        r["human"] = {"likelihood": {4: "High", 3: "Medium", 2: "Low"}[lik], "score": score,
                      "band": band, "bra": "Applicable" if 7 <= score <= 12 else "N/A",
                      "disposition": "Acceptable (BRA)" if 7 <= score <= 12 else "Acceptable",
                      "note": "SYNTHETIC demo finding"}
    return rows


def write_register(rows, out):
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = "Risk Register (DEMO)"
    ws["A1"] = "DEMONSTRATION - SAMPLE-APP SECURITY SCAN - NOT A REGULATORY DOCUMENT"
    ws["A1"].font = Font(bold=True, color="B23B33", size=12); ws.merge_cells("A1:H1")
    ws.append([]); hdr = ["Risk ID", "Category", "CWE / CVE", "Severity", "Observed value", "Likelihood", "Score", "Band / BRA"]
    ws.append(hdr)
    for c in ws[ws.max_row]:
        c.font = Font(bold=True, color="FFFFFF"); c.fill = PatternFill("solid", fgColor="0C8F9B"); c.alignment = Alignment(wrap_text=True)
    for r in rows:
        s, h = r["scanner"], r["human"]
        band = f"{h['band']} ({h['score']})" + (f" - {h['bra']}" if h["bra"] != "N/A" else "")
        ws.append([r["id"], r["category"], s["cve"] or s["cwe"], s["severity"], str(s["observed"])[:60], h["likelihood"], h["score"], band])
        if h["band"] == "Moderate":
            ws.cell(ws.max_row, 8).fill = PatternFill("solid", fgColor="F6EBD6")
    for col, w in zip("ABCDEFGH", (14, 12, 16, 10, 42, 12, 8, 22)): ws.column_dimensions[col].width = w
    wb.save(out)


def verify(rows):
    problems = []
    ids = [r["id"] for r in rows]
    if len(ids) != len(set(ids)): problems.append("duplicate IDs")
    for r in rows:
        h = r["human"]
        if h["band"] == "Moderate" and h["bra"] != "Applicable": problems.append(f"{r['id']}: Moderate without BRA")
        if h["band"] == "Low" and h["bra"] == "Applicable": problems.append(f"{r['id']}: Low marked BRA")
    return problems


def now(): return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%MZ")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", default=os.path.join(HERE, "sample_findings.json"))
    ap.add_argument("--host-results", default=os.path.join(HERE, "..", "host_results.json"))
    ap.add_argument("--out-dir", default=HERE)
    a = ap.parse_args()
    print("=== SECURITY COMPLIANCE PIPELINE (demo, synthetic data) ===\n")
    rows = triage(build_ledger(load_findings(a.findings), load_host_results(a.host_results)))
    led = os.path.join(a.out_dir, "ledger.jsonl")
    with open(led, "w", encoding="utf-8") as f:
        for r in rows: f.write(json.dumps(r) + "\n")
    print(f"[1-2] scan + ledger  -> {len(rows)} findings -> ledger.jsonl")
    for r in rows:
        s, h = r["scanner"], r["human"]
        print(f"      {r['id']:<10} {r['category']:<11} {s['verdict']:<5} sev={s['severity']:<8} score={h['score']:<3} {h['band']:<9} BRA={h['bra']}")
    reg = os.path.join(a.out_dir, "register.xlsx"); write_register(rows, reg)
    print(f"\n[3-4] triage + document -> register.xlsx")
    problems = verify(rows)
    print("[5]   verify -> " + ("PASS" if not problems else "ISSUES: " + "; ".join(problems)))
    if problems: raise SystemExit(1)
    bra = [r["id"] for r in rows if r["human"]["bra"] == "Applicable"]
    print(f"\nRESULT: {len(rows)} findings, {len(bra)} to BRA ({', '.join(bra) or 'none'}). Synthetic only.")
