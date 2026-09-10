#!/usr/bin/env python3
"""
DOCUMENTS stage — build the FULL document set from one ledger, in dependency order:
  STEP 1  individual reports  : SCA, SAST, DAST, FUZZ, ASA, SRT results, TMT results
  STEP 2  aggregate           : Risk Register
  STEP 3  join (LAST)         : Traceability Matrix
Each document is its own generator + sheet; all read the same ledger, so they agree.
Generic/synthetic demo — not a regulatory document.
"""
import json, os, datetime
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

HERE = os.path.dirname(os.path.abspath(__file__))
ACCENT = "0C8F9B"; WARN = "F6EBD6"; CRIT = "F5E0DD"; VERIFIED = "DDEEE3"
thin = Side(style="thin", color="B9C5D2"); BORDER = Border(left=thin, right=thin, top=thin, bottom=thin)

# category -> (document code, human title)
REPORTS = [
    ("SCA",  "DOC_071", "SCA Security Testing Report"),
    ("SAST", "DOC_068", "SAST Security Testing Report"),
    ("DAST", "DOC_069", "DAST Security Testing Report"),
    ("FUZZ", "DOC_066", "Fuzz Testing Report"),
    ("ASA",  "DOC_067", "Attack Surface Analysis Report"),
    ("SRT",  "DOC_036", "Security Requirement Testing Results"),
    ("TMT",  "DOC_035", "Threat Mitigation Testing Results"),
]
# synthetic per-category prefix for the risk id in the register/traceability
PREFIX = {"SCA": "SRSK-VT", "SAST": "SRSK-SAST", "DAST": "SRSK-DAST", "FUZZ": "SRSK-FUZZ",
          "ASA": "SRSK-ASA", "SRT": "SRSK-CT", "TMT": "SRSK-CT"}


def load_ledger(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def _hdr(ws, cols, title, subtitle):
    ws["A1"] = title; ws["A1"].font = Font(bold=True, size=13, color="16202B")
    ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=len(cols))
    ws["A2"] = subtitle; ws["A2"].font = Font(italic=True, size=10, color="B23B33")
    ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=len(cols))
    for c, (name, w) in enumerate(cols, start=1):
        cell = ws.cell(4, c, name); cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=ACCENT); cell.alignment = Alignment(wrap_text=True, vertical="center")
        cell.border = BORDER; ws.column_dimensions[openpyxl.utils.get_column_letter(c)].width = w
    ws.freeze_panes = "A5"


def _row(ws, r, vals, fill=None):
    for c, v in enumerate(vals, start=1):
        cell = ws.cell(r, c, v); cell.alignment = Alignment(wrap_text=True, vertical="top"); cell.border = BORDER
        if fill: cell.fill = PatternFill("solid", fgColor=fill)


def srsk_id(cat, n):
    return f"{PREFIX[cat]}-{n:04d}"


def build_report(rows, cat, code, title, outdir):
    items = [r for r in rows if r["category"] == cat]
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = cat
    if cat in ("SRT", "TMT"):
        cols = [("Verification ID", 16), ("Title", 40), ("Command", 34), ("Observed value", 40),
                ("Result", 10), ("Unresolved Anomaly", 18)]
        _hdr(ws, cols, f"{code} {title} (DEMO)", "Synthetic sample - not a regulatory document")
        r = 5
        for it in items:
            s = it["scanner"]; verdict = s["verdict"]
            anom = f"USA-{it['id']}" if verdict == "FAIL" else "N/A"
            fill = VERIFIED if verdict == "PASS" else CRIT
            _row(ws, r, [it["id"], it["evidence"].get("title", ""), s["location"], s["observed"], verdict, anom], fill); r += 1
        npass = sum(1 for it in items if it["scanner"]["verdict"] == "PASS")
        ws.cell(r + 1, 1, f"Summary: {npass} PASS / {len(items)-npass} FAIL").font = Font(bold=True)
    else:
        cols = [("Finding ID", 14), ("CWE / CVE", 16), ("Severity", 10), ("Location", 30),
                ("Description", 46), ("Status", 10), ("Recommendation", 34)]
        _hdr(ws, cols, f"{code} {title} (DEMO)", "Synthetic sample - not a regulatory document")
        r = 5
        for it in items:
            s = it["scanner"]
            fill = CRIT if s["severity"] in ("Critical", "High") else WARN if s["severity"] == "Medium" else None
            _row(ws, r, [it["id"], s["cve"] or s["cwe"], s["severity"], s["location"], s["observed"],
                         "Open", "Remediate / upgrade; verified on retest."], fill); r += 1
        ws.cell(r + 1, 1, f"Total findings: {len(items)}").font = Font(bold=True)
    out = os.path.join(outdir, f"{code}_{cat}_report.xlsx"); wb.save(out)
    return out, len(items)


def build_register(rows, outdir):
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = "Risk Register"
    cols = [("Risk ID", 16), ("Category", 10), ("Source Report", 12), ("Finding", 40), ("CWE/CVE", 14),
            ("Severity", 9), ("Likelihood", 11), ("Score", 7), ("Residual Level", 13),
            ("Acceptability", 16), ("BRA", 10)]
    _hdr(ws, cols, "DOC_032 Cybersecurity Risk Assessment - Register (DEMO)", "Aggregated from all reports - synthetic")
    code_of = {c: code for c, code, _ in REPORTS}
    r = 5; counters = {}; idmap = {}
    for it in rows:
        if it["human"]["band"] == "Verified":
            continue  # passed controls are verification evidence, not register risks
        cat = it["category"]; counters[cat] = counters.get(cat, 0) + 1
        rid = srsk_id(cat, counters[cat]); idmap[it["id"]] = rid
        s, h = it["scanner"], it["human"]
        fill = CRIT if h["band"] == "High" else WARN if h["band"] == "Moderate" else None
        _row(ws, r, [rid, cat, code_of.get(cat, ""), s["observed"], s["cve"] or s["cwe"], s["severity"],
                     h["likelihood"], h["score"], h["band"], h["disposition"], h["bra"]], fill); r += 1
    out = os.path.join(outdir, "DOC_032_register.xlsx"); wb.save(out)
    return out, r - 5, idmap


def build_traceability(rows, idmap, outdir):
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = "Traceability"
    cols = [("Finding / Test ID", 16), ("Category", 10), ("Source Report", 12), ("CWE/CVE", 14),
            ("Risk Control ID", 16), ("Verification ID", 16), ("Result", 9),
            ("Register Risk ID", 16), ("Residual", 12), ("BRA", 9)]
    _hdr(ws, cols, "DOC_040 Traceability Matrix (Security) - DEMO", "Built LAST - joins IDs across all documents")
    code_of = {c: code for c, code, _ in REPORTS}
    r = 5
    for i, it in enumerate(rows, start=1):
        s, h = it["scanner"], it["human"]
        verdict = s["verdict"]
        rcm = f"RCM-{it['id']}"
        vid = it["id"] if it["category"] in ("SRT", "TMT") else f"TST-{it['id']}"
        result = "PASS" if verdict == "PASS" else "FAIL/OPEN"
        rrid = idmap.get(it["id"], "N/A (verified)")
        fill = VERIFIED if verdict == "PASS" else CRIT if h["band"] in ("High",) else WARN if h["band"] == "Moderate" else None
        _row(ws, r, [it["id"], it["category"], code_of.get(it["category"], ""), s["cve"] or s["cwe"],
                     rcm, vid, result, rrid, h["band"], h["bra"]], fill); r += 1
    out = os.path.join(outdir, "DOC_040_traceability.xlsx"); wb.save(out)
    return out, r - 5


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", default=os.path.join(HERE, "..", "output", "ledger.jsonl"))
    ap.add_argument("--out-dir", default=os.path.join(HERE, "..", "output", "docs"))
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)
    rows = load_ledger(a.ledger)
    print("=== DOCUMENTS STAGE — build in dependency order ===")
    print("\nSTEP 1 — individual reports:")
    for cat, code, title in REPORTS:
        out, n = build_report(rows, cat, code, title, a.out_dir)
        print(f"  {code} {title:<38} <- {n:>2} {cat} results  -> {os.path.basename(out)}")
    print("\nSTEP 2 — aggregate register:")
    reg, nrisk, idmap = build_register(rows, a.out_dir)
    print(f"  DOC_032 Cybersecurity Risk Assessment      <- {nrisk} risks       -> {os.path.basename(reg)}")
    print("\nSTEP 3 — traceability (LAST, joins all IDs):")
    tr, ntr = build_traceability(rows, idmap, a.out_dir)
    print(f"  DOC_040 Traceability Matrix                <- {ntr} rows joined  -> {os.path.basename(tr)}")
    print(f"\nDocument set built in {a.out_dir} ({len(REPORTS)} reports + register + traceability).")


if __name__ == "__main__":
    main()
