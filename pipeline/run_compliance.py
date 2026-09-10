#!/usr/bin/env python3
"""SRT / TMT compliance runner (demo).
Each recipe = a command + an acceptance criterion. Runs the command against the target,
records the OBSERVED value, and decides PASS/FAIL against the criterion — the same pattern
as sec-req-test-agent / TMTA, just simplified.

Target:
  * default: run locally (the runner is itself a Linux host) — reliable for CI demo.
  * production: pass --ssh 'user@host' --key <keyfile> to run each command over SSH
    against a real device via a self-hosted runner. Read-only commands only.

Writes compliance_results.json (list of results) for the pipeline to ingest.
"""
import json, os, re, subprocess, argparse, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
RECIPES = os.path.join(HERE, "..", "compliance", "recipes.json")


NOISE = ("WARNING", "post-quantum", "store now", "decrypt later", "may need to be upgraded", "pq.html", "This session")


def _clean(text):
    return "\n".join(l for l in text.splitlines() if not any(n in l for n in NOISE)).strip()


def run_cmd(cmd, ssh, key, port):
    """Run a recipe command. Over SSH, feed the command to a remote bash via stdin
    (`ssh host bash -s`) so quoting never breaks and it works even when the remote
    default shell is not bash."""
    try:
        if ssh:
            full = ["ssh", "-p", str(port), "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
            if key: full += ["-i", key]
            full += [ssh, "bash -s"]
            out = subprocess.run(full, input=cmd, capture_output=True, text=True, timeout=30)
        else:
            out = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=30)
        return _clean(out.stdout + out.stderr)
    except Exception as e:
        return f"error: {e}"


def evaluate(observed, expect):
    op, val = expect.get("op"), str(expect.get("value", ""))
    o = observed.strip()
    if op == "regex":        return bool(re.search(val, o))
    if op == "equals":       return o == val
    if op == "contains":     return val in o
    if op == "not_contains": return val not in o
    if op == "le_int":
        m = re.search(r"-?\d+", o); return bool(m) and int(m.group()) <= int(val)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recipes", default=RECIPES)
    ap.add_argument("--out", default=os.path.join(HERE, "..", "compliance_results.json"))
    ap.add_argument("--ssh", default="", help="user@host to run over SSH (production)")
    ap.add_argument("--key", default="", help="SSH private key file")
    ap.add_argument("--port", default=22)
    a = ap.parse_args()
    recipes = json.load(open(a.recipes, encoding="utf-8"))
    where = f"SSH {a.ssh}" if a.ssh else "local host"
    print(f"=== SRT/TMT COMPLIANCE RUN ({len(recipes)} recipes on {where}) ===")
    results = []
    for r in recipes:
        observed = run_cmd(r["command"], a.ssh, a.key, a.port)
        verdict = "PASS" if evaluate(observed, r["expect"]) else "FAIL"
        results.append({
            "test_id": r["id"], "category": r["category"], "title": r["title"],
            "command": r["command"], "observed": observed[:120], "verdict": verdict,
            "cwe": r.get("cwe", ""), "severity": r.get("severity", "Medium"),
            "host": a.ssh or "runner(local)", "ts": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%MZ")})
        print(f"  [{verdict}] {r['id']} {r['category']:<3} {r['title'][:44]:<44} observed={observed[:40]!r}")
    json.dump(results, open(a.out, "w", encoding="utf-8"), indent=2)
    npass = sum(1 for x in results if x["verdict"] == "PASS")
    print(f"--- SRT/TMT: {npass} PASS / {len(results)-npass} FAIL -> {os.path.basename(a.out)}")


if __name__ == "__main__":
    main()
