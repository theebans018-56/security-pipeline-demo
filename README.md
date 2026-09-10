# Security Compliance Pipeline — Demo

A self-contained demonstration of an automated security-testing → document pipeline, using
**synthetic data only**. It is a generic sample; it does not represent any real product,
findings, or regulatory content.

## What it shows
```
SSH compliance test (throwaway container)
        │
        ▼
scan (synthetic SCA/SAST/DAST findings)  ──►  ledger.jsonl  ──►  triage/score  ──►  register.xlsx  ──►  verify
```

- **`pipeline/run_pipeline.py`** — reads synthetic findings + host results, normalises them into a
  JSONL ledger, scores each (severity × likelihood → risk band → BRA flag), generates a demo
  register spreadsheet, and runs a consistency verifier.
- **`scripts/ssh_compliance_test.sh`** — generates an ephemeral SSH key, starts a throwaway
  SSH container, runs a **read-only** compliance check over SSH, writes a PASS/FAIL result, and
  cleans up. Demonstrates the "test a host over SSH" pattern with no real device and no committed key.
- **`.github/workflows/security-pipeline.yml`** — runs the whole thing on GitHub Actions and
  uploads `ledger.jsonl` + `register.xlsx` as build artifacts.

## Run locally
```bash
pip install openpyxl
python pipeline/run_pipeline.py            # scan → ledger → register → verify
```

## Run in CI
Push to `main` (or use *Run workflow*). The Actions run performs the SSH compliance test in a
throwaway container, then builds the register and uploads the evidence artifacts.

All data here is synthetic (`CVE-2099-xxxx`, `sample-*` packages). Nothing is confidential.

## Real scan example

The repo includes `sample_app/` — a deliberately vulnerable Python file — and runs a
**real Bandit SAST scan** against it. Try it:
```bash
pip install bandit openpyxl
python -m bandit -r sample_app -f json -o bandit.json -q
python pipeline/normalize_bandit.py bandit.json > pipeline/scan_findings.json
python pipeline/run_pipeline.py --findings pipeline/scan_findings.json
```
Bandit finds real issues (command injection, SQL injection, weak MD5, hardcoded password),
which flow into `register.xlsx` with CWE + risk score + BRA flag.
