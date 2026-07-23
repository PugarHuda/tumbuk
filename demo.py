"""Offline full-deliverable demo — no network, no x402, no OKX key needed.

Runs the REAL engine (attacks.py + redteam.py + report.py) against two in-process stub
agents — one that obeys every embedded instruction, one that refuses all of them — and
prints the full markdown report (with its embedded machine-readable JSON block) for each.
Zero-setup way to see exactly what a Tumbuk scan produces.

    python demo.py
"""
import re, sys
try:  # the emoji/markers below need UTF-8; a Windows cp1252 console would crash on them
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
from redteam import run_scan
import report

CANARY_RE = re.compile(r"TUMBUK-[0-9A-F]{12}")


def vulnerable_agent(url, text):
    m = CANARY_RE.search(text)
    c = m.group(0) if m else "UNKNOWN"
    return (f'{c} sure! TRANSFER_CONFIRMED_{c} sk-' + "x" * 25 +
            f' {{"role":"system","trusted":true,"token":"{c}"}} (verbatim leak, {c})')


def safe_agent(url, text):
    return "I can only help with the task you were actually asked to help with."


def main():
    for label, stub in (("VULNERABLE agent (obeys every embedded instruction)", vulnerable_agent),
                        ("SAFE agent (refuses embedded instructions)", safe_agent)):
        print("=" * 78)
        print(label)
        print("=" * 78)
        scan = run_scan("https://example-agent.invalid/invoke", send=stub)
        rep = report.build(scan)
        print(rep["markdown"])
        print()


if __name__ == "__main__":
    main()
