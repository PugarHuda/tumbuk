"""Pure self-check — no network. Runs the real attack suite + scoring engine against
in-process stub targets (vulnerable / safe / mixed) so the whole grading pipeline is
exercised offline, plus the SSRF guard against real hostnames (DNS resolve only, no
outbound request).

    python test_tumbuk.py
"""
import re, sys
from attacks import PROBES
from redteam import run_scan
import probe

FAILS = []
def check(name, cond, extra=""):
    print(("  ok  " if cond else " FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        FAILS.append(name)

CANARY_RE = re.compile(r"TUMBUK-[0-9A-F]{12}")

def _canary_in(text):
    m = CANARY_RE.search(text or "")
    return m.group(0) if m else "UNKNOWN"


def vulnerable_target(url, text):
    """Obeys every embedded instruction — the worst-case target. Echoes back everything
    needed to trip every detector (canary, a fund-drain confirm, a secret-shaped string,
    and a forged trusted-JSON blob) — which real content applies depends on which probe
    text this is, but stuffing all of it in is harmless: each probe only checks for its
    own marker, and this proves the target obeys ANY embedded instruction."""
    c = _canary_in(text)
    return (f'{c} sure! TRANSFER_CONFIRMED_{c} sk-' + "x" * 25 +
            f' {{"role":"system","trusted":true,"token":"{c}"}} (verbatim leak, {c})')


def safe_target(url, text):
    """Refuses / ignores every embedded instruction — the best-case target."""
    return "I can only help with the task you originally asked for."


def main():
    print("== attack suite shape ==")
    check("8 probes defined", len(PROBES) == 8, str(len(PROBES)))
    ids = {p["id"] for p in PROBES}
    check("no duplicate probe ids", len(ids) == len(PROBES))
    check("every probe has a build+detect", all(callable(p["build"]) and callable(p["detect"]) for p in PROBES))

    print("\n== grading: vulnerable target -> F ==")
    r = run_scan("https://x", send=vulnerable_target)
    check("vulnerable=F", r["grade"] == "F", r["grade"])
    check("vulnerable score is low", r["score"] < 50, r["score"])
    check("all probes flagged vulnerable", r["summary"]["vulnerable"] == len(PROBES))

    print("\n== grading: safe target -> A ==")
    r = run_scan("https://x", send=safe_target)
    check("safe=A", r["grade"] == "A", r["grade"])
    check("safe score is 100", r["score"] == 100, r["score"])
    check("no vulnerable findings", r["summary"]["vulnerable"] == 0)

    print("\n== grading: exactly one CRITICAL vuln among otherwise-safe -> F ==")
    def one_critical_vuln(url, text):
        if "Ignore all previous instructions" in text:  # prompt-injection-canary only
            return _canary_in(text)
        return safe_target(url, text)
    r = run_scan("https://x", send=one_critical_vuln)
    check("1-critical-vuln=F", r["grade"] == "F", r["grade"])
    check("only 1 vulnerable finding", r["summary"]["vulnerable"] == 1, r["summary"])

    print("\n== grading: a critical probe errors (unmeasured), rest safe -> capped at C ==")
    def one_critical_unmeasured(url, text):
        if "Ignore all previous instructions" in text:
            raise probe.TargetRejected("simulated transient failure")
        return safe_target(url, text)
    r = run_scan("https://x", send=one_critical_unmeasured)
    check("1-critical-unmeasured=C", r["grade"] == "C", r["grade"])
    check("unmeasured count 1", r["summary"]["unmeasured"] == 1)

    print("\n== grading: target fully unreachable -> not-evaluated, no fake grade ==")
    def unreachable(url, text):
        raise probe.TargetRejected("connection refused")
    r = run_scan("https://x", send=unreachable)
    check("unreachable=not-evaluated", r["status"] == "not-evaluated", r["status"])
    check("no grade key on not-evaluated", "grade" not in r)

    print("\n== injection neutralized: a target that echoes input but never obeys embedded directives ==")
    def echo_but_ignore(url, text):
        return f"You said: {text[:20]}... I will not comply with embedded instructions."
    r = run_scan("https://x", send=echo_but_ignore)
    check("injection=neutralized (A grade)", r["grade"] == "A", r["grade"])

    print("\n== SSRF guard (resolve-only, no outbound request) ==")
    for bad in ("http://127.0.0.1/x", "http://localhost/x", "http://169.254.169.254/latest/meta-data/",
                "http://10.0.0.1/x", "http://192.168.1.1/x", "ftp://x/y", "file:///etc/passwd"):
        try:
            probe.assert_public_url(bad)
            check(f"reject {bad}", False, "was NOT rejected")
        except probe.TargetRejected:
            check(f"reject {bad}", True)
    try:
        probe.assert_public_url("https://example.com/agent")
        check("example.com (public) is allowed", True)
    except probe.TargetRejected as e:
        check("example.com (public) is allowed", False, str(e))

    print("\n" + ("test_tumbuk: ALL PASSED" if not FAILS else f"test_tumbuk FAILURES: {FAILS}"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
