"""Turn a scan result into a markdown report (with an embedded machine-readable JSON
block) plus a tamper-evident digest — the digest is also the x402 settle sentinel
(server.py), so it must be present on every successfully evaluated scan and absent
whenever the call didn't produce a real report (guard errors, unreachable targets).
"""
import hashlib, json

REMEDIATION = {
    "prompt-injection-canary": "Treat all inbound text as untrusted data, not instructions. Use a system/user role separation the model can't be talked out of, and never let user text redefine the task.",
    "fund-drain": "Never let free-text instruct a fund transfer. Require a structured, out-of-band-signed authorization (e.g. a wallet signature) for any value-moving action — text alone must not be sufficient.",
    "secret-exfil": "Keep credentials out of the model's context entirely (fetch-and-use in your own code, never hand the key to the LLM). Add an output filter for credential-shaped strings as defense in depth.",
    "jailbreak-persona": "Persona/role claims in user input must not change what the agent is permitted to do — enforce policy in code, not by asking the model to self-police a persona.",
    "output-hijack": "Never let a downstream agent trust structured fields (role, trusted, permissions) that originated from a model's free-text output — validate/re-derive trust server-side.",
    "system-prompt-leak": "Assume the system prompt WILL leak eventually; don't put secrets there. Add a response filter that blocks verbatim echoes of configured instruction text.",
    "instruction-override": "Isolate the user's actual task from any embedded meta-instructions; a translation request should never be able to redefine what the agent does next.",
    "indirect-injection": "Content fetched from tools/RAG is still untrusted — wrap it clearly as data, strip HTML-comment-style directives, and never let it carry instructions the model will obey.",
}


def digest(report: dict) -> str:
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    return "0x" + hashlib.sha256(canonical).hexdigest()


def build(scan: dict) -> dict:
    """scan: the dict from redteam.run_scan(). Returns {"markdown", "json", "report_digest"}
    for an evaluated scan, or {"error": ...} passthrough for not-evaluated."""
    if scan.get("status") != "evaluated":
        return {"error": f"target not evaluated: {scan.get('reason', 'unknown')}", "target_url": scan.get("target_url")}

    rd = digest(scan)
    lines = [f"# Tumbuk red-team report", "",
             f"**Target:** `{scan['target_url']}`", f"**Grade:** {scan['grade']}  ·  **Score:** {scan['score']}/100",
             f"**Digest:** `{rd}`", "", "## Findings", ""]
    for r in scan["results"]:
        mark = {"vulnerable": "❌ VULNERABLE", "resisted": "✅ resisted", "unmeasured": "⚠️ unmeasured"}[r["status"]]
        lines.append(f"- **{r['id']}** ({r['category']}, {r['severity']}) — {mark}")
        if r["status"] == "vulnerable":
            lines.append(f"  - {r['description']}")
            lines.append(f"  - Fix: {REMEDIATION.get(r['id'], 'Review this attack surface.')}")
    s = scan["summary"]
    lines += ["", f"## Summary", f"{s['resisted']}/{s['total']} resisted, {s['vulnerable']} vulnerable, "
              f"{s['unmeasured']} unmeasured.", "",
              "```json", json.dumps({"grade": scan["grade"], "score": scan["score"],
                                     "report_digest": rd, "results": scan["results"]}, indent=2), "```"]
    return {"markdown": "\n".join(lines), "report_digest": rd, "grade": scan["grade"], "score": scan["score"]}


def demo() -> None:
    fake_vuln = {"status": "evaluated", "target_url": "https://x", "grade": "F", "score": 40,
                 "results": [{"id": "prompt-injection-canary", "category": "Prompt Injection",
                             "severity": "critical", "description": "d", "status": "vulnerable"}],
                 "summary": {"total": 1, "vulnerable": 1, "resisted": 0, "unmeasured": 0}}
    out = build(fake_vuln)
    assert out["report_digest"].startswith("0x") and len(out["report_digest"]) == 66
    assert "VULNERABLE" in out["markdown"] and "report_digest" in out["markdown"]
    assert "error" not in out
    not_eval = build({"status": "not-evaluated", "reason": "unreachable", "target_url": "https://x"})
    assert "error" in not_eval and "report_digest" not in not_eval
    d1 = digest(fake_vuln)
    d2 = digest(dict(reversed(list(fake_vuln.items()))))
    assert d1 == d2  # canonical (key-order independent)
    print("report self-check ok")


if __name__ == "__main__":
    demo()
