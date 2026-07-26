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


def verify(payload) -> dict:
    """Recompute a report's digest from its own embedded payload — the buyer's side of the
    tamper-evident claim. Accepts the report's embedded JSON block (dict or JSON string),
    or a bare scan object plus a digest to compare against.

    Deliberately does NOT return a "report_digest" key: that quoted key is the x402 settle
    sentinel (x402.py), and this is a FREE tool — emitting it would let a batch pair a failed
    paid scan with a free verify and settle on the free tool's output.
    """
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", "replace")
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, dict):
        raise ValueError("expected a JSON object")
    scan = payload.get("scan") if isinstance(payload.get("scan"), dict) else payload
    claimed = payload.get("report_digest") or payload.get("digest") or ""
    recomputed = digest(scan)
    return {"recomputed_digest": recomputed, "claimed_digest": claimed,
            "digest_matches": bool(claimed) and recomputed == claimed,
            "note": "digest = sha256 over the canonical JSON (sorted keys, no whitespace) of the scan object"}


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
              "```json",
              # embed the EXACT object the digest was taken over, so the buyer can recompute it
              # (verify_report / report.verify). Omitting target_url+status+summary, as this block
              # used to, made the "tamper-evident digest" unverifiable by anyone but us.
              json.dumps({"report_digest": rd, "scan": scan}, indent=2, sort_keys=True), "```"]
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

    # the buyer must be able to recompute the digest from the report ALONE
    block = json.loads(out["markdown"].split("```json")[1].split("```")[0])
    v = verify(block)
    assert v["digest_matches"] and v["recomputed_digest"] == out["report_digest"], v
    assert "report_digest" not in v  # free tool must not emit the x402 settle sentinel
    tampered = json.loads(json.dumps(block))
    tampered["scan"]["grade"] = "A"  # forge a pass
    assert verify(tampered)["digest_matches"] is False
    assert verify(json.dumps(block))["digest_matches"]  # accepts a JSON string too
    print("report self-check ok")


if __name__ == "__main__":
    demo()
