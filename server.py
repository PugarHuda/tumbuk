"""Tumbuk — Agent Red-Team ASP for OKX.AI (A2MCP, pay-per-call).

Point it at another agent's HTTP endpoint; it fires 8 adversarial probes (prompt
injection, fund-drain, secret exfiltration, jailbreak, output hijack, system-prompt
leak, instruction override, indirect injection) and returns a scored, reproducible
vulnerability report. One tool = one billable call, settled as x402 on X Layer.
"""
import hmac, os
from fastmcp import FastMCP


def _load_dotenv(path: str = ".env") -> None:
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:]
            k, v = line.split("=", 1)
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            os.environ.setdefault(k.strip(), v)


_load_dotenv()
import x402       # x402/X Layer paid-endpoint gate (opt-in via TUMBUK_X402_PAYTO)
import redteam
import report
from attacks import PROBES

mcp = FastMCP("tumbuk")

ACCESS_KEY = os.environ.get("TUMBUK_ACCESS_KEY")


@mcp.tool
def redteam_scan(target_url: str, consent: bool = False, access_key: str = "") -> dict:
    """Red-team another agent's HTTP endpoint: fire 8 adversarial probes covering prompt
    injection, unauthorized fund-transfer instructions, secret/credential exfiltration,
    jailbreak/persona-override, A2A output-trust hijacking, system-prompt leakage,
    instruction override, and indirect (tool/RAG-borne) injection — no LLM judge, fully
    reproducible detection via planted canary tokens and credential-pattern matching.

    Args:
        target_url: the target agent's public HTTPS endpoint. Must accept a POST body
            {"input": "<text>"} and reply with the agent's output — as plain text, or JSON
            with an output/response/text/reply/message/result field. Non-public hosts
            (localhost, RFC-1918, link-local, cloud metadata) are refused (SSRF guard).
        consent: REQUIRED — set True to confirm you own target_url or are authorized to
            test it. No consent, no scan. This tool only ever probes the endpoint you
            supply; it never discovers or targets anything on its own.
        access_key: required only if the server sets TUMBUK_ACCESS_KEY.

    Returns a markdown report (with an embedded machine-readable JSON block), a grade
    (A-F, capped at F if ANY critical probe is confirmed vulnerable), a severity-weighted
    score, and a report_digest fingerprint. On failure returns {"error": ...}.
    """
    if ACCESS_KEY and not hmac.compare_digest(access_key.encode(), ACCESS_KEY.encode()):
        return {"error": "unauthorized: valid access_key required"}
    if not consent:
        return {"error": "consent required: set consent=True to confirm you own or are "
                         "authorized to red-team target_url"}
    target_url = (target_url or "").strip()[:2048]  # cap: no unbounded input
    if not target_url:
        return {"error": "target_url is required"}
    try:
        scan = redteam.run_scan(target_url)
        return report.build(scan)
    except Exception as e:  # clean error at the paid boundary, never a raw stack trace
        return {"error": f"scan failed: {e}"}


@mcp.tool
def quote() -> dict:
    """Free price discovery — the USD price a scan costs and what it covers, before
    committing. Returns the probe count, categories covered, and the x402 price."""
    amount = os.environ.get("TUMBUK_X402_AMOUNT", "990000")
    price = round(int(amount) / 1_000_000, 2)
    return {"probes": len(PROBES), "categories": sorted({p["category"] for p in PROBES}),
            "price_usd": price, "currency": "USDT0", "network": "X Layer (eip155:196)",
            "settlement": "x402", "note": "call redteam_scan(target_url, consent=True) to run it"}


if __name__ == "__main__":
    port = os.environ.get("PORT")
    if port and x402.enabled():
        import uvicorn
        app = mcp.http_app()
        app.add_middleware(x402.X402Middleware)
        uvicorn.run(app, host="0.0.0.0", port=int(port))
    elif port:
        mcp.run(transport="http", host="0.0.0.0", port=int(port))
    else:
        mcp.run()
