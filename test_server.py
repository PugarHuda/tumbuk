"""Integration test for the MCP tool boundary — guards, access_key, and the SSRF guard
end-to-end through the real redteam_scan() call (no network needed: a blocked target
IS the test). python test_server.py
"""
import sys
import server

FAILS = []
def check(name, cond, extra=""):
    print(("  ok  " if cond else " FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        FAILS.append(name)


def main():
    server.ACCESS_KEY = None

    print("== guards return clean {error}, never raise ==")
    check("no target_url", "error" in server.redteam_scan(target_url="", consent=True))
    r = server.redteam_scan(target_url="https://example.com/agent", consent=False)
    check("no consent -> refused", "consent" in r.get("error", ""))

    print("\n== SSRF guard reached end-to-end through the real tool (localhost refused) ==")
    r = server.redteam_scan(target_url="http://127.0.0.1:9/", consent=True)
    check("localhost target -> clean {error}, no crash", "error" in r, str(r)[:200])

    print("\n== access_key ==")
    server.ACCESS_KEY = "secret"
    r = server.redteam_scan(target_url="https://example.com/x", consent=True, access_key="wrong")
    check("wrong access_key -> unauthorized", "unauthorized" in r.get("error", ""))
    r = server.redteam_scan(target_url="http://127.0.0.1:9/", consent=True, access_key="secret")
    check("right access_key -> past the gate (reaches the SSRF guard)", "error" in r)
    server.ACCESS_KEY = None

    print("\n== quote() is free pricing, no consent/target needed ==")
    q = server.quote()
    check("quote has price_usd + probe count", q["price_usd"] > 0 and q["probes"] == 8, str(q))

    print("\n== probe_catalog() is free and describes all 8 probes ==")
    cat = server.probe_catalog()
    check("catalog lists 8 probes", len(cat["probes"]) == 8, str(len(cat["probes"])))
    check("catalog explains grading + detection", "critical" in cat["grading"] and "canary" in cat["detection"])

    print("\n== verify_report() proves a report is unaltered, and catches a forged grade ==")
    import json as _json, redteam as _rt, report as _rp
    scan = _rt.run_scan("https://x", send=lambda u, t: "I will not comply.")
    rep = _rp.build(scan)
    block = rep["markdown"].split("```json")[1].split("```")[0]
    v = server.verify_report(block)
    check("untouched report verifies", v.get("digest_matches") is True, str(v)[:160])
    check("verify_report never emits the x402 settle sentinel", "report_digest" not in v, str(v.keys()))
    forged = _json.loads(block)
    forged["scan"]["target_url"] = "https://a-different-agent.example"  # re-badge whose grade this is
    check("re-badged target fails verification", server.verify_report(_json.dumps(forged))["digest_matches"] is False)
    hidden = _json.loads(block)
    hidden["scan"]["results"][0]["severity"] = "low"  # downgrade a finding
    check("downgraded finding fails verification", server.verify_report(_json.dumps(hidden))["digest_matches"] is False)
    check("garbage input -> clean error, no raise", "error" in server.verify_report("not json at all"))
    check("empty input -> clean error", "error" in server.verify_report("   "))

    print("\n" + ("test_server: ALL PASSED" if not FAILS else f"test_server FAILURES: {FAILS}"))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
