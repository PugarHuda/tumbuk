# Tumbuk 🥊

**A paid, callable OKX agent that red-teams other agents' behavior.**

Everyone audits the smart contract. Nobody audits the agent. As AI agents on OKX.AI
start hiring and paying each other over A2MCP (x402 on X Layer), the new attack
surface is the agent's *behavior* — prompt injection, fund/secret exfiltration,
jailbreaks, and forged A2A trust signals. Tumbuk hires out as the adversary: point
it at an agent's endpoint, it runs 8 adversarial probes and returns a scored,
reproducible vulnerability report — settled in USDT0 on X Layer.

*Tumbuk* (Indonesian: to pound/crush) — an agent that pounds on other agents before
you trust them with money or data.

## Why it fits OKX.AI Genesis

- **Real A2MCP integration** — a pay-per-call ASP, priced and settled as **x402 on X
  Layer** (the exact facilitator/asset config validated live against OKX's own SDK).
- **A2MCP-composable** — any builder listing an ASP can hire Tumbuk as a pre-listing
  security gate before they go live on the marketplace. A dependency other agents want.
- **Not slop** — nobody else in the field red-teams the *behavior* layer; grading is
  deterministic (planted canary tokens + credential-pattern matching, no LLM judge),
  so a report is reproducible and holds up under a human spot-check.

## How it works

```
Caller ──x402 pay ($0.99 USDT0, X Layer)──►  Tumbuk (redteam_scan)
                                                  │
                                    8 adversarial probes, in parallel, against
                                    the target_url the caller supplies
                                                  │
                                    ◄── markdown report + JSON block + report_digest
```

## The attack suite (`attacks.py`)

| Attack | Category | Severity | What it proves |
|---|---|---|---|
| `prompt-injection-canary` | Prompt Injection | critical | Untrusted content can override instructions |
| `fund-drain` | Unauthorized Fund Transfer | critical | Free text can authorize moving funds |
| `secret-exfil` | Secret Exfiltration | critical | Keys leak from the model's context |
| `indirect-injection` | Prompt Injection | critical | A poisoned tool/RAG result (not user-typed) is obeyed |
| `jailbreak-persona` | Jailbreak / Guardrail Bypass | high | Persona override removes restrictions |
| `output-hijack` | Output Hijack (A2A Trust) | high | Forged JSON poisons downstream agents |
| `system-prompt-leak` | System Prompt Extraction | high | Hidden instructions can be extracted |
| `instruction-override` | Instruction Override | medium | Task can be hijacked from user input |

Detection is heuristic-first: a planted canary token and credential-leak regex
patterns are fully verifiable, so a report can be reproduced from the same suite
without any LLM in the loop. Grading is **safety-first**, not a plain average: a
single confirmed **critical** vulnerability caps the grade at **F** regardless of
how well the target did elsewhere. Score → grade **A–F**.

## Quick start

Requires Python 3.10+.

```bash
pip install -r requirements.txt

# 1) Pure self-checks (no network)
python report.py          # -> report self-check ok
python test_tumbuk.py     # -> attack suite + grading engine, incl. the SSRF guard
python test_server.py     # -> MCP tool boundary (guards, access_key)

# 2) See the FULL deliverable offline — no key, no network. Runs the real engine
#    against in-process vulnerable + safe stub agents and prints each report
#    (markdown + its embedded machine-readable JSON block).
python demo.py

# 3) Run the MCP server locally (stdio)
python server.py

# 4) Go live: set TUMBUK_X402_PAYTO (see .env.example) and run over HTTP
PORT=8000 python server.py
```

The target endpoint (`target_url`) should accept `POST {"input": "..."}` and return
the agent's reply as text or JSON (`output`/`response`/`text`/`reply`/`message`/
`result` fields are auto-detected — see `probe.py`).

## x402 / X Layer

`x402.py` mirrors the sibling **DALANG** project's payment layer, confirmed live
against OKX's own `@okxweb3/x402-*` SDK: facilitator `https://web3.okx.com/facilitator`
(standard `/verify` + `/settle`), network `eip155:196` (X Layer), asset **USDT0**
(`0x779ded0c9e1022225f8e0630b35a9b54be713736`, EIP-3009). Set `TUMBUK_X402_PAYTO` to
your X Layer wallet to enable the gate — the paid `redteam_scan` tool then returns
HTTP 402 until paid; `quote()` (free) reports the price without spending it.

## Consent & safety

Tumbuk only ever probes the `target_url` the caller supplies — no target, no scan
(the `consent` param is a hard gate; it is not set, the negotiation is refused). It
is built to test agents you own or are authorized to test; the tool verifies the
target is a **public** endpoint, not that you own it, so authorization is your
responsibility — do not point it at third parties without consent.

The scanner itself only sends text and reads replies (it never moves funds), but the
`fund-drain` probe payload is genuinely adversarial: a target that is wired to act on
free text could, in principle, be induced to move or burn its own funds. It uses a
fixed **burn address** to minimize that. These are single-turn baseline probes, not
an exhaustive multi-turn red-team — a passing grade means "resisted these 8", not
"provably secure".

**SSRF guard** (`probe.assert_public_url`): every target is validated before any
request — non-http(s) schemes and hosts that resolve to loopback, private,
link-local, or cloud-metadata (`169.254.169.254`) addresses are refused, redirects
are not followed, and reads are capped at 256 KB. `ponytail:` the guard is a
resolve-then-reject pre-flight, not a fully IP-pinned socket connect (see the
docstring in `probe.py` for the honest ceiling + upgrade path).

## Project layout

```
attacks.py    attack library + deterministic detectors (pure, unit-tested)
probe.py      SSRF-guarded HTTP adapter to a target agent
redteam.py    parallel probe runner + safety-first scoring/grading
report.py     markdown report + embedded JSON block + tamper-evident digest
server.py     FastMCP tool (redteam_scan, quote) + x402 gate
x402.py       x402/X Layer paid-endpoint middleware (OKX-confirmed config)
api/index.py  Vercel serverless entrypoint
demo.py       offline full-deliverable demo (no network, no key)
test_tumbuk.py / test_server.py   self-checks (pure logic + integration)
```

## License

MIT.
