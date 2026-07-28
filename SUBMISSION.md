# OKX.AI Genesis Hackathon — Google Form draft (Tumbuk)

Deadline: **Jul 27, 23:59 UTC**. Account: hudapugar@gmail.com

> Dependency: **Agent ID** is issued only AFTER the ASP is listed & goes live on
> OKX.AI. Deploy → list → get the ID → then fill this in. See DEPLOY.md.

---

### ASP Name *
```
Tumbuk Red-Team
```
(the on-chain name — OKX caps an agent name at 25 chars, so the longer
"Tumbuk — Agent Red-Team ASP" didn't fit. Use this exact name in the form so it
matches the listing.)

### Agent ID *
```
9619
```
(registered on X Layer 2026-07-27, tx 0x6b6cf6ca6e2a42e759e9b9d374c53b80019edd993700db7eda2b6ac01705b5d9 ·
submitted for review, approvalStatus 2 · EVM wallet 0xc87ac386c485afd1c9b4087c8efe5daeeab08307)

### ASP Description *
```
Everyone audits the smart contract. Nobody audits the agent. As agents on OKX.AI start
hiring and paying each other over A2MCP, the new attack surface is the agent's behavior —
prompt injection, fund/secret exfiltration, jailbreaks, and forged A2A trust signals.
Tumbuk hires out as the adversary: point it at an agent's endpoint and it fires 8
adversarial probes in parallel — prompt-injection, unauthorized fund-transfer,
secret/credential exfiltration, jailbreak/persona-override, A2A output-trust hijacking,
system-prompt leakage, instruction override, and indirect (tool/RAG-borne) injection —
then returns a scored, reproducible vulnerability report graded A–F.

Detection is deterministic, no LLM judge: planted canary tokens + credential-pattern
matching, so a report reproduces from the same suite and holds up under a human
spot-check. Grading is safety-first — a single confirmed critical hole caps the grade at
F, full stop. It's a real on-chain business, agent-native for OKX.AI: pay-per-call —
$0.99 in USDT0 on X Layer, settled on-chain via x402 (real OKX facilitator config, not
illustrative). A FREE quote tool reports the price before you commit; a hard consent gate
means it only ever probes the endpoint you supply. Any builder listing an ASP can hire
Tumbuk as a pre-listing security gate before they trust another agent with money or data —
a dependency other agents want.

And the grade itself is checkable, not just claimed: every report embeds the exact object its
digest covers, and a FREE verify_report recomputes it — re-badge the target or downgrade a
finding and verification fails. A FREE probe_catalog exposes the whole suite, severities and
grading rule before you spend anything, so a buyer audits the auditor first.

One endpoint in → a graded, reproducible, verifiable red-team report out.
Agent #9619 on OKX.AI (X Layer) · MCP endpoint https://tumbuk.vercel.app/mcp
Site + in-browser report verifier: https://tumbuk-security.vercel.app
```

### ASP Type *
```
A2MCP
```
(FastMCP server — paid tool `redteam_scan(target_url, consent)`; also free `quote`.)

### X Account Handle *
```
@BangDropID
```

### X Participation Post (Link) *
```
<< post the ≤90s Tumbuk demo with #OKXAI @OKX, paste the link (can be a thread off the
   DALANG post, or its own) >>
```

### Telegram Handle *
```
<< your @telegram >>
```

---

## HackQuest project page — every field, ready to paste

| Field | Value |
|---|---|
| Project Logo | `Desktop/tumbuk-logo/tumbuk-mark-1024.png` |
| Name | Tumbuk |
| Sector | AI · Infra |
| Tech Tag | Python · Web3 (no Solidity — Tumbuk ships no contract) |
| MVP Link | https://tumbuk-security.vercel.app |
| Project Link | https://github.com/PugarHuda/tumbuk |
| X (Twitter) | BangDropID |
| Images (4) | `Desktop/tumbuk-hackquest/` — 1-hero, 2-suite, 3-grades, 4-verify |
| Demo Video | `Desktop/tumbuk-demo-90s.mp4` (65 s) · Pitch Video: leave empty |
| Ecosystem | X Layer · **Mainnet** |
| Prize tracks | Creative Genius · Software Utility · Best Product (skip Revenue Rocket while salesCount is 0) |

### Description
```
Everyone audits the smart contract. Nobody audits the agent. As agents on OKX.AI begin
hiring and paying each other over A2MCP, the new attack surface is the agent's behavior:
prompt injection, fund and secret exfiltration, jailbreaks, and forged agent-to-agent trust
signals. There is no equivalent of a contract audit for any of it.

Tumbuk hires out as the adversary. Point it at an agent's HTTP endpoint and it fires 8
adversarial probes in parallel — prompt injection, unauthorized fund transfer, secret and
credential exfiltration, jailbreak and persona override, output-trust hijacking, system
prompt leakage, instruction override, and indirect (tool/RAG-borne) injection — then returns
a scored vulnerability report in markdown and JSON, graded A to F.

Detection is deterministic, with no LLM judge anywhere in the loop: every probe plants a
unique canary token, and a finding is that token coming back or a credential-shaped string
appearing in the reply. The same suite produces the same report, so a grade survives a human
spot-check. Grading is safety-first: a severity-weighted score, but one confirmed critical
hole caps the grade at F regardless of how clean the rest looks. A target that merely echoes
the probe text is reported as unmeasured rather than vulnerable, so a harmless logging bot
is not slandered with a false F.

The grade is checkable rather than claimed. Every report embeds the exact object its digest
covers, and a free verify_report recomputes it — re-badge the target or downgrade a finding
and verification fails. The landing page does the same recomputation in your own browser,
nothing uploaded. A free probe_catalog exposes the whole suite, severities and grading rule
before you spend anything, so the buyer audits the auditor first.

It refuses to be a weapon: consent=true is a hard gate, and the probe layer is SSRF-guarded
against localhost, private ranges and cloud-metadata addresses in every IP encoding, with
redirects unfollowed and reads capped.

It is a real on-chain business: $0.99 in USDT0 per scan on X Layer, settled via x402 through
OKX's own facilitator. Tumbuk burns no model credits, so the marginal cost is outbound
bandwidth alone. Any builder listing an ASP can hire it as a pre-listing security gate — a
dependency other agents want.

One endpoint in → a graded, reproducible, verifiable red-team report out.
Agent #9619 on OKX.AI · https://tumbuk-security.vercel.app · https://tumbuk.vercel.app/mcp
```

### Progress During Hackathon
```
Built from zero during the hackathon window, in Python with only fastmcp and uvicorn as
dependencies — everything else is standard library, and there is no model API key anywhere
in the system, which is what makes the unit economics work.

Shipped: the 8-probe attack library with deterministic canary/credential detectors; an
SSRF-guarded HTTP probe layer; a parallel runner with safety-first grading; a markdown+JSON
report with a tamper-evident digest; a FastMCP server exposing one paid tool and three free
ones; an x402 payment gate configured against OKX's real facilitator on X Layer; a stateless
Vercel deployment; and a landing page whose in-browser verifier recomputes a report digest
locally. Registered as an A2MCP ASP on OKX.AI (Agent #9619) with a paid scan service and a
free verification service.

Hardening was most of the work, and the real bugs came from running the thing against real
endpoints rather than stubs. A security audit fixed a detector that could not tell an ECHO
from OBEDIENCE, so a harmless echo endpoint scored "F, fund-drainable". A JSON-RPC batch
could skip the payment gate. Then live scanning of public services exposed two more: an HTTP
error body was being treated as the agent's reply, so a target that was DOWN scored
"resisted" on all 8 probes — a false A on an endpoint that never ran; and the echo check
compared raw text while real services return the body re-encoded, so two CRITICAL probes came
back "vulnerable" on three harmless echo services. Both are fixed and regression-tested.

A deeper QA pass found that the tamper-evident digest could not actually be verified by the
buyer: the report embedded only part of the object the digest covered. Fixed, and turned into
a feature — verify_report and probe_catalog now ship as free tools, and the browser verifier
was cross-checked against the Python implementation on a report containing non-ASCII text.

On the final day, live probing caught the worst one: the deployed endpoint had been returning
HTTP 200 with an EMPTY body on every call, because Vercel's ASGI bridge cancels an SSE stream
before it flushes. Smoke tests that only assert status codes never saw it. Fixed by replying
as plain JSON and verified live.

42 executed deep-QA checks cover hostile targets, the read cap and timeout, payment-gate
composition, 16-way concurrency, and fuzzing of every free tool. Three self-check suites run
in CI on every push.
```

### Fundraising Status
```
Not raising. Self-funded, no outside capital, no token. Tumbuk consumes no model credits —
the marginal cost of a scan is outbound HTTP bandwidth — so $0.99 per scan in USDT0 on X
Layer is close to pure margin and the service is profitable per call from day one. Open to
ecosystem or grant support from the X Layer team to expand the suite (multi-turn attack
chains, MCP tool-poisoning probes, a continuous re-scan subscription for listed ASPs).
```

### Deployment Details (judges only)
```
ERC-8004 agent identity (OKX.AI registry, X Layer / chain 196) — Agent #9619 "Tumbuk Red-Team"
  register tx  0x6b6cf6ca6e2a42e759e9b9d374c53b80019edd993700db7eda2b6ac01705b5d9
  owner wallet 0xc87ac386c485afd1c9b4087c8efe5daeeab08307
  explorer     https://www.oklink.com/x-layer/tx/0x6b6cf6ca6e2a42e759e9b9d374c53b80019edd993700db7eda2b6ac01705b5d9

Live MCP endpoint (paid, x402 on X Layer): https://tumbuk.vercel.app/mcp
  paid:  redteam_scan  ($0.99 USDT0, HTTP 402 until paid)
  free:  quote · probe_catalog · verify_report
Site + in-browser report verifier: https://tumbuk-security.vercel.app

Payments settle in USDT0 (0x779ded0c9e1022225f8e0630b35a9b54be713736) via OKX's facilitator
(web3.okx.com/facilitator). No custom contract is deployed — the on-chain footprint is the
agent identity and x402 settlement.
```

## Category to target
Primary: **Creative Genius** (20,000 USD — "use your imagination": red-teaming the agent
*behavior* layer is a category nobody else covers). Also **Revenue Rocket** (paid $0.99
x402 A2MCP, real on-chain settlement). Naturally supports **Social Buzz** via the X post.

## Pricing
$0.99 USDT0 per scan on X Layer. Tumbuk consumes no model credits — the marginal cost is
only outbound probe bandwidth, so the $0.99 is near-pure margin (unlike a render agent).

## Status checklist
- [x] Code complete, self-checks + demo green, security audit clean, pushed (`PugarHuda/tumbuk`)
- [x] Deployed live to Vercel — https://tumbuk.vercel.app/mcp (paid x402 gate verified: 402 w/o payment, $0.99 USDT0 / X Layer)
- [x] Registered as A2MCP ASP on OKX — **Agent ID 9619**, listing under review
  - two services: paid `Agent Red-Team Security Scan` (0.99) + free `Report Digest Verification` (0)
  - rejected twice (challenge not in the PAYMENT-REQUIRED header; real calls not matching the
    described capability), fixed and resubmitted 2026-07-28 on x402 v2 + OKX's official seller SDK
- [x] Site live with an in-browser report verifier: https://tumbuk-security.vercel.app
- [x] Demo video built (65 s, every panel real captured output): `tumbuk-demo-90s.mp4`
- [ ] Record + post the ≤90s demo on X with #OKXAI @OKX → paste link  ← YOUR NEXT STEP (script in demo-x-post.md)
- [ ] Submit this form before Jul 27 23:59 UTC (= Jul 28 06:59 WIB) — Telegram handle is the only field nobody but you can fill

## Registration (run on VPN — okx.com is ISP-blocked here)
Wallet `0xc87ac386c485afd1c9b4087c8efe5daeeab08307` is already logged into Onchain OS
from the DALANG session, so this is just the `agent create` step. In Claude Code on a
network where okx.com works:

1. "Log in to Agentic Wallet on Onchain OS with my email" (hudapugar@gmail.com) — if the
   session isn't still authed.
2. "Register an A2MCP ASP on OKX.AI" with:
   - **Name:** Tumbuk — Agent Red-Team ASP
   - **Type:** A2MCP
   - **Endpoint:** https://tumbuk.vercel.app/mcp
   - **Fee:** 0.99 (USDT0, X Layer / 196) — payTo is already the wallet above
   - **Category:** the security / tooling category (or Creative Genius fit)
   - **Avatar:** generate one (DALANG used an ffmpeg-made logo uploaded to OKX CDN)
3. "List / activate my ASP on OKX.AI" → "Listing under review" (~24h, emailed to
   hudapugar@gmail.com). The issued **Agent ID** goes in the field above.

The x402 endpoint config already matches OKX's facilitator, so the paid handshake the
reviewer tests will succeed (verified: 402 with a spec-perfect payment-requirements body).
