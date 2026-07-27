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
- [x] Registered as A2MCP ASP on OKX — **Agent ID 9619**, submitted for review (2026-07-27)
  - two services: paid `Agent Red-Team Security Scan` (0.99) + free `Report Digest Verification` (0)
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
