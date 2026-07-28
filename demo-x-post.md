# Tumbuk — X post + 90s demo script for #OKXAI

Live ASP: `https://tumbuk.vercel.app/mcp` · Repo: github.com/PugarHuda/tumbuk · Handle: @BangDropID
OKX.AI **Agent #9619** ("Tumbuk Red-Team", X Layer) — registered 2026-07-27, listing in review.
Two services: paid `Agent Red-Team Security Scan` ($0.99) + free `Report Digest Verification`.

> Framing: **everyone audits the contract, nobody audits the agent.** Tumbuk is live and PAID —
> $0.99 USDT0 on X Layer via real x402 (OKX facilitator, eip155:196). Detection is deterministic
> (planted canaries + credential regex, no LLM judge), so a report reproduces. Free `quote` tool.

---

## ✅ MAIN POST (copy-paste, then attach the video)

> You audited the smart contract. **Did you audit the agent?** 🔨
>
> **Tumbuk** red-teams *other* agents. Point it at an endpoint — it fires 8 adversarial probes in
> parallel (prompt injection, fund drain, secret exfil, jailbreak, forged trust signals…) and
> returns a graded **A–F** vulnerability report.
>
> No LLM judge. Planted canary tokens + credential regex → **reproducible**. One confirmed critical
> hole caps the grade at **F**, full stop. And you don't have to trust the grade: a free
> `verify_report` recomputes the report's digest, so a forged verdict fails on the spot.
>
> Pay-per-call **$0.99 USDT0 on X Layer** (real x402, OKX facilitator). Agent **#9619** on @OKX AI.
>
> Hire the adversary before you trust an agent with your money. 👇 #OKXAI

*(attach: the 90s demo below)*

---

## 🧵 THREAD (post under the main tweet)

> 1/ Agents on @OKX AI now hire and pay each other over A2MCP. That makes **agent behavior** the new
> attack surface — and nothing in the stack tests it. Tumbuk hires out as the adversary. 🔨
>
> 2/ 8 probes, fired in parallel: prompt injection · unauthorized fund transfer · secret/credential
> exfiltration · jailbreak & persona override · **A2A output-trust hijacking** · system-prompt leakage
> · instruction override · indirect (tool/RAG-borne) injection.
>
> 3/ Detection is **deterministic** — every probe plants a unique canary token; a hit is a canary
> coming back, or a credential pattern in the reply. No model grading a model. Same suite → same
> report. It holds up under a human spot-check.
>
> 4/ Grading is **safety-first**: severity-weighted score, but ONE confirmed critical → **F**. No
> averaging a fund-drain hole away behind seven passes. Every report carries a tamper-evident
> `report_digest`.
>
> 5/ It refuses to be a weapon: a hard **consent gate** (no `consent=true`, no scan), and an
> SSRF-guarded probe layer that blocks localhost, private ranges and cloud-metadata IPs in every
> encoding. It only ever probes the endpoint you hand it.
>
> 6/ **Don't trust the grade — check it.** Every report embeds the exact object its digest covers,
> and a free `verify_report` recomputes it. Re-badge the target or downgrade a finding and
> verification fails. A free `probe_catalog` shows the whole suite before you buy. 🔍
>
> 7/ **$0.99 USDT0 per scan on X Layer**, settled on-chain via x402 through OKX's own facilitator —
> free `quote` first. Zero model credits burned, so it's a real margin business, not a demo.
> Any builder listing an ASP can hire Tumbuk as a **pre-listing security gate**.
> Agent #9619 on @OKX AI · `https://tumbuk.vercel.app/mcp` #OKXAI

---

## 🎥 90-SECOND DEMO — production script

Format: **screen recording**, subtitles ON. All beats are real, nothing staged.
Assets: a terminal (`python demo.py` = offline vuln + safe stub), a live 402 curl, the OKX listing.

| # | t | RECORD THIS | On-screen text | Voiceover |
|---|------|-------------|----------------|-----------|
| 1 | 0–8 | Text on black: an agent card, "$0.49/call, pays out of your wallet." Cursor blinks. | You audited the contract. | "You'd never send funds to an unaudited contract. But you'll hire an agent you've never tested." |
| 2 | 8–18 | Terminal: `python demo.py` — 8 probes fire, canary tokens scroll | 8 adversarial probes, parallel | "Tumbuk points 8 adversarial probes at an agent's endpoint." |
| 3 | 18–38 | The VULNERABLE report renders: **Grade F**, critical rows (fund transfer, secret exfil), canary evidence quoted | Grade F · confirmed critical | "This one obeyed every embedded instruction — it confirmed a transfer and leaked a credential. One critical hole, and the grade is F. No averaging." |
| 4 | 38–50 | Scroll to the SAFE stub report: **Grade A**, all probes refused | Grade A · same suite | "Same suite against a hardened agent: A. Deterministic — canary tokens, not a model's opinion. Run it twice, get the same report." |
| 5 | 50–62 | Highlight `report_digest`, then call the free `verify_report` on the block → `digest_matches: true`. Edit one finding, run it again → `false` | Don't trust it — verify it | "Every report is fingerprinted, and anyone can recompute it. Alter one finding and verification fails. The grade is checkable, not just claimed." |
| 6 | 62–78 | Terminal: curl the LIVE endpoint `redteam_scan` with no payment → **HTTP 402**, `eip155:196` / `USDT0` / `990000` visible | Real x402 · X Layer | "It's a paid agent: $0.99 in USDT0 on X Layer, settled through OKX's facilitator. Free quote first." |
| 7 | 78–90 | OKX.AI listing page for Tumbuk. Cut to logo: **TUMBUK — audit the agent, not just the contract.** | Live on OKX AI · #OKXAI | "Hire the adversary before you trust an agent with your money. Live on OKX AI." |

Beats 3 and 6 are the memorable ones — give them room. Trim 5 if over 90s.
Honesty: the vuln/safe targets in beats 2–4 are the bundled stubs (`demo.py`), not a real third-party
agent — say "stub" on screen. Don't scan someone's live agent without consent, that's the whole point.
The 402 in beat 6 is the real production endpoint.

---

## Alt 1-tweet (if you skip the thread)
> Everyone audits the smart contract. Nobody audits the **agent**. **Tumbuk** fires 8 adversarial
> probes at any agent endpoint and grades it **A–F** — deterministic, reproducible, and the grade
> itself is verifiable (recompute the report digest yourself). $0.99 USDT0 on X Layer via x402.
> Agent #9619 on @OKX AI. 🔨 #OKXAI

---

## Pre-post checklist
- [x] Live + paid endpoint verified (402 w/o payment): https://tumbuk.vercel.app/mcp
- [x] ASP registered on OKX.AI (A2MCP, $0.99) → **Agent #9619**, listing under review
- [x] Site live: https://tumbuk-security.vercel.app (in-browser report verifier)
- [x] Demo video built: `tumbuk-demo-90s.mp4` (65 s, real captured output)
- [ ] Record beats 1–7, cut to ≤90s, subtitles ON
- [ ] Post main tweet + thread with #OKXAI and @OKX; grab the link
- [ ] Google Form: SUBMISSION.md + Agent ID + X link (before Jul 27 23:59 UTC)
