# Deploying the Tumbuk ASP

Tumbuk is a **pure-HTTP** MCP server — no ffmpeg, no filesystem, no model key. Every
probe is an outbound HTTP call to the caller-supplied `target_url`. That makes it the
easy deploy: a stateless serverless function is enough. **Recommended: Vercel.**

## Vercel (recommended)
The repo ships the serverless entrypoint (`api/index.py`, `vercel.json`): a stateless
FastMCP app; the x402 gate turns on only when `TUMBUK_X402_PAYTO` is set.

Via CLI (fastest, from the repo root):
```bash
vercel link          # create/link a project (e.g. "tumbuk")
vercel --prod        # deploy
```
Or dashboard: **vercel.com → Add New → Project → import `PugarHuda/tumbuk`**, Root
Directory = repo root.

### Environment variables (Vercel → Settings → Environment Variables)
To go **paid** (x402 on X Layer — OKX-confirmed config, same as DALANG):
```
TUMBUK_X402_PAYTO   = 0x<your X Layer wallet>        # enables the 402 gate
# the rest already default to the confirmed OKX values — override only if needed:
TUMBUK_X402_AMOUNT       = 990000                    # $0.99 USDT0 (6dp)
TUMBUK_X402_ASSET        = 0x779ded0c9e1022225f8e0630b35a9b54be713736  # USDT0
TUMBUK_X402_NETWORK      = eip155:196                 # X Layer
TUMBUK_X402_FACILITATOR  = https://web3.okx.com/facilitator
TUMBUK_X402_ASSET_NAME   = USD₮0
```
**Required for a listing that passes OKX review** — the facilitator answers **403 to
unsigned calls**, so without these the paid path can never verify anything:
```
OKX_API_KEY     = <from the OKX Developer Portal>
OKX_SECRET_KEY  = <same>
OKX_PASSPHRASE  = <the passphrase you chose when creating the key>
```
Get them at **https://web3.okx.com/onchainos/dev-portal**. Set them from a shell that
does not add a BOM — a PowerShell pipe prepends `﻿` to the value and the SDK's
request signing then dies with `'ascii' codec can't encode character`, which reads like
a unicode problem in the EIP-712 name and sends you hunting the wrong thing:
```bash
printf '%s' "<value>" | vercel env add OKX_API_KEY production
```

To stay **free** (fastest OKX review): set nothing — the tool runs unpaid.
To protect a free/public endpoint from abuse: set `TUMBUK_ACCESS_KEY` (callers must
then pass a matching `access_key`).

## Smoke test after deploy
**Check bodies, not status codes.** A deploy that returns `200` with an *empty* body on
every call looks healthy to a status-only check and is completely broken to a caller
(see the `json_response` note in the README).

A raw `curl` handshake works for `tools/list` and for the 402 gate; a full paid call
needs a real `PAYMENT-SIGNATURE`. Quick checks:
```bash
# free tool listing -> 200
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<host>/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# paid tool without payment -> 402 (only when TUMBUK_X402_PAYTO is set)
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<host>/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"redteam_scan","arguments":{"target_url":"https://example.com","consent":true}}}'
```
FastMCP client listing:
```bash
python - <<'PY'
import asyncio
from fastmcp import Client
async def main():
    async with Client("https://<host>/mcp") as c:
        print("tools:", [t.name for t in await c.list_tools()])
asyncio.run(main())
PY
# expect: tools: ['redteam_scan', 'quote', 'probe_catalog', 'verify_report']
```
Also confirm the challenge travels in the **header**, since that is what OKX's client
reads (and what a rejection was once written for):
```bash
curl -sD - -o /dev/null -X POST https://<host>/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"redteam_scan","arguments":{"target_url":"https://example.com","consent":true}}}' \
  | grep -i payment-required
```

## Register on OKX.AI (A2MCP)
Needs the OKX Onchain OS CLI + Agentic Wallet on a network where `okx.com` is reachable
(the ISP intercepts it here — use a VPN). Same flow that listed DALANG (#7234); Tumbuk is
**Agent #9619**:
1. `onchainos` → log in to Agentic Wallet (email code).
2. `agent create` → type **A2MCP**, endpoint `https://<host>/mcp`, fee `0.99` (paid) or
   `0` (free), chain X Layer (196). See `SUBMISSION.md` for the exact field values.
3. Activate → "Listing under review" (~24h, result emailed).

### What the review actually checks
Four rejections, four distinct causes — all now closed and regression-tested:
1. **`PAYMENT-REQUIRED` header missing** — the challenge must be a base64 header, not
   only a JSON body.
2. **Wrong protocol version** — OKX is on **x402 v2** (`amount`, `payTo`, object
   `resource`); a v1-only endpoint that also rejects v2 payloads fails.
3. **Not on the official SDK** — the facilitator 403s unsigned calls, so verification
   is impossible without portal credentials.
4. **"Results don't match the service description"** — usually not the text at all: it
   means a real call didn't produce what you promised. Describe the service by the exact
   MCP tool names and arguments, and make sure a paying caller is actually served.

Before every resubmit, run `scratchpad/qa_review_sim.py` (40 checks): it validates the
live 402 against OKX's own SDK models, drives the full MCP flow, and asserts each listing
claim against real output.

> Tumbuk spends **no** model credits — the only cost of a public endpoint is outbound
> bandwidth from the probes. There is no key to leak. Keep the x402 gate on (or an
> access_key) mainly to bill for the scan, not to protect a secret.
