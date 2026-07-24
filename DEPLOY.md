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
To stay **free** (fastest OKX review): set nothing — the tool runs unpaid.
To protect a free/public endpoint from abuse: set `TUMBUK_ACCESS_KEY` (callers must
then pass a matching `access_key`).

## Smoke test after deploy
A raw `curl` handshake works for `tools/list` and for the 402 gate; a full paid call
needs a real `X-PAYMENT`. Quick checks:
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
# expect: tools: ['redteam_scan', 'quote']
```

## Register on OKX.AI (A2MCP)
Needs the OKX Onchain OS CLI + Agentic Wallet on a network where `okx.com` is reachable
(the ISP intercepts it here — use a VPN). Same flow that listed DALANG (#7234):
1. `onchainos` → log in to Agentic Wallet (email code).
2. `agent create` → type **A2MCP**, endpoint `https://<host>/mcp`, fee `0.99` (paid) or
   `0` (free), chain X Layer (196). See `SUBMISSION.md` for the exact field values.
3. Activate → "Listing under review" (~24h, result emailed).

> Tumbuk spends **no** model credits — the only cost of a public endpoint is outbound
> bandwidth from the probes. There is no key to leak. Keep the x402 gate on (or an
> access_key) mainly to bill for the scan, not to protect a secret.
