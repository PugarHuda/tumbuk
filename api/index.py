"""Vercel serverless entrypoint for the Tumbuk red-team ASP.

Serves the MCP endpoint at /mcp as a stateless ASGI app (serverless keeps no session
between requests). No ffmpeg / filesystem dependency — every probe is a plain HTTP
call, so this needs nothing beyond fastmcp + uvicorn.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # loads .env, builds mcp + the x402 gate

# json_response=True is REQUIRED here, not a preference: with the default SSE transport
# Vercel's ASGI bridge kills the stream before it flushes ("ASGI callable returned without
# completing response" in the function log) and every caller gets HTTP 200 with an EMPTY
# body — tools/list and every tool call included. Plain JSON replies complete in one shot.
app = server.mcp.http_app(stateless_http=True, json_response=True)
if server.x402.enabled():
    app.add_middleware(server.x402.X402Middleware)
