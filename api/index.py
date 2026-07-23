"""Vercel serverless entrypoint for the Tumbuk red-team ASP.

Serves the MCP endpoint at /mcp as a stateless ASGI app (serverless keeps no session
between requests). No ffmpeg / filesystem dependency — every probe is a plain HTTP
call, so this needs nothing beyond fastmcp + uvicorn.
"""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # loads .env, builds mcp + the x402 gate

app = server.mcp.http_app(stateless_http=True)
if server.x402.enabled():
    app.add_middleware(server.x402.X402Middleware)
