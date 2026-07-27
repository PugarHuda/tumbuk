"""x402 payment layer — makes Tumbuk a native paid endpoint for OKX A2MCP / X Layer.

Opt-in: set TUMBUK_X402_PAYTO (your X Layer wallet). When enabled, a `tools/call`
for the paid tool over HTTP must carry a verified `X-PAYMENT` header; otherwise the
server answers HTTP **402** with x402 payment requirements (USDT0 on X Layer) —
exactly the "x402-based paid endpoint" form OKX A2MCP settles via the Agent Payments
Protocol. Verification/settlement is delegated to a configured facilitator (the x402
design), so no private keys ever touch this server. Off by default -> free / access_key.

Config values are the CONFIRMED OKX values (extracted + validated against the
@okxweb3/x402-* SDK and OKX's own facilitator, same as the sibling DALANG project):
facilitator https://web3.okx.com/facilitator, network eip155:196, asset USDT0
0x779ded0c9e1022225f8e0630b35a9b54be713736.

Spec: coinbase/x402 v1. The handshake and tools/list stay free; only the paid
tools/call is gated.
"""
import asyncio, base64, json, os, urllib.request

PAID_TOOL = "redteam_scan"
MCP_PATH = os.environ.get("TUMBUK_MCP_PATH", "/mcp")


def _cfg() -> dict:
    return {
        "payTo": os.environ.get("TUMBUK_X402_PAYTO", ""),
        "asset": os.environ.get("TUMBUK_X402_ASSET", "0x779ded0c9e1022225f8e0630b35a9b54be713736"),
        "network": os.environ.get("TUMBUK_X402_NETWORK", "eip155:196"),
        "amount": os.environ.get("TUMBUK_X402_AMOUNT", "990000"),  # atomic units ($0.99 USDT0, 6dp)
        "facilitator": os.environ.get("TUMBUK_X402_FACILITATOR", "https://web3.okx.com/facilitator"),
        "description": os.environ.get("TUMBUK_X402_DESCRIPTION", "One Tumbuk red-team scan"),
        "timeout": int(os.environ.get("TUMBUK_X402_TIMEOUT", "300")),
        "asset_name": os.environ.get("TUMBUK_X402_ASSET_NAME", "USD₮0"),
        "asset_version": os.environ.get("TUMBUK_X402_ASSET_VERSION", "1"),
    }


def enabled() -> bool:
    return bool(os.environ.get("TUMBUK_X402_PAYTO"))


def challenge(resource: str) -> dict:
    """The x402 challenge: {x402Version, resource, accepts:[…]}.

    `amount` AND `maxAmountRequired` both carry the atomic price — the coinbase/x402 v1
    body names it maxAmountRequired, while OKX's listing review requires `amount`; sending
    both satisfies either reader.
    """
    c = _cfg()
    extra = {"name": c["asset_name"], "version": c["asset_version"]} if c["asset_name"] else {}
    return {"x402Version": 1, "resource": resource, "accepts": [{
        "scheme": "exact", "network": c["network"],
        "amount": c["amount"], "maxAmountRequired": c["amount"],
        "asset": c["asset"], "payTo": c["payTo"], "resource": resource,
        "description": c["description"], "mimeType": "application/json",
        "maxTimeoutSeconds": c["timeout"], "extra": extra}]}


def challenge_header(resource: str) -> bytes:
    """base64 of the challenge, for the PAYMENT-REQUIRED response header. A caller that
    reads only headers (OKX's reviewer does) must still be able to obtain the payment
    requirements — a body-only 402 got this listing rejected."""
    return base64.b64encode(json.dumps(challenge(resource), separators=(",", ":")).encode())


def payment_requirements(resource: str) -> dict:
    return challenge(resource) | {"error": "X-PAYMENT header is required"}


def verify(x_payment_b64: str, resource: str) -> tuple[bool, str]:
    if not x_payment_b64:
        return False, "missing X-PAYMENT header"
    try:
        payload = json.loads(base64.b64decode(x_payment_b64))
    except Exception:
        return False, "malformed X-PAYMENT header"
    if not isinstance(payload, dict):
        return False, "malformed X-PAYMENT header"
    if payload.get("x402Version") != 1 or payload.get("scheme") != "exact":
        return False, "unsupported payment scheme"
    fac = _cfg()["facilitator"]
    if not fac:
        return False, "no facilitator configured"
    body = json.dumps({"x402Version": 1, "paymentPayload": payload,
                       "paymentRequirements": payment_requirements(resource)["accepts"][0]}).encode()
    try:
        req = urllib.request.Request(fac.rstrip("/") + "/verify", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            res = json.loads(r.read())
        return bool(res.get("isValid")), res.get("invalidReason", "")
    except Exception as e:
        return False, f"facilitator error: {e}"


def settle(x_payment_b64: str, resource: str) -> tuple[bool, dict]:
    fac = _cfg()["facilitator"]
    if not fac:
        return False, {"error": "no facilitator configured"}
    try:
        payload = json.loads(base64.b64decode(x_payment_b64))
    except Exception:
        return False, {"error": "malformed X-PAYMENT header"}
    body = json.dumps({"x402Version": 1, "paymentPayload": payload,
                       "paymentRequirements": payment_requirements(resource)["accepts"][0]}).encode()
    try:
        req = urllib.request.Request(fac.rstrip("/") + "/settle", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.loads(r.read())
        return bool(res.get("success")), res
    except Exception as e:
        return False, {"error": f"settlement failed: {e}"}


def is_paid_call(body: bytes) -> bool:
    try:
        msg = json.loads(body)
    except Exception:
        return False
    if isinstance(msg, list):  # JSON-RPC batch: gate if ANY sub-request is the paid tool (don't depend on the transport's batch policy)
        return any(is_paid_call(json.dumps(m).encode()) for m in msg)
    if not isinstance(msg, dict):
        return False
    return (msg.get("method") == "tools/call"
            and isinstance(msg.get("params"), dict)
            and msg["params"].get("name") == PAID_TOOL)


def _header(scope, name: bytes) -> str:
    for k, v in scope.get("headers", []):
        if k.lower() == name:
            return v.decode("latin-1")
    return ""


class X402Middleware:
    """ASGI middleware: gate the paid tools/call with x402, everything else free."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") != "POST" or scope.get("path") != MCP_PATH:
            return await self.app(scope, receive, send)
        chunks, total, more = [], 0, True
        while more:
            m = await receive()
            b = m.get("body", b"")
            total += len(b)
            if total > 6_000_000:
                await send({"type": "http.response.start", "status": 413,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"error":"request body too large"}'})
                return
            chunks.append(b)
            more = m.get("more_body", False)
        body = b"".join(chunks)

        def make_replay():
            sent = False
            async def replay():
                nonlocal sent
                if not sent:
                    sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return {"type": "http.disconnect"}
            return replay

        if not is_paid_call(body):
            return await self.app(scope, make_replay(), send)

        resource = f"{scope.get('scheme','https')}://{_header(scope, b'host') or 'localhost'}{MCP_PATH}"
        xp = _header(scope, b"x-payment")

        async def reject(reason):
            out = json.dumps(payment_requirements(resource) | {"error": reason}).encode()
            await send({"type": "http.response.start", "status": 402,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"payment-required", challenge_header(resource)),
                                    (b"www-authenticate", b'Payment realm="x402"'),
                                    (b"access-control-expose-headers", b"PAYMENT-REQUIRED"),
                                    (b"content-length", str(len(out)).encode())]})
            await send({"type": "http.response.body", "body": out})

        ok, reason = await asyncio.to_thread(verify, xp, resource)
        if not ok:
            return await reject(reason)

        buffered, status = [], 500
        async def capture(msg):
            nonlocal status
            if msg["type"] == "http.response.start":
                status = msg["status"]
            buffered.append(msg)
        await self.app(scope, make_replay(), capture)

        # Success sentinel is the QUOTED JSON key "report_digest" — a real scan report
        # always emits it; a guard/target-unreachable error never does, and it can't be
        # forged by echoing caller-controlled text (the digest is a hash the server computes).
        resp_body = b"".join(m.get("body", b"") for m in buffered if m["type"] == "http.response.body")
        rendered_ok = 200 <= status < 300 and b'"report_digest"' in resp_body
        if not rendered_ok:
            for m in buffered:
                await send(m)
            return

        settled, sresult = await asyncio.to_thread(settle, xp, resource)
        if not settled:
            return await reject(f"scan complete but settlement was not confirmed "
                                f"({sresult.get('error', 'settlement rejected')}); "
                                "check your wallet before retrying to avoid a double payment")
        xpr = base64.b64encode(json.dumps(sresult).encode())
        for m in buffered:
            if m["type"] == "http.response.start":
                m["headers"] = list(m.get("headers", [])) + [(b"x-payment-response", xpr)]
            await send(m)
