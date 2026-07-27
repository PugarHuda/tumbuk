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
    return {"x402Version": 2,
            # v2 models a resource as an object; v1 clients read the string copy inside accepts
            "resource": {"url": resource, "description": c["description"],
                         "mimeType": "application/json"},
            "accepts": [{
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
    return challenge(resource) | {"error": "payment required: send PAYMENT-SIG (or X-PAYMENT)"}


def _sdk_client():
    """OKX's official seller SDK client, or None when credentials aren't configured.

    The plain /verify + /settle calls below answer 403 without OKX-signed auth, which is
    why a genuinely paid call still failed — the facilitator requires the API key, secret
    and passphrase from your OKX account. Set OKX_API_KEY / OKX_SECRET_KEY /
    OKX_PASSPHRASE and this path takes over (`pip install okxweb3-app-x402`).
    """
    k = os.environ.get("OKX_API_KEY", "")
    s = os.environ.get("OKX_SECRET_KEY", "")
    p = os.environ.get("OKX_PASSPHRASE", "")
    if not (k and s and p):
        return None
    try:
        from x402.http.okx_facilitator_client import OKXFacilitatorClientSync, OKXFacilitatorConfig
        from x402.http.okx_auth import OKXAuthConfig
        return OKXFacilitatorClientSync(OKXFacilitatorConfig(
            auth=OKXAuthConfig(api_key=k, secret_key=s, passphrase=p)))
    except Exception:
        return None  # SDK absent -> fall back to the raw facilitator call


def _sdk_models(payload: dict, resource: str):
    """Coerce either payload dialect into the SDK's models.

    OKX's own client sends `accepted` (the requirement it paid against) and an object
    `resource`; a plain coinbase/x402 client sends neither, and the SDK model then refuses
    the payload outright. We already know what we quoted, so fill it in rather than reject
    a caller for using the other dialect.
    """
    from x402.schemas.payments import PaymentPayload, PaymentRequirements
    accepts = payment_requirements(resource)["accepts"][0]
    req = PaymentRequirements.model_validate(accepts)
    p = dict(payload)
    # `accepted` is what the payment gets verified AGAINST, so it is ours, not the caller's:
    # honouring a caller-supplied one would let them claim they agreed to pay 1 atomic unit.
    # It also repairs a partial `accepted`, which the SDK model rejects outright.
    p["accepted"] = accepts
    if isinstance(p.get("resource"), str):
        p.pop("resource")            # the model wants an object; the requirement carries it
    return PaymentPayload.model_validate(p), req


def verify(x_payment_b64: str, resource: str) -> tuple[bool, str]:
    if not x_payment_b64:
        return False, "missing payment: send PAYMENT-SIG (or X-PAYMENT)"
    try:
        payload = json.loads(base64.b64decode(x_payment_b64))
    except Exception:
        return False, "malformed X-PAYMENT header"
    if not isinstance(payload, dict):
        return False, "malformed X-PAYMENT header"
    # OKX's dialect nests the scheme inside `accepted`; coinbase/x402 puts it at the top
    # level. Checking only the top level rejected a real OKX payment before it ever reached
    # the facilitator.
    scheme = payload.get("scheme") or (payload.get("accepted") or {}).get("scheme")
    # v1 payloads arrive on X-PAYMENT, v2 on PAYMENT-SIGNATURE — accept both versions.
    if str(payload.get("x402Version")) not in ("1", "2") or scheme != "exact":
        return False, "unsupported payment scheme"
    client = _sdk_client()
    if client is not None:
        try:
            res = client.verify(*_sdk_models(payload, resource))
            return bool(getattr(res, "is_valid", False)), getattr(res, "invalid_reason", "") or ""
        except Exception as e:
            return False, f"facilitator error: {e}"

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
    try:
        payload = json.loads(base64.b64decode(x_payment_b64))
    except Exception:
        return False, {"error": "malformed payment header"}

    client = _sdk_client()
    if client is not None:
        try:
            res = client.settle(*_sdk_models(payload, resource))
            ok = bool(getattr(res, "success", False))
            out = res.model_dump(by_alias=True) if hasattr(res, "model_dump") else {"success": ok}
            return ok, out
        except Exception as e:
            return False, {"error": f"settlement failed: {e}"}

    fac = _cfg()["facilitator"]
    if not fac:
        return False, {"error": "no facilitator configured"}
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
        # Header names, straight from the SDK's own constants: a v2 payload arrives on
        # PAYMENT-SIGNATURE, a v1 payload on X-PAYMENT (PAYMENT-SIG appears in the docs
        # prose). Reading only X-PAYMENT meant an OKX-native caller could pay and still be
        # answered 402 forever.
        xp = (_header(scope, b"payment-signature") or _header(scope, b"payment-sig")
              or _header(scope, b"x-payment"))

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
                # PAYMENT-RESPONSE is what OKX's SDK reads; x-payment-response is the
                # coinbase/x402 spelling. Emit both so either client sees the proof.
                m["headers"] = list(m.get("headers", [])) + [(b"payment-response", xpr),
                                                            (b"x-payment-response", xpr)]
            await send(m)
