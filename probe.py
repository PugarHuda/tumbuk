"""SSRF-guarded HTTP adapter: send one probe input to a target agent endpoint and
extract its reply text. A red-team tool that itself becomes an SSRF pivot is a bug,
so every target is validated before any request is made.
"""
import ipaddress, json, socket, urllib.error, urllib.parse, urllib.request

MAX_BYTES = 256_000       # cap reads so a hostile target can't exhaust memory
TIMEOUT = 15               # seconds per probe request
_REPLY_KEYS = ("output", "response", "text", "reply", "message", "result")


class TargetRejected(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Disable automatic redirect-following: a red-team probe must not be lured
    off its declared target by a 3xx to an internal host."""
    def redirect_request(self, *a, **k):
        return None


def assert_public_url(url: str) -> None:
    """Reject anything that isn't a publicly-routable http(s) endpoint: non-http(s)
    schemes, and hosts that resolve to loopback/private/link-local/reserved/multicast
    addresses (RFC-1918, 127.0.0.1, 169.254.169.254 cloud metadata, etc.).

    ponytail: this is a resolve-then-reject pre-flight, not a fully IP-pinned connect —
    a DNS-rebinding attacker could in principle swap the A record between this check and
    the actual request. Closing that needs a custom socket that connects to the exact
    validated IP while keeping the original Host/SNI (see the JS reference's undici
    dispatcher). Deferred: the pre-flight check covers the common "point it at localhost/
    169.254.169.254" case, which is the realistic misuse here.
    """
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        raise TargetRejected(f"unsupported scheme: {p.scheme!r}")
    host = p.hostname or ""
    if not host:
        raise TargetRejected("no host in target_url")
    if host in ("localhost",) or host.endswith(".local") or host.endswith(".internal"):
        raise TargetRejected(f"non-public host: {host}")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise TargetRejected(f"could not resolve host: {e}")
    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise TargetRejected(f"target resolves to a non-public address: {ip}")


def _extract_text(body: bytes) -> str:
    try:
        obj = json.loads(body)
    except Exception:
        return body.decode("utf-8", "replace")
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        for k in _REPLY_KEYS:
            if isinstance(obj.get(k), str):
                return obj[k]
        return json.dumps(obj)  # no known reply field -> stringify so canary matching still works
    return json.dumps(obj)


def send(target_url: str, input_text: str) -> str:
    """POST {"input": input_text} to target_url and return the extracted reply text.
    Raises TargetRejected before any network call if the URL isn't safely public."""
    assert_public_url(target_url)
    body = json.dumps({"input": input_text}).encode()
    req = urllib.request.Request(target_url, data=body, method="POST",
                                  headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            raw = r.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        # An error status is NOT the agent's answer: a 503 page, a WAF block or a 404 carries
        # no canary, so treating its body as a reply scored a DOWN target "resisted" -> a false
        # "A, safe" grade on an endpoint that never ran. Unmeasured is the honest verdict.
        raise TargetRejected(f"target returned HTTP {e.code}; no agent reply to evaluate")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise TargetRejected(f"target unreachable: {e}")
    if len(raw) > MAX_BYTES:
        raw = raw[:MAX_BYTES]
    return _extract_text(raw)
