"""TrustedProxyMiddleware — resolve the real client IP/scheme/host from
X-Forwarded-* headers, but ONLY when the direct TCP peer is trusted.

== Trust model ==

When Sairo runs behind a reverse proxy (HAProxy, nginx, an ingress, AWS ALB,
…), the direct TCP peer the ASGI server sees is the *proxy*, not the end user.
All user-visible information about the real origin — client IP, scheme (http vs
https), and original host — is delivered via the ``X-Forwarded-{For,Proto,Host}``
/ ``X-Real-IP`` headers, which the proxy adds.

Those headers are **untrusted by default**: any client can set them. Trusting
them blindly means a remote attacker can spoof their source IP (defeating audit
log/rate-limiter/geo logic) or impersonate an HTTPS request from a trusted host.

The operator declares which source IPs are allowed to set these headers via the
``TRUSTED_PROXIES`` environment variable (comma-separated bare IPs or CIDRs).
``parse_trusted_proxies()`` turns that string into a set of
``ipaddress.ip_network`` objects.

== Fail-closed default ==

If ``TRUSTED_PROXIES`` is empty/unset (the existing behavior in every test and
the default deployment), ``self.trusted`` is empty and the middleware is a
complete no-op: the request scope is passed through UNCHANGED. No header is
inspected, nothing is rewritten. Downstream code (audit log, rate limiter,
``request.client``) keeps behaving exactly as before.

Similarly, if the direct peer is not in any trusted network, every forwarded
header is ignored — we never widen trust to an unknown source.

== Header resolution ==

When the peer *is* trusted:

* ``X-Forwarded-For`` is walked right-to-left; entries inside a trusted network
  (or equal to the peer) are skipped. The first non-trusted entry is the real
  client. If every entry is trusted (multi-hop through our own proxies), we
  fall back to the leftmost entry. Malformed entries are skipped, never crash.
* If ``X-Forwarded-For`` is absent, ``X-Real-IP`` is used (if parseable).
* Otherwise the peer is kept as-is.

``X-Forwarded-Proto`` rewrites ``scope["scheme"]`` (so ``request.url.scheme``
and SSO redirect-URI construction are correct behind a TLS-terminating proxy).
``X-Forwarded-Host`` rewrites the ``host``/``:authority`` header (so
``request.base_url`` is correct).
"""

import ipaddress


def parse_trusted_proxies(value):
    """Parse the ``TRUSTED_PROXIES`` env string into a set of IP networks.

    Accepts a comma-separated list of bare IPs (``10.0.0.5``) or CIDRs
    (``10.0.0.0/8``). Empty / whitespace-only / ``None`` → empty set
    (fail-closed default: no peer is trusted).

    Raises ``ValueError`` on the first invalid token — the app must refuse to
    boot rather than silently widening or narrowing the trust set.
    """
    if not value or not value.strip():
        return set()
    networks = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            networks.add(ipaddress.ip_network(token, strict=False))
        except ValueError as e:
            # Fail-fast at startup — invalid config must not silently fall back.
            raise ValueError(f"Invalid TRUSTED_PROXIES entry {token!r}: {e}") from e
    return networks


def _find_header(headers, name):
    """Return the raw bytes value of an ASGI header by lowercase name, or None.

    ASGI stores headers as a list of ``(name_lowercased_bytes, value_bytes)``.
    """
    target = name.encode("latin-1") if isinstance(name, str) else name
    for key, value in headers:
        if key == target:
            return value
    return None


def _resolve_xff(xff_value, trusted, peer_ip):
    """Resolve the real client IP from an ``X-Forwarded-For`` value.

    Walks entries right-to-left (rightmost = closest proxy, leftmost = origin),
    skipping any entry whose IP is inside a trusted network or equals the
    direct TCP peer. Returns the first non-trusted entry as a ``str``.

    If every valid entry is trusted (or the only untrusted entries are the peer
    itself), falls back to the leftmost valid entry. If no entry parses to a
    valid IP, returns ``None`` (caller keeps the peer).
    """
    valid = []  # left-to-right list of parsed IP addresses
    for entry in xff_value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            ip = ipaddress.ip_address(entry)
        except ValueError:
            continue  # malformed entry — skip, never crash
        valid.append(ip)

    if not valid:
        return None

    # Right-to-left: first non-trusted, non-peer entry is the real client.
    for ip in reversed(valid):
        if ip == peer_ip:
            continue
        if any(ip in net for net in trusted):
            continue
        return str(ip)

    # All entries trusted / peer → fall back to the leftmost valid entry.
    return str(valid[0])


class TrustedProxyMiddleware:
    """Pure-ASGI middleware that rewrites the request scope from forwarded
    headers when the direct TCP peer is in ``trusted_proxies``.

    Construct with ``TrustedProxyMiddleware(app, trusted_proxies=<set of
    ip_network>)``. ``trusted_proxies`` may be empty (no-op) and is copied
    defensively.
    """

    def __init__(self, app, trusted_proxies):
        self.app = app
        self.trusted = set(trusted_proxies)

    async def __call__(self, scope, receive, send):
        # Only HTTP requests can carry these headers; everything else (lifespan,
        # websocket) and the fail-closed default (empty trust set) passes through.
        if scope.get("type") != "http" or not self.trusted:
            return await self.app(scope, receive, send)

        client = scope.get("client") or (None, None)
        peer = client[0]
        if peer is None:
            return await self.app(scope, receive, send)

        try:
            peer_ip = ipaddress.ip_address(peer)
        except ValueError:
            # Malformed peer — can't determine trust, leave scope untouched.
            return await self.app(scope, receive, send)

        if not any(peer_ip in net for net in self.trusted):
            # Untrusted peer → NEVER trust forwarded headers it sent.
            return await self.app(scope, receive, send)

        headers = scope.get("headers") or []
        xff = _find_header(headers, "x-forwarded-for")
        x_real_ip = _find_header(headers, "x-real-ip")
        xfp = _find_header(headers, "x-forwarded-proto")
        xfh = _find_header(headers, "x-forwarded-host")

        # ── Resolve real client IP ───────────────────────────────────────
        real_ip = peer
        if xff is not None:
            resolved = _resolve_xff(xff.decode("latin-1"), self.trusted, peer_ip)
            if resolved is not None:
                real_ip = resolved
        elif x_real_ip is not None:
            candidate = x_real_ip.decode("latin-1").strip()
            try:
                ipaddress.ip_address(candidate)
                real_ip = candidate
            except ValueError:
                pass  # invalid X-Real-IP → keep peer

        # ── Build rewritten scope (copy, never mutate the original) ───────
        new_scope = dict(scope)
        new_scope["client"] = (real_ip, client[1])  # preserve original port

        if xfp is not None:
            scheme = xfp.decode("latin-1").strip()
            if scheme:
                new_scope["scheme"] = scheme

        if xfh is not None:
            # Replace host / :authority so request.base_url is correct. HTTP/2
            # pseudo-header (:authority) is preserved if the original request
            # carried one — otherwise we only set the plain host header.
            had_authority = any(k == b":authority" for (k, _) in headers)
            new_headers = [
                (k, v) for (k, v) in headers
                if k != b"host" and k != b":authority"
            ]
            new_headers.append((b"host", xfh))
            if had_authority:
                new_headers.append((b":authority", xfh))
            new_scope["headers"] = new_headers

        return await self.app(new_scope, receive, send)
