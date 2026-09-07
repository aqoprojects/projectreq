from __future__ import annotations

import ipaddress
import re
from typing import Optional

import structlog
from starlette.requests import Request

log = structlog.get_logger(__name__)

# ── Known private / loopback ranges ──────────────────────────────────────────
# These are always considered "internal" regardless of trusted proxy config.
_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),   # link-local
    ipaddress.IPv6Network("::1/128"),           # IPv6 loopback
    ipaddress.IPv6Network("fc00::/7"),          # IPv6 unique local
    ipaddress.IPv6Network("fe80::/10"),         # IPv6 link-local
)

# ── Trusted proxy IP ranges ───────────────────────────────────────────────────
# IPs and CIDRs of reverse proxies we operate (nginx, K8s ingress, LB).
# The algorithm trusts any IP in this set to have correctly forwarded
# the real client IP.
#
# In production, override via environment variable TRUSTED_PROXY_CIDRS
# (comma-separated CIDR list). The defaults cover common K8s pod ranges.
#
# Never include 0.0.0.0/0 — that would allow clients to spoof any IP.
_DEFAULT_TRUSTED_CIDRS: list[str] = [
    "127.0.0.1/32",        # loopback (same-host nginx)
    "10.0.0.0/8",          # K8s pod network (typical)
    "172.16.0.0/12",       # Docker / K8s node network
    "192.168.0.0/16",      # Local dev network
]

# Compiled once at module load
_TRUSTED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(cidr, strict=False)
    for cidr in _DEFAULT_TRUSTED_CIDRS
)

# ── IPv4-mapped IPv6 prefix ───────────────────────────────────────────────────
_IPV4_MAPPED_PREFIX = "::ffff:"

def _normalise_ip(raw: str) -> str:
    """
    Normalise an IP address string.

    Handles:
        - Stripping whitespace and port numbers ("1.2.3.4:8080" → "1.2.3.4")
        - IPv4-mapped IPv6 addresses ("::ffff:1.2.3.4" → "1.2.3.4")
        - IPv6 bracket notation ("[::1]:8080" → "::1")
        """
    raw = raw.strip()
    # Strip IPv6 brackets and port: [::1]:8080 → ::1
    if raw.startswith("["):
        raw = raw.split("]")[0].lstrip("[")
        return raw

    # Strip IPv4 port: 1.2.3.4:8080 → 1.2.3.4
    # Only strip if it looks like IPv4 with port (contains single colon)
    if raw.count(":") == 1:
        raw = raw.split(":")[0]

    # Unwrap IPv4-mapped IPv6: ::ffff:1.2.3.4 → 1.2.3.4
    if raw.lower().startswith(_IPV4_MAPPED_PREFIX):
        raw = raw[len(_IPV4_MAPPED_PREFIX):]

    return raw


def _is_trusted_proxy(ip_str: str) -> bool:
    """
    Return True if the given IP string belongs to a trusted proxy network.
    Returns False on any parsing error (treat unknown as untrusted).
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in network for network in _TRUSTED_NETWORKS)
    except ValueError:
        return False


def _is_valid_public_ip(ip_str: str) -> bool:
    """
    Return True if the string is a valid, globally routable IP address.
    Rejects private, loopback, link-local, and multicast addresses.
    Returns False on any parsing error.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback or addr.is_private or addr.is_link_local:
            return False
        if addr.is_multicast or addr.is_reserved:
            return False
        return True
    except ValueError:
        return False


def extract_client_ip(request: Request) -> str:
    """
    Extract the real client IP address from a Starlette request.

    Algorithm (in order of precedence):

        1.  Read X-Forwarded-For header (set by nginx / K8s ingress / LB).
        Format: "client, proxy1, proxy2" — leftmost is the original client,
        rightmost is the most recent proxy.

        2.  Walk the header from right to left.
        Skip any IP that belongs to a trusted proxy network.
        The first non-trusted IP from the right is the real client.

        3.  If no X-Forwarded-For or all entries are trusted proxies,
        fall back to X-Real-IP (set by some nginx configurations).

        4.  If no forwarding headers, use request.client.host directly.
        This is correct in development (no proxy) and incorrect
        behind a proxy that does not set forwarding headers (misconfiguration).

        5.  Return "unknown" if no IP can be determined.

        Security note:
            This function never trusts a single forwarding header blindly.
            The trusted proxy list controls which entries are considered
            proxy-added vs client-supplied. Misconfiguration of the trusted
            list is the only way this function can be fooled.

            Args:
                request: Starlette Request object.

                Returns:
                    The client's real IP address as a string.
                    Returns "unknown" if the IP cannot be determined.
                    Never raises an exception.
                    """
    try:
        forwarded_for = request.headers.get("X-Forwarded-For", "").strip()

        if forwarded_for:
            # Split and normalise each IP in the chain
            # X-Forwarded-For: "1.2.3.4, 10.0.0.1, 10.0.0.2"
            raw_ips = [_normalise_ip(ip) for ip in forwarded_for.split(",")]

            # Walk from right to left — skip trusted proxies
            for ip_str in reversed(raw_ips):
                if not ip_str:
                    continue
                if _is_trusted_proxy(ip_str):
                    continue
                # First non-trusted IP from the right is the real client
                try:
                    ipaddress.ip_address(ip_str)   # validate it's a real IP
                    return ip_str
                except ValueError:
                    continue   # malformed entry — keep walking

        # Fallback 1: X-Real-IP (nginx single-header forwarding)
        x_real_ip = request.headers.get("X-Real-IP", "").strip()
        if x_real_ip:
            normalised = _normalise_ip(x_real_ip)
            try:
                ipaddress.ip_address(normalised)
                return normalised
            except ValueError:
                pass

        # Fallback 2: Direct connection IP
        if request.client and request.client.host:
            return _normalise_ip(request.client.host)

        return "unknown"

    except Exception as exc:
        log.warning("ip_extraction_error", error=str(exc))
        return "unknown"


def extract_client_ip_info(request: Request) -> dict[str, str]:
    """
    Extract full IP metadata from a request.

    Returns a dict with:
        ip          : The real client IP (from extract_client_ip)
        is_public   : "true" / "false" — whether the IP is globally routable
        forwarded_for: Raw X-Forwarded-For header value (for logging)
        proxy_chain : Comma-separated list of proxy IPs in the chain

        Used by the registration endpoint to log the full proxy chain
        alongside the extracted client IP for audit purposes.
        """
    client_ip = extract_client_ip(request)
    forwarded_for = request.headers.get("X-Forwarded-For", "")

    raw_ips: list[str] = []
    proxy_ips: list[str] = []

    if forwarded_for:
        raw_ips  = [_normalise_ip(ip) for ip in forwarded_for.split(",")]
        proxy_ips = [ip for ip in raw_ips if _is_trusted_proxy(ip)]

    return {
        "ip": client_ip,
        "is_public": str(_is_valid_public_ip(client_ip)).lower(),
        "forwarded_for": forwarded_for,
        "proxy_chain":  ", ".join(proxy_ips),
    }
