from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

import httpx
import structlog

from core.config import settings

log = structlog.get_logger(__name__)

# ── Redis key for IP info cache ───────────────────────────────────────────────
_IP_INFO_KEY_PREFIX = "ipinfo:"
_IP_INFO_TTL        = 86400   # 24 hours


@dataclass
class IPInfo:
    """
    Structured result from the IP geolocation lookup.

    All fields are Optional — any field may be absent if the lookup
    fails or the IP is a private/reserved address.

    Fields stored in the DB:
        ip_address  → users.registered_ip
        country     → users.registered_country
        city        → users.registered_city

    Fields used for search ranking / UX (not stored long-term):
        region      → passed to search ranking formula
        timezone    → used to display relative timestamps (future)
        isp         → logged for abuse detection (not stored in DB)
    """
    ip_address:  str
    country:     Optional[str] = None   # ISO 3166-1 alpha-2: "NG", "US", "GB"
    country_name: Optional[str] = None  # "Nigeria", "United States"
    region:      Optional[str] = None   # "Lagos", "California"
    city:        Optional[str] = None   # "Lagos", "San Francisco"
    timezone:    Optional[str] = None   # "Africa/Lagos", "America/Los_Angeles"
    isp:         Optional[str] = None   # "MTN Nigeria", "Comcast"
    latitude:    Optional[float] = None
    longitude:   Optional[float] = None
    is_proxy:    bool = False
    lookup_failed: bool = False         # True if the lookup could not complete


def _ip_info_cache_key(ip_address: str) -> str:
    """Build the Redis cache key for an IP info lookup result."""
    return f"{_IP_INFO_KEY_PREFIX}{ip_address}"


async def get_ip_info(ip_address: str) -> IPInfo:
    """
    Look up geolocation and identity information for an IP address.

    Strategy:
        1. Check Redis cache — return cached result if present.
        2. Query ip-api.com JSON API with a 3-second timeout.
        3. Parse and cache the result in Redis for 24 hours.
        4. On any error: return an IPInfo with lookup_failed=True.
           Registration continues — this is non-critical.

    Private and loopback IPs (127.x, 192.168.x, 10.x, ::1) are
    returned immediately with lookup_failed=True — there is no useful
    geolocation data for these addresses.

    Args:
        ip_address : The client's real IP string (from extract_client_ip).

    Returns:
        IPInfo dataclass. Never raises.
    """
    # ── Skip lookup for private / special IPs ─────────────────────────────────
    if _is_private_ip(ip_address):
        log.debug("ip_info_skipped_private", ip=ip_address)
        return IPInfo(ip_address=ip_address, lookup_failed=True)

    # ── Check Redis cache ─────────────────────────────────────────────────────
    cached = await _get_cached_ip_info(ip_address)
    if cached is not None:
        log.debug("ip_info_cache_hit", ip=ip_address)
        return cached

    # ── Query ip-api.com ──────────────────────────────────────────────────────
    return await _fetch_ip_info(ip_address)


async def _fetch_ip_info(ip_address: str) -> IPInfo:
    """
    Perform the actual HTTP request to ip-api.com.

    Request URL:
        http://ip-api.com/json/<ip>?fields=status,message,country,
        countryCode,region,regionName,city,zip,lat,lon,timezone,isp,proxy

    Response (success):
        {
          "status": "success",
          "country": "Nigeria",
          "countryCode": "NG",
          "region": "LA",
          "regionName": "Lagos",
          "city": "Lagos",
          "lat": 6.4531,
          "lon": 3.3958,
          "timezone": "Africa/Lagos",
          "isp": "MTN Nigeria",
          "proxy": false
        }

    Response (failure):
        {"status": "fail", "message": "private range"}

    On any network error, timeout, or unexpected response:
        Returns IPInfo(lookup_failed=True) and logs a warning.
        Registration is never blocked by a lookup failure.
    """
    fields = (
        "status,message,country,countryCode,regionName,"
        "city,lat,lon,timezone,isp,proxy"
    )
    url = f"{settings.ip_api_url}/{ip_address}?fields={fields}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=settings.ip_api_timeout,
                read=settings.ip_api_timeout,
                write=settings.ip_api_timeout,
                pool=settings.ip_api_timeout,
            ),
            follow_redirects=False,
        ) as client:
            response = await client.get(url)

        if response.status_code != 200:
            log.warning(
                "ip_info_http_error",
                ip=ip_address,
                status_code=response.status_code,
            )
            return IPInfo(ip_address=ip_address, lookup_failed=True)

        data: dict = response.json()

        if data.get("status") != "success":
            log.debug(
                "ip_info_lookup_failed",
                ip=ip_address,
                reason=data.get("message", "unknown"),
            )
            return IPInfo(ip_address=ip_address, lookup_failed=True)

        info = IPInfo(
            ip_address=ip_address,
            country=data.get("countryCode"),        # "NG"
            country_name=data.get("country"),       # "Nigeria"
            region=data.get("regionName"),          # "Lagos"
            city=data.get("city"),                  # "Lagos"
            timezone=data.get("timezone"),          # "Africa/Lagos"
            isp=data.get("isp"),                    # "MTN Nigeria"
            latitude=data.get("lat"),
            longitude=data.get("lon"),
            is_proxy=bool(data.get("proxy", False)),
            lookup_failed=False,
        )

        log.info(
            "ip_info_fetched",
            ip=ip_address,
            country=info.country,
            city=info.city,
            is_proxy=info.is_proxy,
        )

        # Cache result
        await _cache_ip_info(ip_address, info)

        return info

    except httpx.TimeoutException:
        log.warning("ip_info_timeout", ip=ip_address,
                    timeout=settings.ip_api_timeout)
        return IPInfo(ip_address=ip_address, lookup_failed=True)

    except httpx.RequestError as exc:
        log.warning("ip_info_request_error", ip=ip_address, error=str(exc))
        return IPInfo(ip_address=ip_address, lookup_failed=True)

    except Exception as exc:
        log.error("ip_info_unexpected_error", ip=ip_address, error=str(exc))
        return IPInfo(ip_address=ip_address, lookup_failed=True)


async def _get_cached_ip_info(ip_address: str) -> Optional[IPInfo]:
    """
    Attempt to retrieve a cached IPInfo from Redis.
    Returns None on cache miss or any error.
    """
    try:
        from cache.client import get_redis_client
        redis  = get_redis_client()
        cached = await redis.get(_ip_info_cache_key(ip_address))
        await redis.aclose()

        if cached is None:
            return None

        data = json.loads(cached)
        return IPInfo(**data)

    except Exception as exc:
        log.debug("ip_info_cache_miss", ip=ip_address, error=str(exc))
        return None


async def _cache_ip_info(ip_address: str, info: IPInfo) -> None:
    """
    Store an IPInfo result in Redis with a 24-hour TTL.
    Non-critical — silently ignores any Redis errors.
    """
    try:
        from cache.client import get_redis_client
        import dataclasses

        redis = get_redis_client()
        await redis.set(
            _ip_info_cache_key(ip_address),
            json.dumps(dataclasses.asdict(info)),
            ex=_IP_INFO_TTL,
        )
        await redis.aclose()

    except Exception as exc:
        log.debug("ip_info_cache_write_failed", ip=ip_address, error=str(exc))


def _is_private_ip(ip_address: str) -> bool:
    """
    Return True if the IP is a private, loopback, or reserved address
    for which geolocation is not meaningful.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip_address)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or ip_address in {"unknown", ""}
        )
    except ValueError:
        return True
