"""API authentication helpers and startup security enforcement.

Authentication uses a single shared secret supplied by clients in the
``X-API-Key`` header and configured via ``APEIRON_API_KEY``.

Behavior by environment:

* production - the application refuses to start if the API key is missing,
  empty, or still set to a known placeholder, and if CORS is misconfigured.
* development - startup is allowed for convenience, but a clear warning is
  logged when authentication is effectively disabled.
"""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from .config import Settings, settings
from .logging_config import get_logger

logger = get_logger("apeiron.security")


class InsecureConfigurationError(RuntimeError):
    """Raised when the runtime configuration is unsafe for production."""


def enforce_startup_security(current: Settings | None = None) -> None:
    """Validate security-sensitive configuration at process startup.

    Raises :class:`InsecureConfigurationError` in production when fatal issues
    are present; otherwise logs warnings.
    """
    current = current or settings
    errors, warnings = current.security_report()

    for warning in warnings:
        logger.warning("security configuration warning: %s", warning)

    if current.is_development and current.api_key_is_placeholder:
        logger.warning(
            "API key authentication is DISABLED (no APEIRON_API_KEY set). "
            "This is acceptable for local development only."
        )

    if errors:
        joined = "; ".join(errors)
        raise InsecureConfigurationError(
            f"Refusing to start in production with insecure configuration: {joined}"
        )


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """FastAPI dependency enforcing the ``X-API-Key`` header when configured."""
    expected = settings.api_key
    if settings.api_key_is_placeholder:
        # Auth disabled (development only - production startup is blocked).
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
