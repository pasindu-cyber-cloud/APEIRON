"""API authentication helpers.

If ``APEIRON_API_KEY`` is set, all protected routes require a matching
``X-API-Key`` header. If unset, the API is open (suitable for local/dev only).
"""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from .config import settings


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected = settings.api_key
    if not expected:
        return  # auth disabled
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
