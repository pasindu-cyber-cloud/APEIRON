"""Indicator-of-Compromise extraction from strings and runtime trace data."""
from __future__ import annotations

import re
from collections.abc import Iterable

from .types import IOCRecord, TraceRecord

# --- Regular expressions ---------------------------------------------------
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\)]{4,2048}", re.IGNORECASE)
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|io|ru|cn|co|top|xyz|online|site|club|pw|gq|tk|ml|"
    r"ga|cf|su|onion|me|us|uk|de|fr|nl|br|in|ir|kp|live|shop|app|dev)\b",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_REGISTRY = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[\\A-Za-z0-9 _.\-{}]+",
)
_BITCOIN = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
_FILEPATH_WIN = re.compile(r"[A-Za-z]:\\(?:[^\s\"'<>|*?\r\n]{1,200})")

# Common false-positive domains/strings to drop.
_NOISE_DOMAINS = {
    "microsoft.com",
    "windows.com",
    "schemas.microsoft.com",
    "w3.org",
    "example.com",
}

# Mutex-creating APIs whose first string arg is the mutex name.
_MUTEX_APIS = {"CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW"}


def _add(store: dict[tuple[str, str], IOCRecord], ioc_type: str, value: str, context: str) -> None:
    value = value.strip().strip(".,;\"'")
    if not value:
        return
    key = (ioc_type, value.lower())
    if key in store:
        store[key].count += 1
    else:
        store[key] = IOCRecord(ioc_type=ioc_type, value=value, context=context)


def _scan_text(store: dict, text: str, context: str) -> None:
    for m in _URL.finditer(text):
        _add(store, "url", m.group(), context)
    for m in _IPV4.finditer(text):
        ip = m.group()
        if ip.startswith(("0.", "255.255.255")) or ip == "127.0.0.1":
            continue
        _add(store, "ip", ip, context)
    for m in _DOMAIN.finditer(text):
        dom = m.group().lower()
        if dom in _NOISE_DOMAINS:
            continue
        _add(store, "domain", dom, context)
    for m in _EMAIL.finditer(text):
        _add(store, "email", m.group(), context)
    for m in _REGISTRY.finditer(text):
        _add(store, "registry_key", m.group(), context)
    for m in _BITCOIN.finditer(text):
        _add(store, "bitcoin", m.group(), context)
    for m in _FILEPATH_WIN.finditer(text):
        _add(store, "filepath", m.group(), context)


def extract_from_strings(strings: Iterable[str]) -> list[IOCRecord]:
    store: dict[tuple[str, str], IOCRecord] = {}
    for s in strings:
        _scan_text(store, s, context="static_string")
    return list(store.values())


def extract_from_trace(events: Iterable[TraceRecord]) -> list[IOCRecord]:
    """Pull dynamic IOCs from runtime trace events (network, mutex, registry, files)."""
    store: dict[tuple[str, str], IOCRecord] = {}
    for evt in events:
        blob = " ".join(str(v) for v in evt.args.values()) + " " + evt.detail
        _scan_text(store, blob, context=f"runtime:{evt.category}:{evt.name}")

        if evt.name in _MUTEX_APIS:
            name = evt.args.get("lpName") or evt.args.get("name")
            if name:
                _add(store, "mutex", str(name), context=evt.name)
        if evt.category == "network":
            host = evt.args.get("host") or evt.args.get("addr")
            if host:
                _add(store, "ip", str(host), context=f"network:{evt.name}")
        if evt.category == "registry":
            key = evt.args.get("key") or evt.args.get("subkey")
            if key:
                _add(store, "registry_key", str(key), context=evt.name)
    return list(store.values())


def merge_iocs(*groups: Iterable[IOCRecord]) -> list[IOCRecord]:
    merged: dict[tuple[str, str], IOCRecord] = {}
    for group in groups:
        for ioc in group:
            key = (ioc.ioc_type, ioc.value.lower())
            if key in merged:
                merged[key].count += ioc.count
            else:
                merged[key] = ioc
    # Sort by type then descending count for stable presentation.
    return sorted(merged.values(), key=lambda i: (i.ioc_type, -i.count, i.value))
