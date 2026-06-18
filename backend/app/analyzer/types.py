"""Lightweight dataclasses used internally by the analysis engine.

These are intentionally decoupled from the ORM models so the engine can run
(and be unit-tested) without a database.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TraceRecord:
    seq: int
    rel_ts: float
    category: str  # api | syscall | file | registry | network | process | memory
    name: str
    args: dict[str, Any] = field(default_factory=dict)
    ret: str = ""
    detail: str = ""
    severity: str = "info"  # info | low | medium | high
    suspicious: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "rel_ts": round(self.rel_ts, 6),
            "category": self.category,
            "name": self.name,
            "args": self.args,
            "ret": self.ret,
            "detail": self.detail,
            "severity": self.severity,
            "suspicious": self.suspicious,
        }


@dataclass
class IOCRecord:
    ioc_type: str
    value: str
    context: str = ""
    count: int = 1


@dataclass
class DumpRecord:
    reason: str
    address: str
    size: int
    path: str
    sha256: str


@dataclass
class Detection:
    name: str
    severity: str  # low | medium | high
    description: str
    mitre: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


class Recorder:
    """Collects trace events during analysis and forwards them live.

    A callback (``on_event``) is invoked for every recorded event so the engine
    can publish to the websocket bus in real time.
    """

    def __init__(self, on_event: Callable[[TraceRecord], None] | None = None) -> None:
        self._seq = 0
        self._t0 = time.monotonic()
        self.events: list[TraceRecord] = []
        self._on_event = on_event

    def record(
        self,
        category: str,
        name: str,
        args: dict[str, Any] | None = None,
        ret: str = "",
        detail: str = "",
        severity: str = "info",
        suspicious: bool = False,
    ) -> TraceRecord:
        self._seq += 1
        evt = TraceRecord(
            seq=self._seq,
            rel_ts=time.monotonic() - self._t0,
            category=category,
            name=name,
            args=args or {},
            ret=ret,
            detail=detail,
            severity=severity,
            suspicious=suspicious,
        )
        self.events.append(evt)
        if self._on_event is not None:
            try:
                self._on_event(evt)
            except Exception:
                pass
        return evt
