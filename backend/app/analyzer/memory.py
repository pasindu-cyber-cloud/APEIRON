"""Memory dump triggering and persistence.

Dumps are written to the per-sample dump directory. When a Qiling instance is
available the actual emulated memory region is read; otherwise a best-effort
slice of the on-disk sample is captured so the pipeline always produces an
inspectable artifact for suspicious events.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..logging_config import get_logger
from ..storage import sample_dump_dir
from .types import DumpRecord

logger = get_logger("apeiron.memory")


def _write_dump(sample_id: str, label: str, data: bytes) -> Path:
    out_dir = sample_dump_dir(sample_id)
    digest = hashlib.sha256(data).hexdigest()[:16]
    safe_label = "".join(c if c.isalnum() else "_" for c in label)[:40]
    path = out_dir / f"{safe_label}_{digest}.bin"
    path.write_bytes(data)
    return path


def dump_region(
    sample_id: str,
    reason: str,
    address: int,
    size: int,
    ql=None,  # noqa: ANN001 - dynamic Qiling instance
    fallback_data: bytes | None = None,
) -> DumpRecord | None:
    """Capture a memory region triggered by a suspicious event."""
    size = max(0, min(size, 4 * 1024 * 1024))  # cap dump size at 4 MiB
    data: bytes | None = None
    try:
        if ql is not None and size > 0:
            data = bytes(ql.mem.read(address, size))
    except Exception as exc:  # pragma: no cover - requires qiling
        logger.warning("emulated memory read failed @0x%x: %s", address, exc)

    if data is None:
        if not fallback_data:
            return None
        start = address % max(1, len(fallback_data)) if address else 0
        data = fallback_data[start : start + (size or 65536)]

    if not data:
        return None

    path = _write_dump(sample_id, reason, data)
    record = DumpRecord(
        reason=reason,
        address=hex(address),
        size=len(data),
        path=str(path),
        sha256=hashlib.sha256(data).hexdigest(),
    )
    logger.info("memory dump captured: %s (%d bytes) reason=%s", path.name, len(data), reason)
    return record
