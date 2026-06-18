"""Filesystem storage helpers for samples, dumps, reports and rules."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .config import settings


def compute_hashes(data: bytes) -> dict[str, str]:
    """Return md5/sha1/sha256 (and ssdeep when available) for raw bytes."""
    hashes = {
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - identification only
        "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324 - identification only
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    try:
        import ssdeep  # type: ignore

        hashes["ssdeep"] = ssdeep.hash(data)
    except Exception:
        hashes["ssdeep"] = ""
    return hashes


def store_sample(sample_id: str, original_name: str, data: bytes) -> Path:
    """Persist an uploaded sample under the upload dir keyed by id."""
    settings.ensure_dirs()
    safe_name = Path(original_name).name or "sample.bin"
    dest_dir = Path(settings.upload_dir) / sample_id
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / safe_name
    dest.write_bytes(data)
    return dest


def sample_dump_dir(sample_id: str) -> Path:
    path = Path(settings.dump_dir) / sample_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def sample_report_dir(sample_id: str) -> Path:
    path = Path(settings.report_dir) / sample_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def sample_rules_dir(sample_id: str) -> Path:
    path = Path(settings.rules_dir) / sample_id
    path.mkdir(parents=True, exist_ok=True)
    return path
