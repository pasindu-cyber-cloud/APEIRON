"""Pytest fixtures. Environment is configured *before* importing the app so
settings resolve to an isolated temp database and data directory.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# --- Configure an isolated environment up-front -----------------------------
_TMP = Path(tempfile.mkdtemp(prefix="apeiron-test-"))
os.environ.update(
    {
        "APEIRON_ENV": "test",
        "DATABASE_URL": f"sqlite:///{_TMP / 'test.sqlite3'}",
        "APEIRON_DATA_DIR": str(_TMP),
        "APEIRON_UPLOAD_DIR": str(_TMP / "uploads"),
        "APEIRON_DUMP_DIR": str(_TMP / "dumps"),
        "APEIRON_REPORT_DIR": str(_TMP / "reports"),
        "APEIRON_RULES_DIR": str(_TMP / "rules_generated"),
        "APEIRON_BUILTIN_RULES_DIR": str(Path(__file__).resolve().parents[1] / "rules"),
        "APEIRON_ENABLE_EMULATION": "false",
        "APEIRON_API_KEY": "",
    }
)


@pytest.fixture(scope="session")
def app_client():
    from fastapi.testclient import TestClient

    from app import queue as queue_mod
    from app.database import init_db
    from app.main import app

    # Avoid hitting a real broker: record enqueued sample ids instead.
    enqueued: list[str] = []
    queue_mod.enqueue_analysis = lambda sample_id: enqueued.append(sample_id) or "task-test"
    # The samples route imported the symbol directly; patch there too.
    import app.api.routes_samples as routes_samples

    routes_samples.enqueue_analysis = queue_mod.enqueue_analysis

    init_db()
    client = TestClient(app)
    client.enqueued = enqueued  # type: ignore[attr-defined]
    return client


@pytest.fixture
def minimal_pe() -> bytes:
    # "MZ" header is sufficient for format detection.
    return b"MZ" + b"\x00" * 0x80 + b"This program cannot be run in DOS mode" + b"\x00" * 64


@pytest.fixture
def minimal_elf() -> bytes:
    return b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 120
