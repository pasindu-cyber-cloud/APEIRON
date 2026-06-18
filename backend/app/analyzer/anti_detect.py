"""Anti-sandbox-evasion measures.

Malware frequently checks for analysis artifacts and alters or halts its
behavior when detected. To capture authentic behavior we mask common
virtualization / debugger artifacts inside the emulated guest and randomize
timing so the environment looks like an ordinary workstation.

These functions are best-effort and degrade gracefully when Qiling is not
available (e.g. static-only mode).
"""
from __future__ import annotations

import random

from ..logging_config import get_logger
from .types import Recorder

logger = get_logger("apeiron.anti_detect")

# A plausible, non-VM-looking machine profile presented to the guest.
REALISTIC_PROFILE = {
    "computer_name": "DESKTOP-7F3KQ2A",
    "user_name": "jsmith",
    "num_processors": 8,
    "total_ram_mb": 16384,
    "cpu_vendor": "GenuineIntel",
    "cpu_brand": "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz",
    "uptime_ms": 5_400_000,  # ~90 minutes — sandboxes often report near-zero
}

# Artifact strings that should never resolve/appear so VM checks fail "clean".
HIDDEN_ARTIFACTS = (
    "VBoxGuest",
    "VBoxMouse",
    "vmci",
    "vmhgfs",
    "vmtoolsd",
    "vboxservice",
    "vmware",
    "SbieDll.dll",
    "dbghelp.dll",
    "sandbox",
)


def random_jitter(base: float = 0.0) -> float:
    """Return a small randomized delay (seconds) to defeat timing-based checks."""
    return base + random.uniform(0.01, 0.18)


def humanized_tick(counter: list[int]) -> int:
    """Monotonic-ish tick generator with human-scale increments."""
    counter[0] += random.randint(9, 47)
    return REALISTIC_PROFILE["uptime_ms"] + counter[0]


def apply_qiling_hooks(ql, recorder: Recorder) -> None:  # noqa: ANN001 - ql is dynamic
    """Install hooks on a Qiling instance to neutralize common evasion checks."""
    try:
        tick_state = [0]

        def _hook_isdebuggerpresent(ql_):  # pragma: no cover - requires qiling
            recorder.record(
                "api", "IsDebuggerPresent", ret="0",
                detail="anti-evasion: forced not-debugged", severity="low",
            )
            ql_.os.set_function_result(0) if hasattr(ql_.os, "set_function_result") else None
            return 0

        def _hook_gettickcount(ql_):  # pragma: no cover
            value = humanized_tick(tick_state)
            recorder.record("api", "GetTickCount", ret=str(value),
                            detail="anti-evasion: humanized tick")
            return value

        # Qiling exposes set_api to override Windows API behavior.
        if hasattr(ql, "os") and hasattr(ql.os, "set_api"):
            for api in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent"):
                try:
                    ql.os.set_api(api, _hook_isdebuggerpresent)
                except Exception:
                    pass
            for api in ("GetTickCount", "GetTickCount64"):
                try:
                    ql.os.set_api(api, _hook_gettickcount)
                except Exception:
                    pass
        logger.info("anti-evasion hooks applied")
    except Exception as exc:  # pragma: no cover
        logger.warning("apply_qiling_hooks failed: %s", exc)


def sanitize_artifact(name: str) -> bool:
    """Return True if the requested artifact should be hidden from the guest."""
    low = name.lower()
    return any(a.lower() in low for a in HIDDEN_ARTIFACTS)
