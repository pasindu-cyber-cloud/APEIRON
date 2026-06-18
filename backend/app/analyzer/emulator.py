"""User-mode emulation + API/syscall tracing via the Qiling Framework.

Qiling emulates the CPU and a userland OS layer, so the sample never executes
natively on the host. We capture every API/syscall Qiling resolves by attaching
a logging handler to its logger (broad coverage) and additionally intercept a
curated set of high-signal APIs to trigger memory dumps on suspicious events.

If Qiling or a suitable rootfs is unavailable, ``run_emulation`` records an
informational event and returns ``False`` so the engine continues with static
results only.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..config import settings
from ..logging_config import get_logger
from . import anti_detect, memory
from .types import DumpRecord, Recorder

logger = get_logger("apeiron.emulator")

# Map keywords found in API names to a trace category.
_CATEGORY_HINTS = (
    (("RegOpenKey", "RegSetValue", "RegCreateKey", "RegQueryValue", "RegDeleteKey"), "registry"),
    (
        (
            "CreateFile",
            "WriteFile",
            "ReadFile",
            "DeleteFile",
            "MoveFile",
            "open",
            "read",
            "write",
            "unlink",
            "fopen",
        ),
        "file",
    ),
    (
        (
            "socket",
            "connect",
            "send",
            "recv",
            "WSAStartup",
            "InternetConnect",
            "HttpSendRequest",
            "WinHttp",
            "getaddrinfo",
            "gethostbyname",
            "bind",
            "listen",
        ),
        "network",
    ),
    (
        (
            "CreateProcess",
            "ShellExecute",
            "WinExec",
            "fork",
            "execve",
            "CreateRemoteThread",
            "VirtualAllocEx",
            "WriteProcessMemory",
        ),
        "process",
    ),
    (("VirtualAlloc", "VirtualProtect", "mmap", "mprotect", "HeapAlloc"), "memory"),
)

# APIs that, when called, warrant an immediate memory dump.
_DUMP_TRIGGERS = {
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtWriteVirtualMemory",
    "VirtualAllocEx",
    "QueueUserAPC",
    "SetThreadContext",
    "AdjustTokenPrivileges",
}

_API_LINE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)(?:\s*=\s*(.+))?$")
_MAX_EVENTS = 20000


def _classify(name: str) -> str:
    for keywords, category in _CATEGORY_HINTS:
        if any(k.lower() in name.lower() for k in keywords):
            return category
    return "api"


class _QilingLogCapture(logging.Handler):
    """Parses Qiling's API/syscall log lines into structured trace events."""

    def __init__(self, recorder: Recorder, on_trigger) -> None:
        super().__init__(level=logging.DEBUG)
        self.recorder = recorder
        self.on_trigger = on_trigger
        self.count = 0

    def emit(self, record: logging.LogRecord) -> None:
        if self.count >= _MAX_EVENTS:
            return
        try:
            msg = record.getMessage()
            match = _API_LINE_RE.search(msg)
            if not match:
                return
            name, raw_args, ret = match.group(1), match.group(2), match.group(3) or ""
            # Skip internal/noise symbols.
            if name in ("hook_code", "hook_block") or name.startswith("_"):
                return
            args = {}
            for i, part in enumerate(a.strip() for a in raw_args.split(",") if a.strip()):
                if "=" in part:
                    k, v = part.split("=", 1)
                    args[k.strip()] = v.strip()
                else:
                    args[f"arg{i}"] = part
            category = _classify(name)
            self.recorder.record(category, name, args=args, ret=ret.strip())
            self.count += 1
            if name in _DUMP_TRIGGERS:
                self.on_trigger(name, args)
        except Exception:
            pass


def _resolve_rootfs(file_format: str, arch: str, bits: int) -> Path | None:
    """Locate an appropriate Qiling rootfs directory for the target."""
    root = Path(settings.qiling_rootfs)
    if not root.exists():
        return None
    if file_format == "PE":
        candidate = "x8664_windows" if bits == 64 else "x86_windows"
    else:  # ELF
        mapping = {
            ("x86_64", 64): "x8664_linux",
            ("x86", 32): "x86_linux",
            ("arm64", 64): "arm64_linux",
            ("arm", 32): "arm_linux",
        }
        candidate = mapping.get((arch, bits), "x8664_linux")
    path = root / candidate
    return path if path.exists() else None


def run_emulation(
    sample_path: str,
    static_info: dict,
    recorder: Recorder,
    sample_id: str,
) -> tuple[bool, list[DumpRecord]]:
    """Emulate the sample and populate ``recorder`` with trace events.

    Returns (emulation_ran, dumps).
    """
    dumps: list[DumpRecord] = []
    fallback_data = Path(sample_path).read_bytes()

    if not settings.enable_emulation:
        recorder.record("api", "emulation.skipped", detail="emulation disabled by config")
        return False, dumps

    try:
        from qiling import Qiling  # type: ignore
        from qiling.const import QL_VERBOSE  # type: ignore
    except Exception as exc:
        recorder.record(
            "api",
            "emulation.unavailable",
            detail=f"Qiling not importable: {exc}",
            severity="info",
        )
        logger.warning("Qiling unavailable: %s", exc)
        return False, dumps

    rootfs = _resolve_rootfs(
        static_info.get("file_format", "unknown"),
        static_info.get("arch", "unknown"),
        int(static_info.get("bits", 0) or 0),
    )
    if rootfs is None:
        recorder.record(
            "api",
            "emulation.no_rootfs",
            detail=f"No rootfs under {settings.qiling_rootfs}; static-only analysis",
            severity="info",
        )
        logger.warning("No Qiling rootfs available at %s", settings.qiling_rootfs)
        return False, dumps

    def _trigger_dump(api_name: str, args: dict) -> None:
        rec = memory.dump_region(
            sample_id=sample_id,
            reason=f"suspicious_api:{api_name}",
            address=0,
            size=65536,
            ql=getattr(_trigger_dump, "ql", None),
            fallback_data=fallback_data,
        )
        if rec:
            dumps.append(rec)
        recorder.record(
            "memory",
            "MemoryDumpTriggered",
            args={"api": api_name},
            detail=f"Dump captured after {api_name}",
            severity="high",
            suspicious=True,
        )

    handler = _QilingLogCapture(recorder, _trigger_dump)
    try:
        ql = Qiling(
            [sample_path],
            rootfs=str(rootfs),
            verbose=QL_VERBOSE.DEFAULT,
            console=False,
            log_override=None,
        )
        _trigger_dump.ql = ql  # type: ignore[attr-defined]

        # Attach our capture handler to Qiling's logger.
        ql_logger = getattr(ql, "log", logging.getLogger("qiling"))
        ql_logger.addHandler(handler)
        ql_logger.setLevel(logging.DEBUG)

        if settings.anti_evasion:
            anti_detect.apply_qiling_hooks(ql, recorder)

        recorder.record(
            "api",
            "emulation.start",
            args={"rootfs": str(rootfs), "format": static_info.get("file_format")},
            detail="Qiling user-mode emulation started",
        )

        timeout_us = max(1, settings.emulation_timeout) * 1_000_000
        try:
            ql.run(timeout=timeout_us)
        except Exception as run_exc:
            recorder.record(
                "api",
                "emulation.halted",
                detail=f"Execution halted: {run_exc}",
                severity="low",
            )

        recorder.record("api", "emulation.end", detail="Emulation finished")
        ql_logger.removeHandler(handler)
        return True, dumps
    except Exception as exc:
        logger.exception("Emulation failed")
        recorder.record(
            "api",
            "emulation.error",
            detail=f"{exc}",
            severity="medium",
        )
        return False, dumps
