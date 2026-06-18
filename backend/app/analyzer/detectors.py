"""Heuristic behavior detection.

Combines statically-imported APIs with dynamically observed API/syscall trace
events to flag suspicious techniques, assign a threat score, and tag samples.
Findings are mapped to MITRE ATT&CK technique IDs where applicable.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .types import Detection, TraceRecord


@dataclass(frozen=True)
class BehaviorRule:
    name: str
    severity: str  # low | medium | high
    description: str
    mitre: tuple[str, ...]
    api_markers: tuple[str, ...]  # case-insensitive substring match against API names
    string_markers: tuple[str, ...] = ()
    tag: str = ""


_SEVERITY_WEIGHT = {"low": 8, "medium": 18, "high": 32}

RULES: tuple[BehaviorRule, ...] = (
    BehaviorRule(
        name="Process Injection",
        severity="high",
        description="APIs used to allocate, write and execute code in a remote process.",
        mitre=("T1055",),
        api_markers=(
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtWriteVirtualMemory",
            "QueueUserAPC",
            "RtlCreateUserThread",
            "SetThreadContext",
            "NtMapViewOfSection",
        ),
        tag="injection",
    ),
    BehaviorRule(
        name="Anti-Debugging",
        severity="medium",
        description="Routines that detect debuggers / analysis tooling.",
        mitre=("T1622", "T1497"),
        api_markers=(
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "OutputDebugString",
            "NtSetInformationThread",
            "ptrace",
        ),
        string_markers=("ThreadHideFromDebugger", "/proc/self/status", "TracerPid"),
        tag="anti-debug",
    ),
    BehaviorRule(
        name="Anti-VM / Sandbox Evasion",
        severity="medium",
        description="Checks for virtualization or sandbox artifacts.",
        mitre=("T1497",),
        api_markers=("GetTickCount", "QueryPerformanceCounter", "cpuid", "GetModuleHandle"),
        string_markers=(
            "VMware",
            "VBOX",
            "VirtualBox",
            "vboxguest",
            "Sandboxie",
            "SbieDll",
            "qemu",
            "wine_get_unix_file_name",
            "DISKVELOCITY",
        ),
        tag="anti-vm",
    ),
    BehaviorRule(
        name="Privilege Escalation",
        severity="high",
        description="Token/privilege manipulation indicative of escalation.",
        mitre=("T1134", "T1548"),
        api_markers=(
            "AdjustTokenPrivileges",
            "OpenProcessToken",
            "LookupPrivilegeValue",
            "DuplicateTokenEx",
            "ImpersonateLoggedOnUser",
            "setuid",
            "setgid",
        ),
        string_markers=("SeDebugPrivilege", "SeTakeOwnershipPrivilege"),
        tag="privesc",
    ),
    BehaviorRule(
        name="Persistence",
        severity="medium",
        description="Registry run keys, services, scheduled tasks or startup entries.",
        mitre=("T1547", "T1543", "T1053"),
        api_markers=(
            "RegSetValue",
            "RegCreateKey",
            "CreateServiceA",
            "CreateServiceW",
            "StartServiceA",
            "StartServiceW",
            "schtasks",
        ),
        string_markers=(
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "/etc/cron",
            "systemctl",
            ".bashrc",
            "LaunchAgents",
        ),
        tag="persistence",
    ),
    BehaviorRule(
        name="Credential Access",
        severity="high",
        description="Access to credential stores or LSASS.",
        mitre=("T1003",),
        api_markers=("LsaEnumerate", "SamConnect", "CredEnumerate", "CredRead"),
        string_markers=("lsass", "SAM\\SAM", "/etc/shadow"),
        tag="credential-access",
    ),
    BehaviorRule(
        name="Network / C2 Communication",
        severity="medium",
        description="Outbound network primitives suggesting C2 or exfiltration.",
        mitre=("T1071", "T1095"),
        api_markers=(
            "InternetOpen",
            "InternetConnect",
            "HttpSendRequest",
            "WinHttpConnect",
            "WSAStartup",
            "connect",
            "socket",
            "send",
            "recv",
            "getaddrinfo",
        ),
        tag="network",
    ),
    BehaviorRule(
        name="Dynamic Code / API Resolution",
        severity="low",
        description="Runtime resolution of APIs, often used to hide imports.",
        mitre=("T1027", "T1620"),
        api_markers=("LoadLibrary", "GetProcAddress", "dlopen", "dlsym", "LdrLoadDll"),
        tag="dynamic-api",
    ),
    BehaviorRule(
        name="Defense Evasion / Self-Delete",
        severity="medium",
        description="File deletion or shadow-copy tampering to remove forensic traces.",
        mitre=("T1070",),
        api_markers=("DeleteFile", "MoveFileEx", "unlink", "WinExec"),
        string_markers=("vssadmin delete shadows", "wevtutil cl", "cmd.exe /c del"),
        tag="defense-evasion",
    ),
    BehaviorRule(
        name="Ransomware Indicators",
        severity="high",
        description="Bulk crypto + file enumeration patterns typical of ransomware.",
        mitre=("T1486",),
        api_markers=(
            "CryptEncrypt",
            "CryptAcquireContext",
            "CryptGenKey",
            "FindFirstFile",
            "FindNextFile",
        ),
        string_markers=("YOUR FILES", "decrypt", ".locked", "ransom", "bitcoin"),
        tag="ransomware",
    ),
)


def _collect_api_names(static_info: dict, events: Iterable[TraceRecord]) -> set[str]:
    names = set(static_info.get("imported_api", []) or [])
    for evt in events:
        if evt.category in ("api", "syscall"):
            names.add(evt.name)
    return names


def _collect_strings(static_info: dict, events: Iterable[TraceRecord]) -> str:
    parts = list(static_info.get("strings", []) or [])
    for evt in events:
        parts.append(evt.detail)
        parts.extend(str(v) for v in evt.args.values())
    return "\n".join(parts).lower()


def run_detectors(
    static_info: dict, events: list[TraceRecord]
) -> tuple[list[Detection], int, list[str]]:
    api_names = {n.lower() for n in _collect_api_names(static_info, events)}
    blob = _collect_strings(static_info, events)

    detections: list[Detection] = []
    tags: set[str] = set()

    for rule in RULES:
        evidence: list[str] = []
        for marker in rule.api_markers:
            ml = marker.lower()
            hit = next((n for n in api_names if ml in n), None)
            if hit:
                evidence.append(f"api:{hit}")
        for marker in rule.string_markers:
            if marker.lower() in blob:
                evidence.append(f"str:{marker}")
        # Require at least 2 markers for low-confidence noisy rules.
        threshold = 2 if rule.severity == "low" else 1
        if len(evidence) >= threshold:
            detections.append(
                Detection(
                    name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    mitre=list(rule.mitre),
                    evidence=evidence[:12],
                )
            )
            if rule.tag:
                tags.add(rule.tag)

    if static_info.get("likely_packed"):
        detections.append(
            Detection(
                name="Packed / Obfuscated Binary",
                severity="low",
                description="High-entropy sections suggest packing or encryption.",
                mitre=["T1027.002"],
                evidence=[f"section:{s}" for s in static_info.get("high_entropy_sections", [])]
                or ["overall_entropy>=7.5"],
            )
        )
        tags.add("packed")

    score = min(100, sum(_SEVERITY_WEIGHT.get(d.severity, 5) for d in detections))
    return detections, score, sorted(tags)


def mark_suspicious_events(events: list[TraceRecord], detections: list[Detection]) -> None:
    """Flag trace events that match high/medium detection evidence."""
    sev_by_api: dict[str, str] = {}
    for det in detections:
        if det.severity == "info":
            continue
        for ev in det.evidence:
            if ev.startswith("api:"):
                sev_by_api[ev.split(":", 1)[1].lower()] = det.severity
    for evt in events:
        sev = sev_by_api.get(evt.name.lower())
        if sev:
            evt.suspicious = True
            evt.severity = sev


def verdict_from_score(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 35:
        return "suspicious"
    if score >= 10:
        return "low-risk"
    return "benign"
