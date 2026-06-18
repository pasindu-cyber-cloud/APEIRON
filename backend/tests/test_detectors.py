from app.analyzer import detectors
from app.analyzer.types import TraceRecord


def test_process_injection_detected():
    static_info = {
        "imported_api": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "strings": [],
    }
    dets, score, tags = detectors.run_detectors(static_info, [])
    names = {d.name for d in dets}
    assert "Process Injection" in names
    assert "injection" in tags
    assert score >= 32


def test_verdict_thresholds():
    assert detectors.verdict_from_score(0) == "benign"
    assert detectors.verdict_from_score(20) == "low-risk"
    assert detectors.verdict_from_score(50) == "suspicious"
    assert detectors.verdict_from_score(85) == "malicious"


def test_anti_vm_from_strings():
    static_info = {"imported_api": [], "strings": ["found VBoxGuest driver", "VBoxService.exe"]}
    dets, _score, tags = detectors.run_detectors(static_info, [])
    assert "anti-vm" in tags
    assert any(d.name == "Anti-VM / Sandbox Evasion" for d in dets)


def test_mark_suspicious_events():
    events = [
        TraceRecord(seq=1, rel_ts=0.0, category="api", name="WriteProcessMemory"),
        TraceRecord(seq=2, rel_ts=0.1, category="api", name="printf"),
    ]
    static_info = {"imported_api": ["WriteProcessMemory", "CreateRemoteThread"], "strings": []}
    dets, _score, _tags = detectors.run_detectors(static_info, events)
    detectors.mark_suspicious_events(events, dets)
    assert events[0].suspicious is True
    assert events[1].suspicious is False


def test_packed_flag_adds_detection():
    static_info = {
        "imported_api": [],
        "strings": [],
        "likely_packed": True,
        "high_entropy_sections": [".text"],
    }
    dets, _score, tags = detectors.run_detectors(static_info, [])
    assert "packed" in tags
    assert any("Packed" in d.name for d in dets)
