from types import SimpleNamespace

from app.analyzer import rule_generator as rg
from app.analyzer.types import Detection, IOCRecord


def _fake_sample():
    return SimpleNamespace(
        id="abcdef0123456789",
        filename="evil.exe",
        sha256="a" * 64,
        verdict="malicious",
        threat_score=80,
        tags=["injection", "packed"],
    )


def test_generate_yara_structure():
    sample = _fake_sample()
    static_info = {
        "file_format": "PE",
        "strings": [
            "http://c2.evil.test/gate.php",
            "CreateRemoteThread",
            "cmd.exe /c powershell -enc",
        ],
    }
    iocs = [IOCRecord("domain", "c2.evil.test")]
    dets = [Detection("Process Injection", "high", "desc", ["T1055"], ["api:CreateRemoteThread"])]
    name, content = rg.generate_yara(sample, static_info, iocs, dets)
    assert name.startswith("APEIRON_")
    assert "rule " in content
    assert "uint16(0) == 0x5A4D" in content
    assert "condition:" in content
    assert "T1055" in content


def test_generate_sigma_structure():
    sample = _fake_sample()
    iocs = [
        IOCRecord("domain", "c2.evil.test"),
        IOCRecord("registry_key", r"HKLM\Software\Run"),
    ]
    dets = [Detection("Persistence", "medium", "desc", ["T1547"], [])]
    name, content = rg.generate_sigma(sample, iocs, dets)
    assert name.startswith("apeiron-")
    assert "title:" in content
    assert "detection:" in content
    assert "condition:" in content
    assert "level:" in content


def test_yara_escapes_quotes():
    sample = _fake_sample()
    static_info = {"file_format": "ELF", "strings": ['weird"string\\path with http link']}
    name, content = rg.generate_yara(sample, static_info, [], [])
    # Generated content must remain syntactically plausible (balanced braces).
    assert content.count("{") == content.count("}")
    assert "0x464C457F" in content
