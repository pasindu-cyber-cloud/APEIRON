from app.analyzer import ioc_extractor as ie
from app.analyzer.types import TraceRecord


def test_extract_urls_ips_domains():
    strings = [
        "connect to http://malware.example/payload.bin",
        "c2 at 203.0.113.45 port 443",
        "drop evil-domain.top now",
        "ignore microsoft.com please",
    ]
    iocs = ie.extract_from_strings(strings)
    by_type = {}
    for i in iocs:
        by_type.setdefault(i.ioc_type, []).append(i.value.lower())
    assert any("malware.example" in v for v in by_type.get("url", []))
    assert "203.0.113.45" in by_type.get("ip", [])
    assert any("evil-domain.top" in v for v in by_type.get("domain", []))
    # Noise domains are dropped.
    assert "microsoft.com" not in by_type.get("domain", [])


def test_registry_and_localhost_filtering():
    strings = [r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "127.0.0.1"]
    iocs = ie.extract_from_strings(strings)
    types = {i.ioc_type for i in iocs}
    assert "registry_key" in types
    assert "ip" not in types  # loopback excluded


def test_extract_from_trace_mutex():
    events = [
        TraceRecord(
            seq=1,
            rel_ts=0.1,
            category="api",
            name="CreateMutexA",
            args={"lpName": "Global\\EvilMutex"},
        ),
    ]
    iocs = ie.extract_from_trace(events)
    assert any(i.ioc_type == "mutex" and "EvilMutex" in i.value for i in iocs)


def test_merge_dedup_counts():
    a = ie.extract_from_strings(["http://x.test/a", "http://x.test/a"])
    b = ie.extract_from_strings(["http://x.test/a"])
    merged = ie.merge_iocs(a, b)
    url = next(i for i in merged if i.ioc_type == "url")
    assert url.count >= 3
