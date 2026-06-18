from app.analyzer import static_analysis as sa


def test_detect_format_pe(minimal_pe):
    assert sa.detect_format(minimal_pe) == "PE"


def test_detect_format_elf(minimal_elf):
    assert sa.detect_format(minimal_elf) == "ELF"


def test_detect_format_unknown():
    assert sa.detect_format(b"not a binary at all") == "unknown"


def test_entropy_bounds():
    assert sa.shannon_entropy(b"") == 0.0
    assert sa.shannon_entropy(b"\x00" * 1000) == 0.0
    # Uniform random-ish bytes approach 8.0
    high = bytes(range(256)) * 8
    assert sa.shannon_entropy(high) > 7.9


def test_extract_strings():
    blob = b"\x00\x01hello world\x00\x02http://evil.test/x\x00"
    strings = sa.extract_strings(blob)
    assert any("hello world" in s for s in strings)
    assert any("evil.test" in s for s in strings)


def test_analyze_static_pe(tmp_path, minimal_pe):
    p = tmp_path / "sample.exe"
    p.write_bytes(minimal_pe)
    info = sa.analyze_static(p)
    assert info["file_format"] == "PE"
    assert info["platform"] == "windows"
    assert "strings" in info
    assert isinstance(info["sections"], list)


def test_analyze_static_elf(tmp_path, minimal_elf):
    p = tmp_path / "sample.bin"
    p.write_bytes(minimal_elf)
    info = sa.analyze_static(p)
    assert info["file_format"] == "ELF"
