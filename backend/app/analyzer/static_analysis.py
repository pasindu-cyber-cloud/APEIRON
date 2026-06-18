"""Static analysis: format detection, headers, imports, sections, entropy, strings."""
from __future__ import annotations

import math
import re
import struct
from pathlib import Path
from typing import Any

from ..logging_config import get_logger

logger = get_logger("apeiron.static")

# PE machine constants
_PE_MACHINE = {
    0x014C: ("x86", 32),
    0x8664: ("x86_64", 64),
    0x01C0: ("arm", 32),
    0xAA64: ("arm64", 64),
    0x01C4: ("armv7", 32),
}

# ELF e_machine constants
_ELF_MACHINE = {
    0x03: ("x86", 32),
    0x3E: ("x86_64", 64),
    0x28: ("arm", 32),
    0xB7: ("arm64", 64),
    0xF3: ("riscv", 64),
}

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UNICODE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_strings(data: bytes, max_strings: int = 5000) -> list[str]:
    found: list[str] = []
    for match in _ASCII_RE.finditer(data):
        found.append(match.group().decode("ascii", "ignore"))
        if len(found) >= max_strings:
            return found
    for match in _UNICODE_RE.finditer(data):
        found.append(match.group().decode("utf-16-le", "ignore"))
        if len(found) >= max_strings:
            break
    return found


def detect_format(data: bytes) -> str:
    if data[:2] == b"MZ":
        # confirm PE header offset
        if len(data) >= 0x40:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_off + 4 <= len(data) and data[pe_off : pe_off + 4] == b"PE\x00\x00":
                return "PE"
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    return "unknown"


def _analyze_pe(path: Path, data: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {"file_format": "PE", "platform": "windows"}
    try:
        import pefile  # type: ignore

        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ]
        )
        machine = pe.FILE_HEADER.Machine
        arch, bits = _PE_MACHINE.get(machine, ("unknown", 0))
        info["arch"] = arch
        info["bits"] = bits
        info["compile_timestamp"] = int(pe.FILE_HEADER.TimeDateStamp)
        try:
            info["imphash"] = pe.get_imphash()
        except Exception:
            info["imphash"] = ""

        sections = []
        for section in pe.sections:
            raw = section.get_data()
            sections.append(
                {
                    "name": section.Name.rstrip(b"\x00").decode("ascii", "ignore"),
                    "vaddr": hex(section.VirtualAddress),
                    "vsize": section.Misc_VirtualSize,
                    "rawsize": section.SizeOfRawData,
                    "entropy": shannon_entropy(raw),
                }
            )
        info["sections"] = sections

        imports: dict[str, list[str]] = {}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("ascii", "ignore") if entry.dll else "?"
                funcs = [
                    imp.name.decode("ascii", "ignore")
                    for imp in entry.imports
                    if imp.name
                ]
                imports[dll] = funcs
        info["imports"] = imports
        info["imported_api"] = sorted({fn for fns in imports.values() for fn in fns})
        pe.close()
    except Exception as exc:
        logger.warning("PE parse error: %s", exc)
        info.setdefault("arch", "unknown")
        info.setdefault("bits", 0)
        info.setdefault("sections", [])
        info.setdefault("imports", {})
        info.setdefault("imported_api", [])
    return info


def _analyze_elf(path: Path, data: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {"file_format": "ELF", "platform": "linux"}
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore

        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            e_machine = elf.header["e_machine"]
            mapping = {
                "EM_386": ("x86", 32),
                "EM_X86_64": ("x86_64", 64),
                "EM_ARM": ("arm", 32),
                "EM_AARCH64": ("arm64", 64),
                "EM_RISCV": ("riscv", 64),
            }
            arch, bits = mapping.get(e_machine, ("unknown", 0))
            info["arch"] = arch
            info["bits"] = bits or (64 if elf.elfclass == 64 else 32)
            info["elf_type"] = elf.header["e_type"]

            sections = []
            for section in elf.iter_sections():
                raw = section.data() or b""
                sections.append(
                    {
                        "name": section.name,
                        "vaddr": hex(section["sh_addr"]),
                        "vsize": section["sh_size"],
                        "rawsize": len(raw),
                        "entropy": shannon_entropy(raw),
                    }
                )
            info["sections"] = sections

            needed: list[str] = []
            symbols: list[str] = []
            dynamic = elf.get_section_by_name(".dynamic")
            if dynamic is not None:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym is not None:
                for sym in dynsym.iter_symbols():
                    if sym.name:
                        symbols.append(sym.name)
            info["needed_libs"] = needed
            info["imported_api"] = sorted(set(symbols))
            info["imports"] = {lib: [] for lib in needed}
    except Exception as exc:
        logger.warning("ELF parse error: %s", exc)
        info.setdefault("arch", "unknown")
        info.setdefault("bits", 0)
        info.setdefault("sections", [])
        info.setdefault("imports", {})
        info.setdefault("imported_api", [])
    return info


def analyze_static(path: str | Path) -> dict[str, Any]:
    """Run all static analysis and return a structured dict."""
    path = Path(path)
    data = path.read_bytes()
    fmt = detect_format(data)
    result: dict[str, Any] = {
        "file_format": fmt,
        "size": len(data),
        "overall_entropy": shannon_entropy(data),
        "arch": "unknown",
        "bits": 0,
        "platform": "unknown",
        "sections": [],
        "imports": {},
        "imported_api": [],
    }
    if fmt == "PE":
        result.update(_analyze_pe(path, data))
    elif fmt == "ELF":
        result.update(_analyze_elf(path, data))

    result["strings"] = extract_strings(data)
    # Heuristic: high entropy sections suggest packing/compression.
    packed = [
        s["name"]
        for s in result.get("sections", [])
        if s.get("entropy", 0) >= 7.2 and s.get("rawsize", 0) > 0
    ]
    result["high_entropy_sections"] = packed
    result["likely_packed"] = bool(packed) or result["overall_entropy"] >= 7.5
    return result
