/*
 * APEIRON built-in YARA rules: common packers / protectors.
 * These are heuristic and intended for triage, not definitive attribution.
 */

rule Packer_UPX
{
    meta:
        author = "APEIRON"
        description = "UPX packer signatures"
        category = "packer"
    strings:
        $u1 = "UPX0" ascii
        $u2 = "UPX1" ascii
        $u3 = "UPX!" ascii
        $u4 = "$Info: This file is packed with the UPX" ascii
    condition:
        2 of them
}

rule Packer_ASPack
{
    meta:
        author = "APEIRON"
        description = "ASPack packer"
        category = "packer"
    strings:
        $a1 = ".aspack" ascii
        $a2 = ".adata" ascii
        $a3 = "aPLib" ascii
    condition:
        any of them
}

rule Packer_PECompact
{
    meta:
        author = "APEIRON"
        description = "PECompact packer"
        category = "packer"
    strings:
        $p1 = "PEC2" ascii
        $p2 = "PECompact2" ascii
    condition:
        any of them
}

rule Packer_MPRESS
{
    meta:
        author = "APEIRON"
        description = "MPRESS packer"
        category = "packer"
    strings:
        $m1 = ".MPRESS1" ascii
        $m2 = ".MPRESS2" ascii
    condition:
        any of them
}

rule Packer_Themida_WinLicense
{
    meta:
        author = "APEIRON"
        description = "Themida / WinLicense protector"
        category = "protector"
    strings:
        $t1 = "Themida" ascii wide
        $t2 = "WinLicense" ascii wide
        $t3 = ".themida" ascii
    condition:
        any of them
}

rule Packer_VMProtect
{
    meta:
        author = "APEIRON"
        description = "VMProtect virtualization protector"
        category = "protector"
    strings:
        $v1 = ".vmp0" ascii
        $v2 = ".vmp1" ascii
        $v3 = "VMProtect" ascii wide
    condition:
        any of them
}

rule Packer_Enigma
{
    meta:
        author = "APEIRON"
        description = "Enigma Protector"
        category = "protector"
    strings:
        $e1 = ".enigma1" ascii
        $e2 = ".enigma2" ascii
        $e3 = "Enigma Protector" ascii wide
    condition:
        any of them
}

rule Packer_NSIS_Installer
{
    meta:
        author = "APEIRON"
        description = "Nullsoft NSIS installer (often abused as dropper)"
        category = "installer"
    strings:
        $n1 = "Nullsoft" ascii
        $n2 = "NullsoftInst" ascii
    condition:
        any of them
}

rule Generic_High_Entropy_Overlay
{
    meta:
        author = "APEIRON"
        description = "Generic indicator: MZ header with encrypted/packed payload markers"
        category = "packer-heuristic"
    strings:
        $mz = { 4D 5A }
        $packed1 = "This program cannot be run in DOS mode" ascii
    condition:
        $mz at 0 and not $packed1
}
