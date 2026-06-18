/*
 * APEIRON built-in YARA rules: anti-VM / anti-sandbox / anti-debug techniques.
 */

rule AntiVM_VMware_Artifacts
{
    meta:
        author = "APEIRON"
        description = "References to VMware artifacts"
        category = "anti-vm"
    strings:
        $s1 = "VMware" ascii wide nocase
        $s2 = "vmtoolsd" ascii wide nocase
        $s3 = "vmhgfs" ascii wide nocase
        $s4 = "VMwareVMX" ascii wide nocase
        $s5 = "vmci.sys" ascii wide nocase
    condition:
        2 of them
}

rule AntiVM_VirtualBox_Artifacts
{
    meta:
        author = "APEIRON"
        description = "References to VirtualBox artifacts"
        category = "anti-vm"
    strings:
        $s1 = "VBOX" ascii wide nocase
        $s2 = "VBoxGuest" ascii wide nocase
        $s3 = "VBoxMouse" ascii wide nocase
        $s4 = "VBoxService" ascii wide nocase
        $s5 = "VBoxTray" ascii wide nocase
        $s6 = "oracle\\virtualbox" ascii wide nocase
    condition:
        2 of them
}

rule AntiVM_QEMU_Xen_Artifacts
{
    meta:
        author = "APEIRON"
        description = "QEMU / Xen / KVM artifacts"
        category = "anti-vm"
    strings:
        $q1 = "QEMU" ascii wide
        $q2 = "qemu-ga" ascii wide
        $x1 = "Xen" ascii wide
        $x2 = "xenservice" ascii wide nocase
    condition:
        2 of them
}

rule AntiVM_CPUID_Hypervisor_Check
{
    meta:
        author = "APEIRON"
        description = "CPUID hypervisor presence check (leaf 0x40000000 / vendor strings)"
        category = "anti-vm"
    strings:
        // cpuid instruction byte sequence
        $cpuid = { 0F A2 }
        $hv1 = "KVMKVMKVM" ascii
        $hv2 = "Microsoft Hv" ascii
        $hv3 = "VMwareVMware" ascii
        $hv4 = "XenVMMXenVMM" ascii
        $hv5 = "prl hyperv" ascii nocase
    condition:
        $cpuid and any of ($hv*)
}

rule AntiSandbox_Known_Products
{
    meta:
        author = "APEIRON"
        description = "References to known sandbox/analysis products"
        category = "anti-sandbox"
    strings:
        $s1 = "SbieDll.dll" ascii wide nocase
        $s2 = "Sandboxie" ascii wide nocase
        $s3 = "cuckoomon" ascii wide nocase
        $s4 = "cuckoo" ascii wide nocase
        $s5 = "wine_get_unix_file_name" ascii
        $s6 = "joeboxserver" ascii wide nocase
    condition:
        any of them
}

rule AntiDebug_Windows_APIs
{
    meta:
        author = "APEIRON"
        description = "Anti-debugging Windows API usage"
        category = "anti-debug"
    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "NtQueryInformationProcess" ascii
        $a4 = "OutputDebugStringA" ascii
        $a5 = "NtSetInformationThread" ascii
    condition:
        2 of them
}

rule AntiDebug_Linux_ptrace
{
    meta:
        author = "APEIRON"
        description = "Linux anti-debugging via ptrace / proc inspection"
        category = "anti-debug"
    strings:
        $p1 = "ptrace" ascii
        $p2 = "/proc/self/status" ascii
        $p3 = "TracerPid" ascii
    condition:
        $p1 and 1 of ($p2, $p3)
}

rule AntiAnalysis_Timing_Checks
{
    meta:
        author = "APEIRON"
        description = "Timing-based evasion primitives"
        category = "anti-analysis"
    strings:
        $t1 = "QueryPerformanceCounter" ascii
        $t2 = "GetTickCount" ascii
        $t3 = "rdtsc" ascii
        $rdtsc = { 0F 31 }
    condition:
        2 of them
}
