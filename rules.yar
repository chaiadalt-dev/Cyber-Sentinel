rule Pegasus_Indicators {
    meta:
        author = "Cyber Sentinel Engine"
        description = "Detects basic indicators and binaries associated with Pegasus Spyware"
        version = "1.0"
    strings:
        $s1 = "lw-install" ascii wide nocase
        $s2 = "rtbuddyd" ascii wide nocase
        $s3 = "webkit_exploit" ascii wide
        $s4 = "pegasus_intercept_message" ascii wide
    condition:
        any of them
}

rule APT_Malware_Behaviour {
    meta:
        author = "Cyber Sentinel Engine"
        description = "Flags suspicious execution flows often used by Advanced Persistent Threats (APT)"
    strings:
        $e1 = "hijack_execution_flow"
        $e2 = "leak_kernel_address"
        $e3 = "corrupt_kernel_memory"
        $e4 = "send_to_c2_server"
        $e5 = "escalate_privileges"
    condition:
        2 of them
}
