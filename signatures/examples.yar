// Harmless examples, not a production malware corpus. Never execute samples.
rule FerXium_Test_Marker {
    meta:
        description = "Harmless FerXium integration-test marker"
        severity = "low"
    strings:
        $marker = "FERXIUM_TEST_SIGNATURE_v1" ascii
    condition:
        filesize < 67108864 and $marker
}

rule Suspicious_PowerShell_Download_Execute {
    meta:
        description = "Review a script combining download and execution primitives"
        severity = "medium"
    strings:
        $ps = "powershell" nocase ascii wide
        $download = "DownloadString" nocase ascii wide
        $execute = "Invoke-Expression" nocase ascii wide
    condition:
        filesize < 1048576 and all of them
}
