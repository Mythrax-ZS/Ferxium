// Original defensive rules derived from public indicators, not copied vendor rules.
// Source: https://www.malwarebytes.com/blog/threat-intel/2026/07/fake-games-spread-stealers-with-renpy-loader-msbuild-and-etherhiding
// Published 2026-07-20. Synthetic regression tests only; not a live-sample benchmark.
// Never flag Ren'Py, Nancy, MSBuild, or a public blockchain endpoint in isolation.
// Each rule splits a required literal with a character class so embedded rule
// source does not itself contain every required indicator in the compiled app.

rule FerXium_RenEngine_Config_Loader {
    meta:
        description = "RenEngine loader indicators: both reported XOR keys, encrypted config path, and sandbox/MOTW/launcher behavior. Review before containment."
        severity = "high"
        reference = "https://www.malwarebytes.com/blog/threat-intel/2026/07/fake-games-spread-stealers-with-renpy-loader-msbuild-and-etherhiding"
    strings:
        $config_key = /81034149cd6f48c8821340204f92766[e]/ ascii wide
        $payload_key = "A50YyY1" ascii wide
        $config_path = ".GEg" ascii wide
        $behavior_sandbox = "is_sandboxed" ascii wide
        $behavior_motw = ":Zone.Identifier" nocase ascii wide
        $behavior_launcher = "forfiles.exe" nocase ascii wide
    condition:
        filesize < 67108864 and $config_key and $payload_key and $config_path
        and 1 of ($behavior_*)
}

rule FerXium_RenEngine_MSBuild_Launcher {
    meta:
        description = "RenEngine launch-chain indicators: headless conhost, unrestricted MSBuild property functions, and the _czzf/Nancy project pairing. Review before containment."
        severity = "high"
    strings:
        $functions = /MSBUILDENABLEALLPROPERTYFUNCTION[S]=1/ nocase ascii wide
        $env = "_czzf" nocase ascii wide
        $project = "Nancy.csproj" nocase ascii wide
        $build = "MSBuild.exe" nocase ascii wide
        $console = "conhost.exe" nocase ascii wide
        $headless = "--headless" nocase ascii wide
    condition:
        filesize < 1048576 and all of them
}

rule FerXium_RenEngine_MSBuild_Reflective_Load {
    meta:
        description = "MSBuild project combines the reported campaign entry point with reflective AppDomain loading. Review before containment."
        severity = "high"
    strings:
        $project = "<Project" nocase ascii wide
        $entry = /DefaultEvaluator[5]/ ascii wide
        $domain = "AppDomain" ascii wide
        $current = "CurrentDomain" ascii wide
        $load = ".Load(" ascii wide
        $instance = "CreateInstance" ascii wide
    condition:
        filesize < 67108864 and all of them
}

rule FerXium_RenEngine_Trojanized_Nancy {
    meta:
        description = "PE contains the reported campaign entry point and all three distinctive trojanized Nancy resource names."
        severity = "high"
    strings:
        $entry = /DefaultEvaluator[5]/ ascii wide
        $bytecode = /Nancy[.]Runtime[.]mvlorimu/ ascii wide
        $data = "Nancy.Data.tcnlhxw" ascii wide
        $resources = "Nancy.Resources.kxxodp" ascii wide
    condition:
        filesize < 67108864 and uint16(0) == 0x5a4d
        and uint32(uint32(0x3c)) == 0x00004550 and all of them
}

rule FerXium_RenEngine_EtherHiding_Downloader {
    meta:
        description = "PE combines the reported EtherHiding contract and selector with eth_call and a campaign module or payload path. Review before containment."
        severity = "high"
    strings:
        $contract = /0x328a1fadff154290f0ce1389a4e633698cdfdaa[7]/ nocase ascii wide
        $selector = "0x06fdde03" nocase ascii wide
        $rpc = "eth_call" ascii wide
        $campaign_module = "GollopDevest" ascii wide
        $campaign_path1 = "/assets/ExponeAboard.json" ascii wide
        $campaign_path2 = "/assets/MailersKogasin.json" ascii wide
        $campaign_path3 = "/assets/LanoseThrip.json" ascii wide
    condition:
        filesize < 67108864 and uint16(0) == 0x5a4d
        and uint32(uint32(0x3c)) == 0x00004550
        and $contract and $selector and $rpc and 1 of ($campaign_*)
}
