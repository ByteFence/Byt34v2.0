rule DOS_Stub {
    strings:
        $a = "This program cannot be run in DOS mode"
    condition:
        $a
}

rule Ransom_Message {
    strings:
        $a = "Your files have been encrypted"
        $b = "Send Bitcoin"
        $c = "Decryptor"
    condition:
        2 of ($a, $b, $c)
}

rule Suspicious_Script {
    strings:
        $a = "CreateObject"
        $b = "WScript.Shell"
        $c = "Scripting.FileSystemObject"
    condition:
        any of ($a, $b, $c)
}

rule C2_Indicators {
    strings:
        $a = "http://"
        $b = "https://"
        $c = "callback"
    condition:
        2 of ($a, $b, $c)
}

rule Import_APIs {
    strings:
        $a = "VirtualAlloc"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        any of ($a, $b, $c)
}
