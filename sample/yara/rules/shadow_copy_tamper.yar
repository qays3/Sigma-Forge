rule Script_Deletes_Shadow_Copies : windows impact
{
    meta:
        description = "Script or text that deletes Volume Shadow Copies or turns off recovery"
        author = "Sigma Forge samples"
        attack = "T1490"
    strings:
        $vss = /vssadmin(\.exe)?\s+delete\s+shadows/ nocase
        $wmic = "shadowcopy delete" nocase
        $bcd1 = "recoveryenabled no" nocase
        $bcd2 = "bootstatuspolicy ignoreallfailures" nocase
    condition:
        any of them
}
