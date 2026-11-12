rule Ransom_Note_Generic
{
    meta:
        description = "Text that is common in ransom notes"
        author = "Sigma Forge samples"
        severity = "high"
        attack = "T1486"
    strings:
        $a1 = "your files have been encrypted" nocase
        $a2 = "to decrypt your files" nocase
        $b1 = "bitcoin" nocase
        $b2 = "tor browser" nocase
        $b3 = ".onion" nocase
    condition:
        filesize < 200KB and 1 of ($a*) and 2 of ($b*)
}
