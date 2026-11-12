rule PowerShell_Encoded_Command_In_File
{
    meta:
        description = "File that starts PowerShell with an encoded command, or holds base64 of IEX in UTF-16"
        author = "Sigma Forge samples"
        attack = "T1059.001"
    strings:
        $ps = "powershell" nocase
        $enc = /\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $iex_b64 = "SQBFAFgA"
    condition:
        ($ps and $enc) or $iex_b64
}
