import "math"

rule Embedded_PE_Header_Text
{
    meta:
        description = "MZ header followed by the DOS stub text, a sign of a program hidden inside another file"
        author = "Sigma Forge samples"
    strings:
        $mz = { 4D 5A }
        $stub = "This program cannot be run in DOS mode"
    condition:
        $mz and $stub and not ($mz at 0)
}

rule High_Entropy_Blob
{
    meta:
        description = "Large file with very high entropy, often packed or encrypted data"
        author = "Sigma Forge samples"
    condition:
        filesize > 4KB and math.entropy(0, filesize) > 7.5
}
