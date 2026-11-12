rule Hardcoded_AWS_Access_Key : secrets
{
    meta:
        description = "AWS access key id and secret written in a file, often found in leaked configs and scripts"
        author = "Sigma Forge samples"
        attack = "T1552.001"
    strings:
        $id = /\b(AKIA|ASIA)[0-9A-Z]{16}\b/
        $secret = /aws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9\/+=]{40}/ nocase
    condition:
        $id and $secret
}
