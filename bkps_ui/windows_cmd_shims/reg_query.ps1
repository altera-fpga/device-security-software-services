param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RegArgs
)

$ErrorActionPreference = 'Stop'

if ($RegArgs.Count -lt 2 -or $RegArgs[0] -ine 'query') {
    [Console]::Error.WriteLine('ERROR: Only REG QUERY is supported.')
    exit 1
}

$key = $RegArgs[1].Trim('"')
$providerPath = $null
if ($key -match '^(?i)HKLM\\(.+)$') {
    $providerPath = 'Registry::HKEY_LOCAL_MACHINE\' + $Matches[1]
} elseif ($key -match '^(?i)HKCU\\(.+)$') {
    $providerPath = 'Registry::HKEY_CURRENT_USER\' + $Matches[1]
} else {
    [Console]::Error.WriteLine("ERROR: Unsupported registry root: $key")
    exit 1
}

$valueName = $null
for ($index = 2; $index -lt $RegArgs.Count; $index++) {
    if ($RegArgs[$index] -ieq '/v' -and ($index + 1) -lt $RegArgs.Count) {
        $valueName = $RegArgs[$index + 1].Trim('"')
        break
    }
}

try {
    $item = Get-ItemProperty -LiteralPath $providerPath
    Write-Output $key

    if ($valueName) {
        $value = $item.PSObject.Properties[$valueName].Value
        if ($null -eq $value) {
            exit 1
        }
        $type = if ($value -is [int] -or $value -is [long]) { 'REG_DWORD' } else { 'REG_SZ' }
        Write-Output ('    {0}    {1}    {2}' -f $valueName, $type, $value)
    }
    exit 0
} catch {
    exit 1
}
