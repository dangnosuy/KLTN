param(
    [Parameter(Mandatory = $true)][string]$StartUtc,
    [Parameter(Mandatory = $true)][string]$EndUtc,
    [Parameter(Mandatory = $true)][string[]]$TargetPath,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$start = [DateTimeOffset]::Parse($StartUtc).UtcDateTime
$end = [DateTimeOffset]::Parse($EndUtc).UtcDateTime.AddSeconds(90)
$targets = @($TargetPath)
$names = @($targets | ForEach-Object { [IO.Path]::GetFileName($_) })

function Test-TargetMatch([string]$Text) {
    if (-not $Text) { return $false }
    foreach ($value in @($targets + $names)) {
        if ($value -and $Text.IndexOf($value, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

$defender = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 1116, 1117, 1118, 1119, 1121
    StartTime = $start
} -ErrorAction SilentlyContinue | Where-Object {
    $_.TimeCreated.ToUniversalTime() -le $end -and (Test-TargetMatch ($_.ToXml()))
} | ForEach-Object {
    [PSCustomObject]@{ id = $_.Id; timestamp = $_.TimeCreated.ToUniversalTime().ToString('o'); message = $_.Message }
}

$sysmon = @()
try {
    $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
} catch {
    $sysmonLog = $null
}
if ($sysmonLog) {
    $sysmon = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = 1, 3, 7, 10, 11, 12, 13, 14
        StartTime = $start
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.TimeCreated.ToUniversalTime() -le $end -and (Test-TargetMatch ($_.ToXml()))
    } | ForEach-Object {
        [PSCustomObject]@{ id = $_.Id; timestamp = $_.TimeCreated.ToUniversalTime().ToString('o'); message = $_.Message }
    }
}

$threats = @()
$threatQueryError = $null
try {
    $threats = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object {
        $_.InitialDetectionTime -and
        $_.InitialDetectionTime.ToUniversalTime() -ge $start -and
        $_.InitialDetectionTime.ToUniversalTime() -le $end -and
        ((Test-TargetMatch ($_.ProcessName)) -or (Test-TargetMatch (@($_.Resources) -join "`n")))
    } | ForEach-Object {
        [PSCustomObject]@{
            threat_id = $_.ThreatID
            detection_id = $_.DetectionID
            process_name = $_.ProcessName
            resources = @($_.Resources)
            initial_detection_time = $_.InitialDetectionTime
            action_success = $_.ActionSuccess
            threat_status_id = $_.ThreatStatusID
        }
    })
} catch {
    $threatQueryError = $_.Exception.Message
}

[PSCustomObject]@{
    target_paths = $targets
    window_start_utc = $start.ToString('o')
    window_end_utc = $end.ToString('o')
    defender_events = @($defender)
    sysmon_events = @($sysmon)
    threat_detections = @($threats)
    threat_query_error = $threatQueryError
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
