<#
.SYNOPSIS
    Three-State Behavior Verifier (Contribution C1) - Native Windows PowerShell Runner
    Adaptive Program Transformation for Robustness Evaluation of Malware Detection Systems

.DESCRIPTION
    Evaluates Windows C source samples and variants against functional contracts:
      - BUILD_FAIL: Compilation failed (syntax error, missing symbol, invalid flags)
      - UNDETERMINED: Compilation succeeded, but execution crashed, timed out, or failed proof marker
      - PASSED_TEST: Compilation succeeded AND 100% functional proof verified
#>

[CmdletBinding()]
param(
    [string]$SampleId,
    [switch]$All,
    [string]$Group,
    [string]$DatasetDir = "sources/dataset",
    [string]$Manifest = "sources/dataset/manifest.json",
    [string]$Compiler = "auto",
    [switch]$JsonOutput
)

$ErrorActionPreference = "Continue"

# Resolve absolute paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$WorkspaceRoot = (Resolve-Path "$ScriptDir/../..").Path
$ResolvedDatasetDir = (Resolve-Path "$WorkspaceRoot/$DatasetDir").Path
$BuildRoot = Join-Path $ScriptDir "build"

if (-not (Test-Path $BuildRoot)) {
    New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
}

# Locate MSVC Environment
function Get-VcvarsPath {
    $candidates = @(
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    return $null
}

$VcvarsPath = Get-VcvarsPath

# Compile function
function Invoke-CompileSample {
    param(
        [PSCustomObject]$Contract,
        [string]$SandboxDir,
        [string]$OutputExe
    )

    $sourcePaths = @()
    foreach ($s in $Contract.build.sources) {
        $sourcePaths += (Join-Path $ResolvedDatasetDir $s)
    }

    # Verify source files exist
    foreach ($sp in $sourcePaths) {
        if (-not (Test-Path $sp)) {
            return @{ Success = $false; Error = "Source file not found: $sp" }
        }
    }

    # Prepare libraries
    $libArgs = @()
    foreach ($lib in $Contract.build.libraries) {
        if ($lib -notlike "*.lib") { $libArgs += "$lib.lib" } else { $libArgs += $lib }
    }

    $incArgs = "/I`"$ResolvedDatasetDir`""
    $outObj = [System.IO.Path]::ChangeExtension($OutputExe, ".obj")

    $clCmd = "cl.exe /nologo /O2 /W3 $incArgs $($sourcePaths -join ' ') /Fo:`"$outObj`" /link $($libArgs -join ' ') /out:`"$OutputExe`""

    if ($VcvarsPath) {
        $fullCmd = "call `"$VcvarsPath`" >nul 2>&1 && $clCmd"
        $output = cmd.exe /c "$fullCmd 2>&1"
    } else {
        $output = cmd.exe /c "$clCmd 2>&1"
    }

    $compileOk = ($LASTEXITCODE -eq 0 -and (Test-Path $OutputExe))
    return @{
        Success = $compileOk
        Output = ($output -join "`n")
        ExitCode = $LASTEXITCODE
    }
}

# Verify single sample function
function Test-SampleContract {
    param(
        [string]$ContractFile
    )

    if (-not (Test-Path $ContractFile)) {
        return @{
            SampleId = [System.IO.Path]::GetFileNameWithoutExtension($ContractFile)
            Status = "BUILD_FAIL"
            Error = "Contract file not found: $ContractFile"
        }
    }

    $contractJson = Get-Content -LiteralPath $ContractFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $sid = $contractJson.id

    $sandboxDir = Join-Path $BuildRoot "sandbox_$sid"
    if (Test-Path $sandboxDir) {
        Remove-Item -Path $sandboxDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $sandboxDir -Force | Out-Null

    $binaryPath = Join-Path $sandboxDir "$sid.exe"
    $proofFile = Join-Path $sandboxDir $contractJson.verification.proof_file

    # Stage 1: Compilation
    $swCompile = [System.Diagnostics.Stopwatch]::StartNew()
    $compileRes = Invoke-CompileSample -Contract $contractJson -SandboxDir $sandboxDir -OutputExe $binaryPath
    $swCompile.Stop()

    if (-not $compileRes.Success) {
        Remove-Item -Path $sandboxDir -Recurse -Force -ErrorAction SilentlyContinue
        return [PSCustomObject]@{
            SampleId = $sid
            Name = $contractJson.name
            Group = $contractJson.group
            Status = "BUILD_FAIL"
            ExitCode = $null
            ExecutionTimeMs = 0
            ProofMatched = $false
            MatchedMarker = $null
            Error = $compileRes.Output
        }
    }

    # Stage 2: Execution & Watchdog
    $timeoutSec = if ($contractJson.execution.timeout_seconds) { $contractJson.execution.timeout_seconds } else { 15 }
    $expectedExit = if ($null -ne $contractJson.execution.expected_exit_code) { $contractJson.execution.expected_exit_code } else { 0 }

    $swExec = [System.Diagnostics.Stopwatch]::StartNew()
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $binaryPath
    $psi.WorkingDirectory = $sandboxDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $finished = $proc.WaitForExit($timeoutSec * 1000)
    $swExec.Stop()

    if (-not $finished) {
        try { $proc.Kill() } catch {}
        Remove-Item -Path $sandboxDir -Recurse -Force -ErrorAction SilentlyContinue
        return [PSCustomObject]@{
            SampleId = $sid
            Name = $contractJson.name
            Group = $contractJson.group
            Status = "UNDETERMINED"
            ExitCode = -1
            ExecutionTimeMs = [int]$swExec.ElapsedMilliseconds
            ProofMatched = $false
            MatchedMarker = $null
            Error = "Execution timed out ($timeoutSec s)"
        }
    }

    $actualExit = $proc.ExitCode
    $proc.Close()

    if ($actualExit -ne $expectedExit) {
        Remove-Item -Path $sandboxDir -Recurse -Force -ErrorAction SilentlyContinue
        return [PSCustomObject]@{
            SampleId = $sid
            Name = $contractJson.name
            Group = $contractJson.group
            Status = "UNDETERMINED"
            ExitCode = $actualExit
            ExecutionTimeMs = [int]$swExec.ElapsedMilliseconds
            ProofMatched = $false
            MatchedMarker = $null
            Error = "Exit code $actualExit != expected $expectedExit"
        }
    }

    # Stage 3: Proof Marker Verification
    $proofContent = ""
    $proofFound = $false
    if (Test-Path $proofFile) {
        $proofFound = $true
        $proofContent = (Get-Content -LiteralPath $proofFile -Raw -Encoding UTF8).Trim()
    }

    $expectedMarker = $contractJson.verification.expected_marker
    $altMarker = $contractJson.verification.alternative_marker

    $matchedType = $null
    $isMatch = $false

    if ($expectedMarker -and $proofContent.Contains($expectedMarker)) {
        $isMatch = $true
        $matchedType = "EXPECTED"
    } elseif ($altMarker -and $proofContent.Contains($altMarker)) {
        $isMatch = $true
        $matchedType = "ALTERNATIVE"
    }

    # Teardown sandbox
    Remove-Item -Path $sandboxDir -Recurse -Force -ErrorAction SilentlyContinue

    if ($proofFound -and $isMatch) {
        return [PSCustomObject]@{
            SampleId = $sid
            Name = $contractJson.name
            Group = $contractJson.group
            Status = "PASSED_TEST"
            ExitCode = $actualExit
            ExecutionTimeMs = [int]$swExec.ElapsedMilliseconds
            ProofMatched = $true
            MatchedMarker = $matchedType
            Error = $null
        }
    } else {
        return [PSCustomObject]@{
            SampleId = $sid
            Name = $contractJson.name
            Group = $contractJson.group
            Status = "UNDETERMINED"
            ExitCode = $actualExit
            ExecutionTimeMs = [int]$swExec.ElapsedMilliseconds
            ProofMatched = $false
            MatchedMarker = $null
            Error = "Proof missing or marker mismatch. Read: '$proofContent'"
        }
    }
}

# --- MAIN EXECUTION FLOW ---
$ResolvedManifest = (Resolve-Path "$WorkspaceRoot/$Manifest").Path
$manifestData = Get-Content -LiteralPath $ResolvedManifest -Raw -Encoding UTF8 | ConvertFrom-Json

$samplesToRun = @()
if ($SampleId) {
    $matched = $manifestData.samples | Where-Object { $_.id -eq $SampleId }
    if ($matched) {
        $samplesToRun += $matched
    } else {
        # Check if contract exists on disk even if not in manifest (e.g. ad-hoc variants or test cases)
        $adhocContract = Join-Path $ResolvedDatasetDir "$SampleId.json"
        if (Test-Path $adhocContract) {
            $samplesToRun += [PSCustomObject]@{
                id = $SampleId
                contract = "$SampleId.json"
            }
        } else {
            Write-Error "Sample ID '$SampleId' not found in manifest or on disk ($adhocContract)."
            exit 1
        }
    }
} elseif ($Group) {
    $samplesToRun = $manifestData.samples | Where-Object { $_.group -eq $Group }
} elseif ($All) {
    $samplesToRun = $manifestData.samples
} else {
    Write-Host "Usage: .\verifier.ps1 [-SampleId <id>] [-All] [-Group <group_name>] [-JsonOutput]" -ForegroundColor Yellow
    exit 0
}

Write-Host "`n[C1 BEHAVIOR VERIFIER] Initiating verification on $($samplesToRun.Count) samples..." -ForegroundColor Cyan
Write-Host "Compiler Environment: MSVC (vcvars: $(if ($VcvarsPath) { 'Detected' } else { 'PATH' }))`n"

$results = @()
$counter = 0

foreach ($s in $samplesToRun) {
    $counter++
    $contractPath = Join-Path $ResolvedDatasetDir $s.contract
    $res = Test-SampleContract -ContractFile $contractPath
    $results += $res

    $color = switch ($res.Status) {
        "PASSED_TEST"  { "Green" }
        "UNDETERMINED" { "Yellow" }
        "BUILD_FAIL"   { "Red" }
        Default        { "White" }
    }
    $icon = switch ($res.Status) {
        "PASSED_TEST"  { "[PASS]" }
        "UNDETERMINED" { "[UNDET]" }
        "BUILD_FAIL"   { "[FAIL]" }
    }

    Write-Host ("{0,3}/{1,3} {2,-7} {3,-32} -> {4,-13} ({5}ms)" -f $counter, $samplesToRun.Count, $icon, $res.SampleId, $res.Status, $res.ExecutionTimeMs) -ForegroundColor $color
    if ($res.Error) {
        Write-Host ("      Error: " + $res.Error) -ForegroundColor DarkGray
    }
}

$passedCount = @($results | Where-Object { $_.Status -eq "PASSED_TEST" }).Count
$undetCount = @($results | Where-Object { $_.Status -eq "UNDETERMINED" }).Count
$failCount = @($results | Where-Object { $_.Status -eq "BUILD_FAIL" }).Count
$total = @($results).Count

Write-Host "`n" -NoNewline
Write-Host ("=" * 75) -ForegroundColor Cyan
Write-Host "C1 BEHAVIOR VERIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 75) -ForegroundColor Cyan
Write-Host ("Total Tested   : " + $total)
Write-Host ("PASSED_TEST    : {0} ({1:P1})" -f $passedCount, ($passedCount / $total)) -ForegroundColor Green
Write-Host ("UNDETERMINED   : " + $undetCount) -ForegroundColor Yellow
Write-Host ("BUILD_FAIL     : " + $failCount) -ForegroundColor Red
Write-Host ("=" * 75) -ForegroundColor Cyan

if ($JsonOutput) {
    $results | ConvertTo-Json -Depth 4
}

if ($passedCount -eq $total) {
    exit 0
} else {
    exit 1
}
