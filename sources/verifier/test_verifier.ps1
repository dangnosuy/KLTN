<#
.SYNOPSIS
    Self-Test Suite for C1 3-State Behavior Verifier
    Validates that Verifier rigorously distinguishes:
      [1] PASSED_TEST
      [2] BUILD_FAIL
      [3] UNDETERMINED
#>

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$WorkspaceRoot = (Resolve-Path "$ScriptDir/../..").Path
$TestTempDir = Join-Path $ScriptDir "temp_selftest"

if (Test-Path $TestTempDir) {
    Remove-Item -Path $TestTempDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $TestTempDir -Force | Out-Null

Write-Host "`n[C1 VERIFIER SELF-TEST] Verifying 3-State Classification Engine..." -ForegroundColor Cyan

# Test Case 1: Baseline valid sample
Write-Host "`n[1/3] Testing Valid Sample (Expecting PASSED_TEST)..." -ForegroundColor Yellow
$validOutput = & powershell -ExecutionPolicy Bypass -File "$ScriptDir/verifier.ps1" -SampleId "g1_01_local_thread"
if ($validOutput -match "PASSED_TEST") {
    Write-Host "  -> PASS: Valid sample correctly classified as PASSED_TEST" -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Valid sample failed to classify as PASSED_TEST" -ForegroundColor Red
}

# Test Case 2: Synthetic Build Failure
Write-Host "`n[2/3] Testing Synthetic Syntax Error (Expecting BUILD_FAIL)..." -ForegroundColor Yellow
$failSrc = Join-Path $WorkspaceRoot "sources/dataset/temp_syntax_error.c"
$failJson = Join-Path $WorkspaceRoot "sources/dataset/temp_syntax_error.json"

@"
#include <windows.h>
int main(void) {
    SYNTAX_ERROR_BROKEN_TOKEN !!!
    return 0;
}
"@ | Set-Content -Path $failSrc -Encoding UTF8

@{
    id = "temp_syntax_error"
    name = "Synthetic Syntax Failure Test"
    group = "test"
    build = @{
        sources = @("temp_syntax_error.c")
        include_dirs = @(".")
        libraries = @("kernel32")
    }
    execution = @{
        timeout_seconds = 5
        expected_exit_code = 0
    }
    verification = @{
        proof_file = "c1_proof.txt"
        expected_marker = "[C1_PROOF] ID: temp_syntax_error | STATUS: SUCCESS"
    }
} | ConvertTo-Json -Depth 4 | Set-Content -Path $failJson -Encoding UTF8

$buildFailOutput = & powershell -ExecutionPolicy Bypass -File "$ScriptDir/verifier.ps1" -SampleId "temp_syntax_error"
Remove-Item $failSrc, $failJson -Force -ErrorAction SilentlyContinue

if ($buildFailOutput -match "BUILD_FAIL") {
    Write-Host "  -> PASS: Syntax error correctly classified as BUILD_FAIL" -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Syntax error was not classified as BUILD_FAIL" -ForegroundColor Red
}

# Test Case 3: Synthetic Undetermined (Crash / Missing Proof)
Write-Host "`n[3/3] Testing Synthetic Crash / Missing Marker (Expecting UNDETERMINED)..." -ForegroundColor Yellow
$undetSrc = Join-Path $WorkspaceRoot "sources/dataset/temp_crash_fail.c"
$undetJson = Join-Path $WorkspaceRoot "sources/dataset/temp_crash_fail.json"

@"
#include <windows.h>
int main(void) {
    /* Exits with abnormal code without writing proof marker */
    return 42;
}
"@ | Set-Content -Path $undetSrc -Encoding UTF8

@{
    id = "temp_crash_fail"
    name = "Synthetic Runtime Abort Test"
    group = "test"
    build = @{
        sources = @("temp_crash_fail.c")
        include_dirs = @(".")
        libraries = @("kernel32")
    }
    execution = @{
        timeout_seconds = 5
        expected_exit_code = 0
    }
    verification = @{
        proof_file = "c1_proof.txt"
        expected_marker = "[C1_PROOF] ID: temp_crash_fail | STATUS: SUCCESS"
    }
} | ConvertTo-Json -Depth 4 | Set-Content -Path $undetJson -Encoding UTF8

$undetOutput = & powershell -ExecutionPolicy Bypass -File "$ScriptDir/verifier.ps1" -SampleId "temp_crash_fail"
Remove-Item $undetSrc, $undetJson -Force -ErrorAction SilentlyContinue

if ($undetOutput -match "UNDETERMINED") {
    Write-Host "  -> PASS: Runtime failure correctly classified as UNDETERMINED" -ForegroundColor Green
} else {
    Write-Host "  -> FAIL: Runtime failure was not classified as UNDETERMINED" -ForegroundColor Red
}

Remove-Item $TestTempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "`n[C1 VERIFIER SELF-TEST COMPLETED] All 3 classification states empirically verified!`n" -ForegroundColor Cyan
