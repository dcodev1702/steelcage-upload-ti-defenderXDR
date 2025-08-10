# Invoke-TIOrchestrator.ps1
# Orchestrates the generation and upload of synthetic threat intelligence to Microsoft Sentinel

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]$IntervalHours = 3,
    
    [Parameter(Mandatory = $false)]
    [int]$IndicatorCount = 20,
    
    [Parameter(Mandatory = $false)]
    [switch]$RunOnce
)

# Set working directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($scriptPath) {
    Set-Location $scriptPath
}

Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "Threat Intelligence Orchestrator" -ForegroundColor Yellow
Write-Host "Generates and uploads synthetic STIX/TAXII TI to Sentinel" -ForegroundColor Gray
Write-Host ("=" * 60) -ForegroundColor Cyan

# Verify required files exist
$requiredFiles = @(
    ".\Test-TI2UploadAPI.ps1",
    ".\Generate-SyntheticSTIX.ps1",
    ".\.env"
)

Write-Host "`nVerifying required files..." -ForegroundColor Cyan
foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "  ✓ Found: $file" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Missing: $file" -ForegroundColor Red
        Write-Error "Required file not found: $file"
        exit 1
    }
}

# Load the functions
Write-Host "`nLoading PowerShell modules..." -ForegroundColor Cyan
try {
    . .\Generate-SyntheticSTIX.ps1
    Write-Host "  ✓ Loaded Generate-SyntheticSTIX.ps1" -ForegroundColor Green
    
    . .\Test-TI2UploadAPI.ps1
    Write-Host "  ✓ Loaded Test-TI2UploadAPI.ps1" -ForegroundColor Green
} catch {
    Write-Error "Failed to load PowerShell modules: $_"
    exit 1
}

# Main orchestration function
function Start-TIGeneration {
    param (
        [int]$Count = 20
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $outputFile = ".\SyntheticTI_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    Write-Host "`n[$timestamp] Starting TI generation cycle" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor DarkGray
    
    # Step 1: Generate synthetic STIX data
    Write-Host "`nStep 1: Generating synthetic STIX/TAXII indicators..." -ForegroundColor Cyan
    try {
        $result = Generate-SyntheticSTIX -OutputFile $outputFile -IndicatorCount $Count
        if ($result) {
            Write-Host "  ✓ Successfully generated indicators" -ForegroundColor Green
        } else {
            throw "Generation failed"
        }
    } catch {
        Write-Error "Failed to generate synthetic TI: $_"
        return $false
    }
    
    # Step 2: Upload to Sentinel
    Write-Host "`nStep 2: Uploading indicators to Microsoft Sentinel..." -ForegroundColor Cyan
    try {
        $uploadResult = Test-TI2UploadAPI -EnvFile ".\.env" -TIFilePath $outputFile -ShowToken
        if ($uploadResult) {
            Write-Host "  ✓ Successfully uploaded to Sentinel" -ForegroundColor Green
            
            # Clean up old files (keep last 5)
            Write-Host "`nCleaning up old TI files..." -ForegroundColor Gray
            $oldFiles = Get-ChildItem -Path ".\SyntheticTI_*.json" | 
                        Sort-Object -Property LastWriteTime -Descending | 
                        Select-Object -Skip 5
            
            foreach ($oldFile in $oldFiles) {
                Remove-Item $oldFile.FullName -Force
                Write-Host "  Removed: $($oldFile.Name)" -ForegroundColor DarkGray
            }
            
            return $true
        } else {
            throw "Upload failed"
        }
    } catch {
        Write-Error "Failed to upload TI to Sentinel: $_"
        return $false
    }
}

# Main execution loop
if ($RunOnce) {
    Write-Host "`nRunning in single execution mode" -ForegroundColor Yellow
    $success = Start-TIGeneration -Count $IndicatorCount
    if ($success) {
        Write-Host "`n✓ Single execution completed successfully" -ForegroundColor Green
    } else {
        Write-Host "`n✗ Single execution failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "`nStarting continuous operation mode" -ForegroundColor Yellow
    Write-Host "  Interval: Every $IntervalHours hours" -ForegroundColor Gray
    Write-Host "  Indicators per cycle: $IndicatorCount" -ForegroundColor Gray
    Write-Host "`nPress Ctrl+C to stop" -ForegroundColor DarkGray
    
    $cycleCount = 0
    while ($true) {
        $cycleCount++
        Write-Host "`n" -NoNewline
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "CYCLE #$cycleCount" -ForegroundColor Yellow
        Write-Host ("=" * 60) -ForegroundColor Cyan
        
        $success = Start-TIGeneration -Count $IndicatorCount
        
        if ($success) {
            Write-Host "`n✓ Cycle #$cycleCount completed successfully" -ForegroundColor Green
        } else {
            Write-Host "`n⚠ Cycle #$cycleCount completed with errors" -ForegroundColor Yellow
        }
        
        # Calculate next run time
        $nextRun = (Get-Date).AddHours($IntervalHours)
        Write-Host "`nNext cycle scheduled for: $($nextRun.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
        Write-Host "Sleeping for $IntervalHours hours..." -ForegroundColor Gray
        
        # Sleep until next cycle
        Start-Sleep -Seconds ($IntervalHours * 3600)
    }
}
