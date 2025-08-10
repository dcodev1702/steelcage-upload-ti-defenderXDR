# build-local.ps1
# Build and run the container locally for testing before ACI deployment

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$Run,
    
    [Parameter(Mandatory = $false)]
    [switch]$RunOnce,
    
    [Parameter(Mandatory = $false)]
    [switch]$Shell,
    
    [Parameter(Mandatory = $false)]
    [switch]$Stop
)

$containerName = "steelcage-xgen-ti-platform-local"
$imageName = "steelcage-xgen-ti-platform"

Write-Host "=" -ForegroundColor Cyan -NoNewline
Write-Host ("=" * 59) -ForegroundColor Cyan
Write-Host "Local Docker Build, Provision, and Test" -ForegroundColor Yellow
Write-Host ("=" * 60) -ForegroundColor Cyan

if ($Stop) {
    Write-Host "`nStopping container..." -ForegroundColor Yellow
    docker stop $containerName 2>$null
    docker rm -f $containerName 2>$null
    Write-Host "✓ Container stopped and removed" -ForegroundColor Green
    exit 0
}

# Build the image
Write-Host "`nBuilding Docker image locally..." -ForegroundColor Cyan
docker build -t $imageName .

if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker build failed"
    exit 1
}

Write-Host "✓ Docker Image built successfully" -ForegroundColor Green

# Stop and remove existing container
docker stop $containerName 2>$null | Out-Null
docker rm -f $containerName 2>$null | Out-Null

if ($Run) {
    Write-Host "`nRunning container in continuous mode..." -ForegroundColor Cyan
    docker run -d `
        --name $containerName `
        -v "${PWD}/src/.env:/app/.env:ro" `
        -v "${PWD}/src:/app/src:ro" `
        $imageName
    
    Write-Host "✓ Container started" -ForegroundColor Green
    Write-Host "`nView logs with:" -ForegroundColor Yellow
    Write-Host "  docker logs -f $containerName" -ForegroundColor White
    
} elseif ($RunOnce) {
    Write-Host "`nRunning single test cycle..." -ForegroundColor Cyan
    docker run --rm `
        --name $containerName `
        -v "${PWD}/src/.env:/app/.env:ro" `
        -v "${PWD}/src:/app/src:ro" `
        $imageName `
        -RunOnce -IndicatorCount 5
        
} elseif ($Shell) {
    Write-Host "`nStarting interactive shell..." -ForegroundColor Cyan
    docker run -it --rm `
        --name $containerName `
        -v "${PWD}/src/.env:/app/.env:ro" `
        -v "${PWD}/src:/app/src:ro" `
        --entrypoint pwsh `
        $imageName
        
} else {
    Write-Host "`nDocker image built successfully. Use one of these options:" -ForegroundColor Yellow
    Write-Host "  .\provision-local-container.ps1 -Run       # Run continuously" -ForegroundColor White
    Write-Host "  .\provision-local-container.ps1 -RunOnce   # Run single cycle" -ForegroundColor White
    Write-Host "  .\provision-local-container.ps1 -Shell     # Interactive shell" -ForegroundColor White
    Write-Host "  .\provision-local-container.ps1 -Stop      # Stop container" -ForegroundColor White
}
