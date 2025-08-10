# Test-TIUploadAPI.ps1
# PowerShell function to test Microsoft Sentinel Threat Intelligence Upload API
# Based on Microsoft documentation: https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api

function Test-TI2UploadAPI {
<#
.SYNOPSIS
    Tests uploading STIX indicators to Microsoft Sentinel Threat Intelligence API
    Reads configuration from .env file and uses client secret authentication
    
.DESCRIPTION
    This function reads Azure credentials from a .env file, creates a test STIX indicator,
    and attempts to upload it to Microsoft Sentinel using different API patterns to find
    the working configuration.
    
.PARAMETER EnvFile
    Path to the .env file containing Azure credentials. Defaults to .\.env
    
.PARAMETER ShowToken
    If specified, displays a masked version of the access token for debugging
    
.PARAMETER TestAllPatterns
    If specified, tests all patterns even after finding a working one
    
.EXAMPLE
    Test-TIUploadAPI
    
.EXAMPLE
    Test-TIUploadAPI -EnvFile "C:\config\.env" -ShowToken
    
.EXAMPLE
    Test-TIUploadAPI -TestAllPatterns
    
.NOTES
    Requires: PowerShell 5.1 or higher
    Optional: MSAL.PS module (will use direct REST if not available)
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$EnvFile = ".\.env",

        [Parameter(Mandatory = $false)]
        [string]$TIFilePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowToken,
        
        [Parameter(Mandatory = $false)]
        [switch]$TestAllPatterns
    )

    # Helper function to read .env file
    function Read-EnvFile {
        param (
            [string]$Path
        )
        
        $envVars = @{}
        
        if (Test-Path $Path) {
            Get-Content $Path | ForEach-Object {
                if ($_ -match '^([^#][^=]+)=(.*)$') {
                    $key = $matches[1].Trim()
                    $value = $matches[2].Trim()
                    # Remove quotes if present
                    $value = $value -replace '^["'']|["'']$', ''
                    $envVars[$key] = $value
                }
            }
        } else {
            Write-Error "Environment file not found: $Path"
            return $null
        }
        
        return $envVars
    }

    # Helper function to get access token using client secret (no MSAL.PS required)
    function Get-AzureTokenWithSecret {
        param (
            [string]$TenantId,
            [string]$ClientId,
            [string]$ClientSecret,
            [string]$Scope,
            [string]$AuthorityUrl
        )
        
        $tokenEndpoint = "$AuthorityUrl/$TenantId/oauth2/v2.0/token"
        
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = $Scope
        }
        
        try {
            $response = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        } catch {
            Write-Error "Failed to acquire token: $_"
            return $null
        }
    }    

    # Main execution starts here
    Write-Host "=" -ForegroundColor Cyan -NoNewline
    Write-Host ("=" * 59) -ForegroundColor Cyan
    Write-Host "Microsoft Sentinel Threat Intelligence Upload API Test" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor Cyan

    # Read environment variables
    Write-Host "`nReading configuration from: $EnvFile" -ForegroundColor Gray
    $env = Read-EnvFile -Path $EnvFile
    
    if (-not $env) {
        Write-Error "Failed to read environment file"
        return
    }

    # Extract required variables
    $clientId = $env["AZURE_CLIENT_ID"]
    $clientSecret = $env["AZURE_CLIENT_SECRET"]
    $tenantId = $env["AZURE_TENANT_ID"]
    $workspaceId = $env["AZURE_WORKSPACE_ID"]
    $subscriptionId = $env["AZURE_SUBSCRIPTION_ID"]
    $resourceGroup = $env["AZURE_RESOURCE_GROUP_NAME"]
    $workspaceName = $env["AZURE_WORKSPACE_NAME"]
    $azureCloud = if ($env["AZURE_CLOUD"]) { $env["AZURE_CLOUD"].ToUpper() } else { "COMMERCIAL" }

    # Validate required variables
    $missingVars = @()
    if (-not $clientId) { $missingVars += "AZURE_CLIENT_ID" }
    if (-not $clientSecret) { $missingVars += "AZURE_CLIENT_SECRET" }
    if (-not $tenantId) { $missingVars += "AZURE_TENANT_ID" }
    if (-not $workspaceId) { $missingVars += "AZURE_WORKSPACE_ID" }
    
    if ($missingVars.Count -gt 0) {
        Write-Error "Missing required environment variables: $($missingVars -join ', ')"
        return
    }

    # Display configuration (mask sensitive values)
    Write-Host "`nConfiguration:" -ForegroundColor Yellow
    Write-Host "  Azure Cloud: $azureCloud" -ForegroundColor White
    Write-Host "  Tenant ID: $tenantId" -ForegroundColor White
    Write-Host "  Client ID: $clientId" -ForegroundColor White
    $maskedSecret = if ($clientSecret.Length -gt 8) { 
        $clientSecret.Substring(0, 4) + "****" + $clientSecret.Substring($clientSecret.Length - 4) 
    } else { 
        "****" 
    }
    Write-Host "  Client Secret: $maskedSecret" -ForegroundColor White
    Write-Host "  Workspace ID: $workspaceId" -ForegroundColor White
    if ($subscriptionId) { Write-Host "  Subscription ID: $subscriptionId" -ForegroundColor White }
    if ($resourceGroup) { Write-Host "  Resource Group: $resourceGroup" -ForegroundColor White }
    if ($workspaceName) { Write-Host "  Workspace Name: $workspaceName" -ForegroundColor White }

    # Set cloud-specific endpoints
    if ($azureCloud -eq "USGOV") {
        $authorityUrl = "https://login.microsoftonline.us"
        $scope = "https://management.usgovcloudapi.net/.default"
        $managementUrl = "https://management.usgovcloudapi.net"
        $sentinelApiUrl = "https://sentinelus.azure-api.net"  # US Gov Sentinel API
    } else {
        $authorityUrl = "https://login.microsoftonline.com"
        $scope = "https://management.azure.com/.default"
        $managementUrl = "https://management.azure.com"
        $sentinelApiUrl = "https://sentinelus.azure-api.net"  # Commercial also uses sentinelus
    }

    Write-Host "`nEndpoints:" -ForegroundColor Yellow
    Write-Host "  Authority: $authorityUrl" -ForegroundColor White
    Write-Host "  Scope: $scope" -ForegroundColor White
    Write-Host "  Management API: $managementUrl" -ForegroundColor White
    Write-Host "  Sentinel API: $sentinelApiUrl" -ForegroundColor White

    # Check if MSAL.PS is available
    $msalAvailable = $null -ne (Get-Module -ListAvailable -Name MSAL.PS)

    if ($msalAvailable) {
        Write-Host "`n✓ MSAL.PS module found" -ForegroundColor Green
        Import-Module MSAL.PS -ErrorAction SilentlyContinue
        
        # Get token using MSAL.PS
        Write-Host "Acquiring token using MSAL.PS..." -ForegroundColor Gray
        
        $connectionDetails = @{
            TenantId     = $tenantId
            ClientId     = $clientId
            ClientSecret = (ConvertTo-SecureString $clientSecret -AsPlainText -Force)
            Scope        = $scope
        }
        
        try {
            $tokenResponse = Get-MsalToken @connectionDetails # -ForceRefresh
            $token = $tokenResponse.AccessToken
            $authHeader = $tokenResponse.CreateAuthorizationHeader()
        } catch {
            Write-Error "Failed to acquire token with MSAL.PS: $_"
            return
        }
    } else {
        Write-Host "`n! MSAL.PS module not found, using direct REST" -ForegroundColor Yellow
        Write-Host "  To install MSAL.PS: Install-Module -Name MSAL.PS -Scope CurrentUser" -ForegroundColor Gray
        
        # Get token using direct REST
        Write-Host "`nAcquiring token using REST API..." -ForegroundColor Gray
        $token = Get-AzureTokenWithSecret -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret -Scope $scope -AuthorityUrl $authorityUrl
        
        if (-not $token) {
            Write-Error "Failed to acquire access token"
            return
        }
        
        $authHeader = "Bearer $token"
    }

    Write-Host "✓ Token acquired successfully" -ForegroundColor Green
    
    if ($ShowToken) {
        $maskedToken = if ($token.Length -gt 20) { 
            $token.Substring(0, 10) + "..." + $token.Substring($token.Length - 10) 
        } else { 
            "***" 
        }
        Write-Host "  Token (masked): $maskedToken" -ForegroundColor Gray
    }

    # Load indicators from file (default: TIObjects.json in script directory, or path provided via -TIFilePath)
    if (-not $TIFilePath) {
        $TIFilePath = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath "TIObjects.json"
    }
    Write-Host "`nLoading STIX objects from: $TIFilePath" -ForegroundColor Gray
    if (-not (Test-Path $TIFilePath)) {
        Write-Error "JSON file not found: $TIFilePath"
        return
    }
    try {
        $jsonContent = Get-Content -Path $TIFilePath -Raw | ConvertFrom-Json
    } catch {
        Write-Error "Failed to parse JSON file: $_"
        return
    }
    #if (-not $jsonContent.indicators) {
    #    Write-Error "JSON file does not contain an 'indicators' array."
    #    return
    #}
    Write-Host "✓ Loaded $($jsonContent.stixobjects.Count) indicator(s) from JSON file" -ForegroundColor Green

    # Prepare request bodies from JSON
    $requestBodyWithIndicators = @{
        sourcesystem = $jsonContent.sourcesystem
        stixobjects  = $jsonContent.stixobjects
    }
    <#
    $requestBodyWithValue = @{
        sourcesystem = $jsonContent.sourcesystem
        stixobjects  = $jsonContent.stixobjects
    }
    #>

    Write-Host "Test Objects (Microsoft Format):" -ForegroundColor Yellow
    #$testObjects | ConvertTo-Json -Depth 10 | Write-Host -ForegroundColor Gray

    # Prepare headers
    $headers = @{
        "Authorization" = $authHeader
        "Content-Type"  = "application/json"
    }

    # Test different API patterns
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "Testing Microsoft Sentinel V2 API Endpoints:" -ForegroundColor Yellow
    Write-Host ("=" * 60) -ForegroundColor Cyan

    # API version for V2 Upload Indicators API
    $apiVersion = "2025-06-01"

    $testConfigs = @()    
    # Primary endpoint - Direct Sentinel API with indicators array
    if ($workspaceId) {
        # Determine the correct Sentinel API URL based on cloud
        $sentinelDirectUrl = if ($azureCloud -eq "USGOV") {
            "https://sentinelus.azure-api.net"
        } else {
            "https://sentinelus.azure-api.net"
        }
        
        $testConfigs += @{
            Name = "V2 Direct Sentinel API (PREVIEW API - with required 'stixobjects' array)"
            Url = "https://api.ti.sentinel.azure.com/workspaces/$workspaceId/threat-intelligence-stix-objects:upload?api-version=2024-02-01-preview"
            Body = $requestBodyWithIndicators  # Using "indicators" as the JSON array name
            Headers = $headers
        }
        <#
        @{
            Name = "V2 Direct Sentinel API (Legacy - with 'indicators' array)"
            Url = "$sentinelApiUrl/workspaces/$workspaceId/threatintelligenceindicators:upload?api-version=2022-07-01"
            Body = $requestBodyWithIndicators  # Using "indicators" as the JSON array name
            Headers = $headers
        }
        #>
    }
    
    # Add Management API endpoint if we have the required variables
    <#
    if ($subscriptionId -and $resourceGroup -and $workspaceName) {
        $testConfigs += @{
            Name = "V2 Management API Upload Endpoint (with 'indicators' array)"
            Url = "$managementUrl/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/upload?api-version=$apiVersion"
            Body = $requestBodyWithIndicators
            Headers = $headers
        }
        
        $testConfigs += @{
            Name = "V2 Management API Upload Endpoint (with 'value' array)"
            Url = "$managementUrl/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/upload?api-version=$apiVersion"
            Body = $requestBodyWithValue
            Headers = $headers
        }
    }
    #>
    
    if ($testConfigs.Count -eq 0) {
        Write-Host "❌ Error: No endpoints to test. Missing required variables:" -ForegroundColor Red
        Write-Host "  Required: AZURE_WORKSPACE_ID" -ForegroundColor Gray
        Write-Host "  Optional but recommended:" -ForegroundColor Gray
        Write-Host "    - AZURE_SUBSCRIPTION_ID" -ForegroundColor Gray
        Write-Host "    - AZURE_RESOURCE_GROUP_NAME" -ForegroundColor Gray  
        Write-Host "    - AZURE_WORKSPACE_NAME" -ForegroundColor Gray
        return
    }

    $success = $false
    $workingConfig = $null

    foreach ($config in $testConfigs) {
        Write-Host "`n$($config.Name)" -ForegroundColor Cyan
        Write-Host "  URL: $($config.Url)" -ForegroundColor Gray
        Write-Host "  Request Body Structure:" -ForegroundColor Gray
        Write-Host "    - sourcesystem: $($config.Body.sourcesystem)" -ForegroundColor Gray
        
        if ($config.Body.indicators) {
            Write-Host "    - indicators: Array of $($config.Body.indicators.Count) indicator(s)" -ForegroundColor Green
        } elseif ($config.Body.value) {
            Write-Host "    - value: Array of $($config.Body.value.Count) indicator(s)" -ForegroundColor Yellow
        }
        
        try {
            $bodyJson = $config.Body | ConvertTo-Json -Depth 10 -Compress
            
            # Log first 500 chars of body for debugging
            $bodyPreview = if ($bodyJson.Length -gt 700) { $bodyJson.Substring(0, 700) + "..." } else { $bodyJson }
            Write-Host "  Body Preview: $bodyPreview" -ForegroundColor DarkGray
            
            # Use custom headers if provided, otherwise use default
            $requestHeaders = if ($config.Headers) { $config.Headers } else { $headers }

            $response = Invoke-RestMethod -Uri $config.Url -Headers $requestHeaders -Body $bodyJson -Method POST -ContentType "application/json" #-SkipHttpErrorCheck

            Write-Host ("  Status: {0} {1}" -f [int]$response.StatusCode, $response.StatusDescription)
            Write-Host ("  Response body: $($response.Content)")

            Write-Host "  ✓ SUCCESS! Status: 200/202" -ForegroundColor Green
            Write-Host "  Response:" -ForegroundColor Gray
            $response | ConvertTo-Json -Depth 10 | Write-Host -ForegroundColor Gray
            
            $arrayName = if ($config.Body.indicators) { "indicators" } else { "stixobjects" }
            $workingConfig = @{
                Pattern = $config.Name
                Url = $config.Url
                BodyFormat = "Object with 'sourcesystem' and '$arrayName' properties"
                ArrayName = $arrayName
            }
            $success = $true
            
            if (-not $TestAllPatterns) { break }
            
        } catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            $statusDescription = $_.Exception.Response.StatusDescription
            
            if ($statusCode -eq 404) {
                Write-Host "  ✗ 404 - Not Found" -ForegroundColor Red
                Write-Host "    This endpoint may not be available or accessible" -ForegroundColor Gray
            } elseif ($statusCode -eq 400) {
                Write-Host "  ⚠ 400 - Bad Request: $statusDescription" -ForegroundColor Yellow
                try {
                    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                    $responseBody = $reader.ReadToEnd()
                    Write-Host "    Response: $($responseBody.Substring(0, [Math]::Min(500, $responseBody.Length)))" -ForegroundColor Gray
                } catch {}
            } elseif ($statusCode -eq 403) {
                Write-Host "  ✗ 403 - Forbidden (check permissions)" -ForegroundColor Red
                Write-Host "    Required role: Microsoft Sentinel Contributor" -ForegroundColor Gray
            } elseif ($statusCode -eq 401) {
                Write-Host "  ✗ 401 - Unauthorized" -ForegroundColor Red
            } else {
                Write-Host "  ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        if ($success -and -not $TestAllPatterns) { break }
    }

    Write-Host "`n" -NoNewline
    Write-Host ("=" * 60) -ForegroundColor Cyan

    if ($success) {
        Write-Host "✓ Successfully found working API configuration!" -ForegroundColor Green
        Write-Host "`nWorking Configuration:" -ForegroundColor Yellow
        Write-Host "  Pattern: $($workingConfig.Pattern)" -ForegroundColor White
        Write-Host "  API Version: $($workingConfig.ApiVersion)" -ForegroundColor White
        Write-Host "  Body Format: $($workingConfig.BodyFormat)" -ForegroundColor White
        Write-Host "  Full URL: $($workingConfig.Url)" -ForegroundColor Gray
        Write-Host "`nThe upload endpoint is working correctly." -ForegroundColor Gray
        
        # Return the working configuration
        return $workingConfig
    } else {
        Write-Host "✗ Could not find working API configuration" -ForegroundColor Red
        Write-Host "`nTroubleshooting steps:" -ForegroundColor Yellow
        Write-Host "1. Verify Microsoft Sentinel is enabled on your workspace" -ForegroundColor Gray
        Write-Host "   - Go to Azure Portal > Your Log Analytics Workspace" -ForegroundColor Gray
        Write-Host "   - Click 'Microsoft Sentinel' in the left menu" -ForegroundColor Gray
        Write-Host "   - Click 'Add' if not already enabled" -ForegroundColor Gray
        Write-Host "`n2. Check that the workspace ID is correct" -ForegroundColor Gray
        Write-Host "   Current ID: $workspaceId" -ForegroundColor Gray
        Write-Host "`n3. Ensure the app registration has proper permissions" -ForegroundColor Gray
        Write-Host "   Required role: 'Microsoft Sentinel Contributor'" -ForegroundColor Gray
        Write-Host "   Role ID: ab8e14d6-4a74-4a29-9ba8-549422addade" -ForegroundColor Gray
        Write-Host "`n4. Try different API versions or endpoints" -ForegroundColor Gray
        
        return $null
    }

    Write-Host ("=" * 60) -ForegroundColor Cyan
}
