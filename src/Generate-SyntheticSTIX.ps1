# Generate-SyntheticSTIX.ps1
# Dynamically generates synthetic STIX/TAXII v2.1 compliant threat intelligence

function Generate-SyntheticSTIX {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$OutputFile = ".\SyntheticTI.json",
        
        [Parameter(Mandatory = $false)]
        [int]$IndicatorCount = 10,
        
        [Parameter(Mandatory = $false)]
        [switch]$ShowDetails
    )
    
    # Helper function to generate random IPs
    function Get-RandomIP {
        return "{0}.{1}.{2}.{3}" -f (Get-Random -Min 1 -Max 255), 
                                    (Get-Random -Min 0 -Max 255), 
                                    (Get-Random -Min 0 -Max 255), 
                                    (Get-Random -Min 1 -Max 254)
    }
    
    # Helper function to generate random domains
    function Get-RandomDomain {
        $prefixes = @('malware', 'c2', 'phish', 'exploit', 'dropper', 'payload', 'beacon', 'cobra', 'viper', 'shadow')
        $middles = @('control', 'command', 'download', 'update', 'sync', 'data', 'info', 'stats', 'telemetry', 'metrics')
        $tlds = @('.com', '.net', '.org', '.info', '.biz', '.io', '.tech', '.xyz', '.online', '.site')
        
        $prefix = $prefixes | Get-Random
        $middle = $middles | Get-Random
        $tld = $tlds | Get-Random
        
        return "$prefix-$middle$(Get-Random -Min 100 -Max 999)$tld"
    }
    
    # Helper function to generate random URLs
    function Get-RandomURL {
        $domain = Get-RandomDomain
        $paths = @('/api/beacon', '/update/check', '/data/sync', '/config/get', '/task/poll', '/cmd/exec', '/file/upload', '/log/send')
        $path = $paths | Get-Random
        $params = @('', '?id=', '?session=', '?key=', '?token=', '?user=')
        $param = $params | Get-Random
        
        if ($param) {
            # Generate a simple random string instead of using System.Web.Security
            $randomString = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object {[char]$_})
            $param += $randomString
        }
        
        return "https://$domain$path$param"
    }
    
    # Helper function to generate random MD5 hash
    function Get-RandomHash {
        $bytes = New-Object byte[] 16
        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
        return ($bytes | ForEach-Object { $_.ToString("x2") }) -join ''
    }
    
    # Helper function to generate STIX UUID
    function Get-STIXUUID {
        param([string]$prefix)
        return "$prefix--$([guid]::NewGuid().ToString())"
    }
    
    # Get current timestamp in STIX format
    $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $validFrom = (Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    
    # Initialize STIX objects array
    $stixObjects = @()
    
    # Generate indicators
    $indicatorTypes = @('ipv4', 'domain', 'url', 'file-hash')
    $malwareFamilies = @('Emotet', 'TrickBot', 'Qbot', 'Cobalt Strike', 'Metasploit', 'Mimikatz', 'BloodHound', 'Empire', 'PsExec')
    $threatActors = @('APT28', 'APT29', 'Lazarus', 'FIN7', 'Carbanak', 'DarkHydrus', 'OilRig', 'MuddyWater', 'Turla')
    
    # Kill chain phases for indicators
    $killChainPhases = @(
        @{ kill_chain_name = "lockheed-martin-cyber-kill-chain"; phase_name = "reconnaissance" },
        @{ kill_chain_name = "lockheed-martin-cyber-kill-chain"; phase_name = "weaponization" },
        @{ kill_chain_name = "lockheed-martin-cyber-kill-chain"; phase_name = "delivery" },
        @{ kill_chain_name = "lockheed-martin-cyber-kill-chain"; phase_name = "exploitation" },
        @{ kill_chain_name = "lockheed-martin-cyber-kill-chain"; phase_name = "installation" },
        @{ kill_chain_name = "lockheed-martin-cyber-kill-chain"; phase_name = "command-and-control" },
        @{ kill_chain_name = "lockheed-martin-cyber-kill-chain"; phase_name = "actions-on-objectives" }
    )
    
    Write-Host "Generating $IndicatorCount synthetic indicators..." -ForegroundColor Cyan
    
    # Create identity objects for threat actors (used in relationships)
    $identityObjects = @()
    foreach ($actor in $threatActors[0..2]) {  # Create first 3 actors as identity objects
        $identity = @{
            type = "identity"
            spec_version = "2.1"
            id = Get-STIXUUID "identity"
            created = $now
            modified = $now
            name = $actor
            description = "Threat actor group $actor - Known for sophisticated cyber operations"
            identity_class = "group"
            pattern = "[identity:name = '$actor']"  # Adding pattern for consistency
            pattern_type = "stix"
            valid_from = $validFrom
        }
        $stixObjects += $identity
        $identityObjects += $identity
        
        if ($ShowDetails) {
            Write-Host "  Generated Identity: $($identity.name)" -ForegroundColor Gray
        }
    }
    
    # Generate indicators with all required fields
    $indicatorIds = @()
    for ($i = 1; $i -le $IndicatorCount; $i++) {
        $type = $indicatorTypes | Get-Random
        $malware = $malwareFamilies | Get-Random
        $actor = $threatActors | Get-Random
        $confidence = Get-Random -Min 70 -Max 100
        
        # Base indicator with all required fields
        $indicator = @{
            type = "indicator"
            spec_version = "2.1"
            id = Get-STIXUUID "indicator"
            created = $now
            modified = $now
            valid_from = $validFrom
            pattern_type = "stix"
            labels = @("malicious-activity")
            confidence = $confidence
        }
        
        # Add kill chain phases based on indicator type
        switch ($type) {
            'ipv4' {
                $ip = Get-RandomIP
                $indicator.pattern = "[ipv4-addr:value = '$ip']"
                $indicator.name = "Malicious IP - $malware C2"
                $indicator.description = "IP address associated with $malware command and control infrastructure. Threat actor: $actor. This IP has been observed in active campaigns."
                $indicator.kill_chain_phases = @(
                    $killChainPhases[5]  # command-and-control
                )
            }
            'domain' {
                $domain = Get-RandomDomain
                $indicator.pattern = "[domain-name:value = '$domain']"
                $indicator.name = "Malicious Domain - $malware"
                $indicator.description = "Domain used by $malware for C2 communications. Associated with threat actor: $actor. Active infrastructure component."
                $indicator.kill_chain_phases = @(
                    $killChainPhases[5],  # command-and-control
                    $killChainPhases[4]   # installation
                )
            }
            'url' {
                $url = Get-RandomURL
                $indicator.pattern = "[url:value = '$url']"
                $indicator.name = "Malicious URL - $malware Dropper"
                $indicator.description = "URL serving $malware payload. Threat actor: $actor campaign. This URL is part of an active phishing/delivery campaign."
                $indicator.kill_chain_phases = @(
                    $killChainPhases[2],  # delivery
                    $killChainPhases[3]   # exploitation
                )
            }
            'file-hash' {
                $hash = Get-RandomHash
                $indicator.pattern = "[file:hashes.MD5 = '$hash']"
                $indicator.name = "Malicious File Hash - $malware"
                $indicator.description = "MD5 hash of $malware variant. Associated with $actor operations. This file has been used in targeted attacks."
                $indicator.kill_chain_phases = @(
                    $killChainPhases[1],  # weaponization
                    $killChainPhases[2],  # delivery
                    $killChainPhases[4]   # installation
                )
            }
        }
        
        $stixObjects += $indicator
        $indicatorIds += $indicator.id
        
        if ($ShowDetails) {
            Write-Host "  Generated: $($indicator.name)" -ForegroundColor Gray
        }
    }
    
    # Add attack patterns with all required fields
    $attackPatterns = @(
        @{
            name = "Spearphishing Attachment"
            description = "Adversaries send spearphishing emails with malicious attachments to gain initial access"
            external_id = "T1566.001"
            phases = @($killChainPhases[2])  # delivery
        },
        @{
            name = "Command and Scripting Interpreter"
            description = "Adversaries abuse command and script interpreters to execute commands, scripts, or binaries"
            external_id = "T1059"
            phases = @($killChainPhases[3], $killChainPhases[4])  # exploitation, installation
        },
        @{
            name = "Remote System Discovery"
            description = "Adversaries attempt to get a listing of other systems by IP address that may share network resources"
            external_id = "T1018"
            phases = @($killChainPhases[0])  # reconnaissance
        },
        @{
            name = "PowerShell"
            description = "Adversaries may abuse PowerShell commands and scripts for execution of malicious code"
            external_id = "T1059.001"
            phases = @($killChainPhases[3], $killChainPhases[4])  # exploitation, installation
        },
        @{
            name = "Credential Dumping"
            description = "Adversaries may attempt to dump credentials to obtain account login information in plaintext"
            external_id = "T1003"
            phases = @($killChainPhases[6])  # actions-on-objectives
        }
    )
    
    $attackPatternIds = @()
    foreach ($ap in $attackPatterns) {
        $attackPattern = @{
            type = "attack-pattern"
            spec_version = "2.1"
            id = Get-STIXUUID "attack-pattern"
            created = $now
            modified = $now
            name = $ap.name
            description = $ap.description
            pattern = "[attack-pattern:name = '$($ap.name)']"  # Adding pattern for consistency
            pattern_type = "stix"
            valid_from = $validFrom
            kill_chain_phases = $ap.phases
            external_references = @(
                @{
                    source_name = "mitre-attack"
                    external_id = $ap.external_id
                    url = "https://attack.mitre.org/techniques/$($ap.external_id)/"
                }
            )
        }
        $stixObjects += $attackPattern
        $attackPatternIds += $attackPattern.id
        
        if ($ShowDetails) {
            Write-Host "  Generated Attack Pattern: $($attackPattern.name)" -ForegroundColor Gray
        }
    }
    
    # Create relationships with all required fields
    $relationshipTypes = @("indicates", "uses")
    for ($i = 0; $i -lt 5; $i++) {
        if ($indicatorIds.Count -gt 0 -and $attackPatternIds.Count -gt 0) {
            $relType = $relationshipTypes | Get-Random
            $sourceId = $indicatorIds | Get-Random
            $targetId = $attackPatternIds | Get-Random
            
            $relationship = @{
                type = "relationship"
                spec_version = "2.1"
                id = Get-STIXUUID "relationship"
                created = $now
                modified = $now
                name = "Relationship: $relType"
                description = "This relationship shows that the indicator $relType the attack pattern"
                pattern = "[relationship:type = '$relType']"
                pattern_type = "stix"
                valid_from = $validFrom
                relationship_type = $relType
                source_ref = $sourceId
                target_ref = $targetId
            }
            $stixObjects += $relationship
            
            if ($ShowDetails) {
                Write-Host "  Generated Relationship: $($relationship.relationship_type)" -ForegroundColor Gray
            }
        }
    }
    
    # Create relationships between indicators and identities (threat actors)
    for ($i = 0; $i -lt 3; $i++) {
        if ($indicatorIds.Count -gt 0 -and $identityObjects.Count -gt 0) {
            $sourceId = $indicatorIds | Get-Random
            $targetIdentity = $identityObjects | Get-Random
            
            $relationship = @{
                type = "relationship"
                spec_version = "2.1"
                id = Get-STIXUUID "relationship"
                created = $now
                modified = $now
                name = "Relationship: attributed-to"
                description = "This indicator is attributed to threat actor $($targetIdentity.name)"
                pattern = "[relationship:type = 'attributed-to']"
                pattern_type = "stix"
                valid_from = $validFrom
                relationship_type = "attributed-to"
                source_ref = $sourceId
                target_ref = $targetIdentity.id
            }
            $stixObjects += $relationship
            
            if ($ShowDetails) {
                Write-Host "  Generated Relationship: attributed-to $($targetIdentity.name)" -ForegroundColor Gray
            }
        }
    }
    
    # Create the final STIX bundle with STEELCAGE.AI sourcesystem
    $stixBundle = @{
        sourcesystem = "STEELCAGE.AI X-GEN TI PLATFORM"
        stixobjects = $stixObjects
    }
    
    # Save to file
    try {
        $stixBundle | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputFile -Encoding UTF8
        Write-Host "✓ Successfully generated $($stixObjects.Count) STIX objects" -ForegroundColor Green
        Write-Host "  Output saved to: $OutputFile" -ForegroundColor Gray
        
        # Display summary
        $summary = $stixObjects | Group-Object -Property type | Select-Object Name, Count
        Write-Host "`nSummary:" -ForegroundColor Yellow
        foreach ($item in $summary) {
            Write-Host "  $($item.Name): $($item.Count)" -ForegroundColor White
        }
        
        # Verify all objects have required fields
        Write-Host "`nVerifying required fields..." -ForegroundColor Cyan
        $requiredFields = @('type', 'id', 'pattern', 'pattern_type', 'created', 'modified', 'name', 'description', 'spec_version', 'valid_from')
        $allValid = $true
        
        foreach ($obj in $stixObjects) {
            foreach ($field in $requiredFields) {
                if (-not $obj.$field) {
                    Write-Warning "Object $($obj.id) missing field: $field"
                    $allValid = $false
                }
            }
        }
        
        if ($allValid) {
            Write-Host "✓ All objects contain required fields" -ForegroundColor Green
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to save STIX bundle: $_"
        return $false
    }
}

# Execute if run directly
if ($MyInvocation.InvocationName -ne '.') {
    Generate-SyntheticSTIX -IndicatorCount 15 -ShowDetails
}
