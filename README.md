# Synthetic Threat Intelligence Generator for Microsoft Sentinel
## Azure Container Instance Deployment

This solution generates synthetic STIX/TAXII v2.1 compliant threat intelligence and automatically uploads it to Microsoft Sentinel via REST API, designed specifically for Azure Container Instances.

## 📁 Files Overview

### Core Scripts
- **`Generate-SyntheticSTIX.ps1`** - Dynamically generates synthetic STIX/TAXII v2.1 compliant JSON objects
- **`Test-TI2UploadAPI.ps1`** - Your existing script that uploads threat intelligence to Microsoft Sentinel
- **`Invoke-TIOrchestrator.ps1`** - Main orchestration script that coordinates generation and upload

### Deployment Files
- **`Dockerfile`** - Container configuration optimized for ACI
- **`deploy-to-aci.ps1`** - PowerShell script to deploy to Azure Container Instances
- **`build-local.ps1`** - Local testing script before ACI deployment
- **`.env`** - Environment variables with Azure credentials (already exists)

## 🚀 Quick Start

### Prerequisites
- Azure subscription with Microsoft Sentinel enabled
- Azure Container Registry (ACR) configured
- Service Principal with appropriate permissions
- Docker installed locally for building images
- Azure CLI installed
- PowerShell 5.1 or higher

### Step 1: Local Testing

Test the solution locally before deploying to Azure:

```powershell
# Build and test locally
.\build-local.ps1

# Run a single test cycle
.\build-local.ps1 -RunOnce

# Run continuously (like it will in ACI)
.\build-local.ps1 -Run

# Check logs
docker logs -f synthetic-ti-generator-local

# Stop local container
.\build-local.ps1 -Stop
```

### Step 2: Deploy to Azure Container Instance

```powershell
# Build, push to ACR, and deploy to ACI
.\deploy-to-aci.ps1 -BuildAndPush -DeleteExisting

# Or deploy with custom settings
.\deploy-to-aci.ps1 `
    -ResourceGroupName "secops" `
    -ContainerName "synthetic-ti-generator" `
    -Location "eastus" `
    -BuildAndPush `
    -DeleteExisting
```

## 📊 How It Works

1. **Container starts** in Azure Container Instance
2. **Every 3 hours** (configurable):
   - Generates ~20 synthetic STIX indicators
   - Saves to timestamped JSON file
   - Calls `Test-TI2UploadAPI.ps1` with generated file
   - Uploads to Microsoft Sentinel
   - Cleans up old files
3. **Continuous operation** with automatic restart on failure

## 🔧 Configuration

### Environment Variables
The solution reads from `.env` file and passes these as secure environment variables to ACI:

```bash
# Required Azure credentials
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-secret
AZURE_TENANT_ID=your-tenant-id
AZURE_WORKSPACE_ID=your-workspace-id
AZURE_SUBSCRIPTION_ID=your-subscription
AZURE_RESOURCE_GROUP_NAME=your-rg
AZURE_WORKSPACE_NAME=your-workspace
AZURE_CLOUD=COMMERCIAL

# ACR credentials
ACR_USERNAME=your-acr-username
ACR_PASSWORD=your-acr-password
ACR_SERVER=youracr.azurecr.io

# Operational settings
INTERVAL_HOURS=3        # Hours between runs
INDICATOR_COUNT=20      # Indicators per cycle
```

### Modifying Runtime Parameters

To change the generation interval or indicator count:

1. **Update the deployment script** parameters:
```powershell
# In deploy-to-aci.ps1, modify these lines:
$envVarsArray += "INTERVAL_HOURS=2"     # Change to 2 hours
$envVarsArray += "INDICATOR_COUNT=30"   # Generate 30 indicators
```

2. **Redeploy the container**:
```powershell
.\deploy-to-aci.ps1 -DeleteExisting
```

## 📈 Monitoring in Azure

### View Container Logs
```bash
# Stream logs
az container logs --resource-group secops --name synthetic-ti-generator --follow

# Last 100 lines
az container logs --resource-group secops --name synthetic-ti-generator --tail 100
```

### Attach to Container
```bash
# Attach to see real-time output
az container attach --resource-group secops --name synthetic-ti-generator
```

### Execute Commands in Container
```bash
# Open PowerShell session in running container
az container exec --resource-group secops --name synthetic-ti-generator --exec-command "pwsh"

# Run single generation test
az container exec --resource-group secops --name synthetic-ti-generator --exec-command "pwsh -Command './Generate-SyntheticSTIX.ps1 -IndicatorCount 5'"
```

### Check Container Status
```bash
# Get container details
az container show --resource-group secops --name synthetic-ti-generator --query instanceView.state

# Get all details
az container show --resource-group secops --name synthetic-ti-generator
```

## 🎯 Generated Threat Intelligence

Each cycle generates realistic STIX objects including:

### Indicators
- **IP Addresses**: Random malicious IPs (e.g., `192.168.45.123`)
- **Domains**: C2 domains (e.g., `malware-control789.com`)
- **URLs**: Malicious URLs (e.g., `https://phish-update456.net/api/beacon`)
- **File Hashes**: MD5 hashes of simulated malware

### Metadata
- **Attack Patterns**: MITRE ATT&CK techniques
- **Malware Families**: Emotet, TrickBot, Cobalt Strike, etc.
- **Threat Actors**: APT28, APT29, Lazarus, etc.
- **TLP Markings**: WHITE and AMBER
- **Confidence Scores**: 70-100

## 🔍 Troubleshooting

### Container Won't Start
```bash
# Check container events
az container show --resource-group secops --name synthetic-ti-generator --query events

# Check detailed status
az container show --resource-group secops --name synthetic-ti-generator
```

### Authentication Issues
1. Verify `.env` file has correct credentials
2. Check Service Principal permissions
3. Ensure ACR credentials are valid

### No Indicators in Sentinel
1. Check container logs for errors
2. Verify workspace ID is correct
3. Confirm API endpoint URL for your region
4. Review Service Principal permissions

### Container Keeps Restarting
```bash
# Check logs for errors
az container logs --resource-group secops --name synthetic-ti-generator --tail 50

# Verify image is in ACR
az acr repository show --name youracr --image synthetic-ti-generator:latest
```

## 🧹 Maintenance

### Update the Solution
```powershell
# Make changes to scripts
# Then rebuild and redeploy
.\deploy-to-aci.ps1 -BuildAndPush -DeleteExisting
```

### Clean Up Resources
```bash
# Delete container instance
az container delete --resource-group secops --name synthetic-ti-generator --yes

# Delete image from ACR (optional)
az acr repository delete --name youracr --image synthetic-ti-generator --yes
```

### Manual Operations
```bash
# Restart container
az container restart --resource-group secops --name synthetic-ti-generator

# Stop container
az container stop --resource-group secops --name synthetic-ti-generator

# Start container
az container start --resource-group secops --name synthetic-ti-generator
```

## 🔐 Security Considerations

- **Never commit `.env`** to version control
- **Use Azure Key Vault** for production deployments
- **Rotate credentials** regularly
- **Monitor container logs** for unauthorized access
- **Use managed identities** when possible
- **Enable Azure Monitor** for alerting

## 📋 Cost Optimization

Azure Container Instances pricing is based on:
- **CPU**: 0.5 cores allocated
- **Memory**: 0.5 GB allocated
- **Execution time**: Continuous

To reduce costs:
1. Use spot instances if available in your region
2. Adjust CPU/memory in deployment script
3. Consider using Azure Container Apps for better pricing

## 🚨 Important Notes

1. **ACI Limitations**: No Docker Compose support, single container deployments only
2. **Restart Policy**: Set to "Always" for continuous operation
3. **Storage**: Ephemeral - files are lost on container restart
4. **Networking**: Public IP not required for this solution
5. **Region**: Deploy in same region as your Sentinel workspace for best performance

## 📝 Support

For issues with:
- **Script functionality**: Review container logs
- **Azure deployment**: Check Azure Portal > Container Instances
- **Sentinel integration**: Verify in Azure Sentinel > Threat Intelligence blade
