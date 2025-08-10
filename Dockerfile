# Dockerfile for Synthetic TI Generator and Uploader for Azure Container Instances
FROM mcr.microsoft.com/powershell:7.5-alpine-3.20

# Install required packages
RUN apk add --no-cache \
    ca-certificates \
    curl \
    tzdata

# Set timezone
ENV TZ=UTC

# Set default environment variables (can be overridden by ACI)
ENV INTERVAL_HOURS=3
ENV INDICATOR_COUNT=20

# Create working directory
WORKDIR /app

# Copy PowerShell scripts
COPY Test-TI2UploadAPI.ps1 .
COPY Generate-SyntheticSTIX.ps1 .
COPY Invoke-TIOrchestrator.ps1 .

# Copy environment file (will be used as default, ACI env vars will override)
# COPY .env .
# NOTE: .env file should be mounted at runtime, not copied into image
# Mount with: -v ./.env:/app/.env:ro
# Or pass as environment variables in ACI

# Create directory for TI output files
RUN mkdir -p /app/output

# Make scripts executable
RUN chmod +x *.ps1

# Set PowerShell as the default shell
SHELL ["pwsh", "-Command"]

# Install any required PowerShell modules (optional)
# RUN Install-Module -Name MSAL.PS -Force -Scope CurrentUser -AcceptLicense

# Default command - run the orchestrator with environment variables
ENTRYPOINT ["pwsh", "-File", "./Invoke-TIOrchestrator.ps1"]
CMD ["-IntervalHours", "3", "-IndicatorCount", "20"]
