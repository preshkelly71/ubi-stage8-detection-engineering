# Lab Setup Guide

## Wazuh 4.14.6 Docker Deployment

```bash
# Clone the pinned Wazuh Docker repository and install overlays
bash prepare-wazuh.sh

# Generate certificates (follow the pinned repository's instructions)
# Then start the stack
docker compose up -d

# Verify all services are running
docker compose ps
```

## Windows 11 VM Setup

1. Download Windows 11 Evaluation ISO from Microsoft
2. Create a VirtualBox VM: 4GB RAM, 2 CPU, 40GB disk, host-only network
3. Install Sysmon with a documented configuration
4. Install Wazuh agent using `Install-Endpoint.ps1`

```powershell
# Run from an elevated PowerShell on the isolated VM
.\Install-Endpoint.ps1 -WazuhManager <MANAGER_IP> -SysmonExe <path> -SysmonConfig <path> -WazuhAgentMsi <path>
```

5. Verify the agent appears in the Wazuh dashboard

## Atomic Red Team Tests

Install Atomic Red Team on the VM:
```powershell
Invoke-WebRequest -Uri "https://github.com/redcanaryco/invoke-atomicredteam/archive/refs/tags/v1.0.2.0.zip" -OutFile atomic.zip
Expand-Archive atomic.zip
```

Run the 12 assigned Atomic tests (see coverage-matrix.csv for GUIDs).

## Evidence Capture

After running tests, capture lab state:
```powershell
.\Capture-LabState.ps1 -Output C:\NetForge-Evidence\capture
```

This exports Sysmon/Security evtx files, event XML, service state, network connections, and SHA-256 hashes.

## Network Isolation

The Windows VM must be on an isolated host-only network. Never run Atomic tests on a personal, employer, or production machine. The `Install-Endpoint.ps1` script checks for `NetworkCategory -eq 'Private'` before proceeding.
