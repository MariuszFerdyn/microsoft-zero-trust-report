# CIS Microsoft 365 Foundations Benchmark v6.0.1 — Audit Script

Automated PowerShell checks for the **CIS Microsoft 365 Foundations Benchmark v6.0.1**.  
Runs **88 automated checks** across 9 sections: Admin Center, Defender, Purview, Intune, Entra ID, Exchange Online, SharePoint/OneDrive, Teams, and Power BI.

## ⚡ Getting Started — Guided Setup

**Easiest way: just run the permissions script in PowerShell and answer the prompts.**
It creates the app registration, sets all permissions (including Power BI), assigns directory roles, handles Exchange Online registration, and offers to launch the benchmark at the end.

### Prerequisites

- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) installed and on PATH
- PowerShell 5.1+
- ExchangeOnlineManagement module: `Install-Module ExchangeOnlineManagement -Scope CurrentUser`

### Steps

```powershell
# Step 1 — Authenticate with Azure CLI for your tenant
az login --tenant "<your-tenant-id>"

# Step 2 — Run the interactive permissions setup (answer each prompt)
.\CIS_M365_Permissions.ps1 `
    -TenantId           "<your-tenant-id>" `
    -TenantDomain       "<your-tenant>.onmicrosoft.com" `
    -SharePointAdminUrl "https://<your-tenant>-admin.sharepoint.com" `
    -IncludeExchange
```

The script will:

1. Create (or reuse) the **Entra ID app registration**
2. Add all **Microsoft Graph**, **Power BI Service** and **Exchange Online** application permissions
3. Grant **admin consent** for all permissions
4. Directly create **appRoleAssignments** for Power BI `Tenant.Read.All` and Exchange `Exchange.ManageAsApp` (admin-consent silently skips non-Graph APIs)
5. Create a **security group** for Power BI / Fabric API access and verify the required Fabric tenant settings
6. Register the SP in **Exchange Online** via `New-ServicePrincipal` + add to `View-Only Organization Management`
7. Assign **Fabric Administrator** and **Intune Administrator** directory roles (use `-SkipDirectoryRoles` to opt out)
8. **Verify all granted permissions** and report any that are still missing
9. Print the complete benchmark run command and offer to **launch it immediately**

> **Note:** Section 9 uses current **Fabric** tenant settings. If the script detects that service principals still cannot read Fabric admin settings, it will prompt you with the exact manual steps in the admin portal. You must type `continue` after completing them.

---

## Quick Start (benchmark only — if app already configured)

```powershell
.\CIS_M365_Benchmark_Full.ps1 `
    -TenantId           "<your-tenant-id>" `
    -AppId              "<your-app-id>" `
    -AppSecret          "<your-app-secret>" `
    -SharePointAdminUrl "https://<your-tenant>-admin.sharepoint.com" `
    -TenantDomain       "<your-tenant>.onmicrosoft.com"
```

---

## Permissions Needed To Run The Benchmark

`CIS_M365_Permissions.ps1` is the **source of truth** for the required app permissions, directory roles, and service-specific setup.  
This README section is a **human-readable summary** of what is required to run the benchmark successfully.

The benchmark uses **app-only authentication** for most Microsoft 365 services and an **Azure CLI delegated fallback** for Fabric tenant settings when the app-only Fabric admin endpoint returns a server-side `500`.

### Local prerequisites

- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) installed and signed in to the target tenant: `az login --tenant "<tenant-id>"`
- PowerShell 5.1+
- PowerShell modules:
    - `Install-Module Microsoft.Graph -Scope CurrentUser -Force`
    - `Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force`
    - `Install-Module MicrosoftTeams -Scope CurrentUser -Force`
    - `Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force`

### Required application permissions

#### Microsoft Graph application permissions

- `AccessReview.Read.All`
- `AuditLog.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementServiceConfig.Read.All`
- `Directory.Read.All`
- `Domain.Read.All`
- `Group.Read.All`
- `IdentityRiskyUser.Read.All`
- `InformationProtectionPolicy.Read.All`
- `Organization.Read.All`
- `OrgSettings-Forms.ReadWrite.All`
- `Policy.Read.All`
- `Policy.Read.AuthenticationMethod`
- `PrivilegedAccess.Read.AzureAD`
- `RoleManagement.Read.All`
- `RoleManagement.Read.Directory`
- `SecurityEvents.Read.All`
- `User.Read.All`

#### Power BI Service application permission

- `Tenant.Read.All`

#### Exchange Online application permission

- `Exchange.ManageAsApp`
- Required only if you want Exchange Online checks to run app-only without falling back to manual setup.

### Required Entra ID role assignments on the service principal

- `Fabric Administrator` or `Power BI Administrator` for Section 9 (Power BI / Fabric)
- `Intune Administrator` for Section 4 (Intune / Device Management)

### Required service-specific setup

#### Power BI / Fabric

- Fabric Admin portal → Tenant settings → **Admin API settings**
    - Enable `Service principals can access read-only admin APIs`
    - Apply it to the service principal or its security group, e.g. `CIS-Audit-PowerBI-ServicePrincipals`
- For Section `9.1.10` to `9.1.12`, review these **Developer settings** as well:
    - `Service principals can call Fabric public APIs`
    - `Allow service principals to create and use profiles`
    - `Service principals can create workspaces, connections, and deployment pipelines`
- Keep Azure CLI signed in to the same tenant because the benchmark uses an Azure CLI delegated fallback for Fabric tenant settings if the app-only admin endpoint fails server-side.

#### Exchange Online

- Create the `Exchange.ManageAsApp` app role assignment
- Register the service principal in Exchange Online with `New-ServicePrincipal`
- Add the service principal to the `View-Only Organization Management` role group

#### Licensing / feature prerequisites

- Section `5.3.x` (PIM / access reviews) may require Microsoft Entra ID P2 licensing to return complete results
- Some `WARN` results remain manual by design where Microsoft does not expose reliable app-only APIs

---

## Manual Setup Note

If you do **not** want to use the guided helper, manually create the app registration so it matches the requirements summarized above.  
Do **not** treat old one-liners or copied portal steps as authoritative; the maintained logic lives in `CIS_M365_Permissions.ps1`.

In practice, the manual setup must match the helper script in four areas:

1. The exact **Microsoft Graph**, **Power BI Service**, and optional **Exchange Online** application permissions
2. The required **direct appRoleAssignments** for non-Graph APIs
3. The required Entra **directory roles** on the service principal
4. The required **Fabric** and **Exchange Online** service-specific setup steps

If there is any mismatch between this README and the helper script, follow the helper script.

---

## Required PowerShell Modules

```powershell
Install-Module Microsoft.Graph                         -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement                -Scope CurrentUser -Force   # must be v3.2+
Install-Module MicrosoftTeams                          -Scope CurrentUser -Force
Install-Module Microsoft.Online.SharePoint.PowerShell  -Scope CurrentUser -Force
```

Verify EXO module version (must be ≥ 3.2.0 for device-code auth):
```powershell
Get-Module ExchangeOnlineManagement -ListAvailable | Select-Object Version
Update-Module ExchangeOnlineManagement   # if needed
```

---

## Output

- **Console** — color-coded: ✔ PASS (green) / ✘ FAIL (red) / ⚠ WARN (magenta)
- **CSV report** — saved next to the script: `CIS_M365_Benchmark_Results_YYYYMMDD_HHmmss.csv`

---

## Covered Sections

| Section | Area                              | Checks |
|---------|-----------------------------------|--------|
| 1       | Microsoft 365 Admin Center        | 13     |
| 2       | Microsoft 365 Defender            | 10     |
| 3       | Microsoft Purview / Compliance    | 2      |
| 4       | Intune / Device Management        | 2      |
| 5       | Microsoft Entra ID + CA + PIM     | 27     |
| 6       | Exchange Online                   | 7      |
| 7       | SharePoint Online & OneDrive      | 9      |
| 8       | Microsoft Teams                   | 10     |
| 9       | Power BI                          | 8      |
| **Total** |                                 | **88** |
