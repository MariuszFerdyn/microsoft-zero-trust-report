# Microsoft CIS Benchmark Automation

Automated PowerShell scripts to audit your **Microsoft Azure** and **Microsoft 365** environments against the **CIS (Center for Internet Security) Benchmarks**. Each benchmark includes a full audit script and a permissions-setup helper.

## Benchmarks

| Benchmark | Version | Automated Checks | Script | Permissions Helper |
|-----------|---------|------------------:|--------|--------------------|
| CIS Microsoft Azure Foundations | v5.0.0 | 103 | `CIS_Azure_Benchmark_Full.ps1` | `CIS_Azure_Permissions.ps1` |
| CIS Microsoft 365 Foundations | v6.0.1 | 129 | `CIS_M365_Benchmark_Full.ps1` | `CIS_M365_Permissions.ps1` |

---

## 1 — CIS Azure Foundations Benchmark v5.0.0

### Sections Covered

| Section | Area | Checks |
|---------|------|-------:|
| 2 | Databricks | 7 |
| 5 | Identity / Entra ID | 9 |
| 6 | Logging & Monitoring | 22 |
| 7 | Networking | 17 |
| 8 | Security (Defender, Key Vault, Bastion, DDoS) | 30 |
| 9 | Storage | 18 |

> **Multi-resource coverage:** checks that target resource types which can exist more than once
> (Databricks workspaces, NSGs, VNets, Bastion hosts, VPN Gateways, App Services, Public IPs, Storage
> accounts, etc.) iterate **every** instance in the subscription and report per-resource results.
> For example, Bastion coverage is validated per VNet that hosts VMs (same VNet or peered), and NSG
> and VNet flow logs are verified for every NSG/VNet — not just the first one found.

### Prerequisites

```powershell
Install-Module Az               -Scope CurrentUser -Force
Install-Module Microsoft.Graph   -Scope CurrentUser -Force
```

> Or let `CIS_Azure_Permissions.ps1` install them for you. It installs the required sub-modules
> (`Az.Accounts`, `Az.Resources`, `Az.Security`, `Az.Network`, `Az.Monitor`, `Az.KeyVault`,
> `Az.Storage`, `Az.Websites`, `Az.ApplicationInsights`, `Az.Compute`, plus
> `Microsoft.Graph.Identity.SignIns` and `Microsoft.Graph.Identity.DirectoryManagement`).

### Permissions Setup

Run the helper first to create an App Registration with the required RBAC roles and Graph permissions:

```powershell
.\CIS_Azure_Permissions.ps1 -TenantId "<tenant-guid>" -SubscriptionId "<sub-guid>"
```

The script assigns:
- **Azure RBAC**: Reader, Security Reader, Key Vault Reader (subscription scope)
- **Microsoft Graph**: Directory.Read.All, Policy.Read.All, User.Read.All, RoleManagement.Read.All, Organization.Read.All

### Running the Audit

**Interactive login:**

```powershell
.\CIS_Azure_Benchmark_Full.ps1
```

**Service-principal (non-interactive):**

```powershell
.\CIS_Azure_Benchmark_Full.ps1 `
    -TenantId       "<tenant-guid>" `
    -SubscriptionId "<sub-guid>" `
    -ClientId       "<app-id>" `
    -ClientSecret   "<secret>"
```

> At the end of `CIS_Azure_Permissions.ps1` the generated client secret is printed and the ready-to-run
> command line is displayed. You are also prompted **"Run benchmark now? [Y/N]"** — answering `Y` will
> launch `CIS_Azure_Benchmark_Full.ps1` immediately with the newly created credentials.

Results are saved to a timestamped CSV file: `CIS_Azure_Results_<date>.csv`

---

## 2 — CIS Microsoft 365 Foundations Benchmark v6.0.1

### Sections Covered

| Section | Area | Key Topics |
|---------|------|------------|
| 1 | Microsoft 365 Admin Center | Licensing, groups, calendar sharing, customer lockbox, third-party storage |
| 2 | Microsoft 365 Defender | Email & collaboration, DMARC, anti-phishing |
| 3 | Compliance | DLP, information protection, sensitivity labels |
| 4 | Intune / Device Management | Device enrollment, compliance policies |
| 5 | Microsoft Entra ID | Identity, MFA, conditional access, PIM, access reviews |
| 6 | Exchange Online | Transport rules, mailbox auditing |
| 7 | SharePoint Online & OneDrive | Sharing policies, access controls |
| 8 | Microsoft Teams | Meeting policies, external access, guest access |
| 9 | Power BI / Fabric | Tenant settings, admin configuration |

### Prerequisites

```powershell
Install-Module Microsoft.Graph                          -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement                 -Scope CurrentUser -Force
Install-Module MicrosoftTeams                           -Scope CurrentUser -Force
Install-Module Microsoft.Online.SharePoint.PowerShell   -Scope CurrentUser -Force
```

### Permissions Setup

Run the helper to create an App Registration with all required Graph, Exchange, and Power BI permissions:

```powershell
.\CIS_M365_Permissions.ps1 -TenantId "<tenant-guid>"
```

Options:
- `-AppName "CIS-M365-Benchmark-Audit"` — custom app registration name
- `-AppId "<existing-app-guid>"` — reuse an existing app registration
- `-IncludeExchange` — add Exchange.ManageAsApp permission
- `-SkipDirectoryRoles` — skip Entra directory role assignments
- `-AutoLogin` — auto-login if Azure CLI is signed into a different tenant

The script configures:
- **Microsoft Graph**: Directory.Read.All, Policy.Read.All, User.Read.All, Group.Read.All, RoleManagement.Read.All, and many more
- **Entra Directory Roles**: Fabric Administrator, Intune Administrator
- **Exchange Online** (optional): Exchange.ManageAsApp + View-Only Organization Management role

### Running the Audit

**Service-principal (non-interactive):**

```powershell
.\CIS_M365_Benchmark_Full.ps1 `
    -TenantId           "<tenant-guid>" `
    -AppId              "<app-id>" `
    -AppSecret          "<secret>" `
    -SharePointAdminUrl "https://<tenant>-admin.sharepoint.com" `
    -TenantDomain       "<tenant>.onmicrosoft.com"
```

**Graph-only mode** (skip EXO/SPO/Teams interactive prompts):

```powershell
.\CIS_M365_Benchmark_Full.ps1 `
    -TenantId "<tenant-guid>" `
    -AppId    "<app-id>" `
    -AppSecret "<secret>" `
    -GraphOnlyMode
```

Results are saved to a timestamped CSV file: `CIS_M365_Results_<date>.csv`

---

## Output Format

Both benchmark scripts produce:
- **Console output** with color-coded results: `[PASS]`, `[FAIL]`, `[WARN]`, `[SKIP]`
- **CSV report** with columns: Section, Title, Status, Detail

## License

This project is provided as-is for security auditing purposes.