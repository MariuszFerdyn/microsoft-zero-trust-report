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

- **Azure CLI (`az`)** — required by `CIS_Azure_Permissions.ps1` to create the App Registration,
  Service Principal, RBAC role assignments, and Graph permission grants.
  Install from <https://learn.microsoft.com/cli/azure/install-azure-cli> (or `winget install Microsoft.AzureCLI`),
  then sign in with `az login --tenant <tenant-guid>`.

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

- **Azure CLI (`az`)** — required by `CIS_Azure_Permissions.ps1` to create the App Registration,
  Service Principal, RBAC role assignments, and Graph permission grants.
  Install from <https://learn.microsoft.com/cli/azure/install-azure-cli> (or `winget install Microsoft.AzureCLI`),
  then sign in with `az login --tenant <tenant-guid>`.
- **PowerShell modules:**

```powershell
Install-Module Microsoft.Graph                          -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement                 -Scope CurrentUser -Force
Install-Module MicrosoftTeams                           -Scope CurrentUser -Force
Install-Module Microsoft.Online.SharePoint.PowerShell   -Scope CurrentUser -Force
```

> **Tenants without an Azure subscription** (Microsoft 365 / Office 365-only): sign in with
> `az login --tenant <tenant-guid> --allow-no-subscriptions`. The M365 permissions helper only
> needs Microsoft Graph access and does not require an Azure subscription.

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

### Sample console output (M365 benchmark)

```text
----------------------------------------------------------------------------------
 SECTION 1 - Microsoft 365 Admin Center
----------------------------------------------------------------------------------

 [1.1.1 (L1)] Ensure Administrative accounts are cloud-only (Automated)
 [PASS] No hybrid-synced users found in privileged roles.

 [1.1.3 (L1)] Ensure between two and four global admins are designated (Automated)
 Global Admins found: 6
 -> MOD Administrator | admin@M365x55944128.onmicrosoft.com
 -> Allan Deyoung | AllanD@M365x55944128.OnMicrosoft.com
 -> Nestor Wilke | NestorW@M365x55944128.OnMicrosoft.com
 -> Isaiah Langer | IsaiahL@M365x55944128.OnMicrosoft.com
 -> Megan Bowen | MeganB@M365x55944128.OnMicrosoft.com
 -> Lidia Holloway | LidiaH@M365x55944128.OnMicrosoft.com
 [FAIL] 6 Global Admins - maximum is 4. Reduce privileged access.

 [1.1.4 (L1)] Ensure admin accounts use licenses with reduced application footprint (Automated)
 Checking privileged users for assigned service plans (Teams, Exchange, SharePoint)...
 -> MOD Administrator: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 -> Allan Deyoung: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 -> Nestor Wilke: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 -> Isaiah Langer: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 -> Megan Bowen: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 -> Lidia Holloway: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 [FAIL] 6 admin(s) have productivity services assigned.
 Recommendation: Create dedicated cloud-only admin accounts without productivity licenses.

 [1.2.1 (L2)] Ensure only organizationally managed/approved public groups exist (Automated)
 Retrieving all Unified (M365) groups (client-side visibility filter)...
 Total M365 groups: 14, Public: 6
 [WARN] 6 public M365 group(s) - verify each is organizationally approved:
 -> All Company | allcompany@M365x55944128.onmicrosoft.com
 -> Sales and Marketing | SalesAndMarketing@M365x55944128.onmicrosoft.com
 -> Mark 8 Project Team | Mark8ProjectTeam@M365x55944128.onmicrosoft.com
 -> New Employee Onboarding | newemployeeonboarding@M365x55944128.onmicrosoft.com
 -> Contoso marketing | Contosomarketing@M365x55944128.onmicrosoft.com
 -> Remote living | Remoteliving@M365x55944128.onmicrosoft.com

 [1.2.2 (L1)] Ensure sign-in to shared mailboxes is blocked (Automated)
 [PASS] All 0 shared mailbox(es) have sign-in blocked.

 [1.3.1 (L1)] Ensure the Password expiration policy is set to never expire (Automated)
 [PASS] All verified domains have 'Never expire' password policy (value = 2147483647).

 [1.3.2 (L2)] Ensure 'Idle session timeout' is set to 3 hours or less (Automated)
 [FAIL] No Activity-Based Timeout policy found - idle session timeout is not configured.
 Remediation: Entra ID > Properties > Manage security defaults > Session timeout

 [1.3.3 (L2)] Ensure external sharing of calendars is not available (Automated)
 [FAIL] External calendar sharing policy allows anonymous access:
 -> Default Sharing Policy: Anonymous:CalendarSharingFreeBusyReviewer *:CalendarSharingFreeBusySimple

 [1.3.4 (L1)] Ensure 'User owned apps and services' is restricted (Automated)
 AllowedToCreateApps : True
 [FAIL] Users CAN create apps (AllowedToCreateApps = True). Restrict this setting.
 Remediation: Entra ID > User settings > App registrations > No

 [1.3.5 (L1)] Ensure internal phishing protection for Forms is enabled (Automated)
 isInOrgFormsPhishingScanEnabled: True
 [PASS] Internal phishing protection for Forms is ENABLED.

 [1.3.6 (L2)] Ensure the customer lockbox feature is enabled (Automated)
 CustomerLockBoxEnabled: False
 [FAIL] Customer Lockbox is NOT enabled.
 Remediation: M365 Admin Center > Settings > Org Settings > Security & Privacy > Customer Lockbox > On

 [1.3.7 (L2)] Ensure third-party storage services are restricted in Microsoft 365 (Automated)
 [PASS] Third-party storage service principal not found in tenant (not added = restricted).

 [1.3.9 (L1)] Ensure shared Bookings pages are restricted to select users (Automated)
 BookingsMailboxCreationEnabled: True
 BookingsEnabled (org)         : True
 [FAIL] Any user can create Bookings pages (BookingsMailboxCreationEnabled = True).
 Remediation: Exchange Admin > Settings > Bookings > restrict to specific users
```

## License

This project is provided as-is for security auditing purposes.