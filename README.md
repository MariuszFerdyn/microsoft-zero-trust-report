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

## Working Sample Output

The examples below keep the same **monospaced console layout** as the script output.  
On GitHub, Markdown preserves the spacing and formatting, but it does **not** render the live PowerShell console colors. The actual script still shows **green** for `PASS`, **red** for `FAIL`, **magenta** for `WARN`, and the same connection/status colors when you run it locally.

### Sample connection output

```text
----------------------------------------------------------------------------------
    Connecting to Microsoft Services
----------------------------------------------------------------------------------
    Connecting to Microsoft Graph...
    [OK] Graph connected (Tenant: 425b12b1-c9cc-4a2a-98e7-0a7210548876)
    Connecting to Exchange Online...
    [OK] Exchange Online connected (app-only token)
    Connecting to SharePoint Online...
    [OK] SharePoint Online connected
    Connecting to Microsoft Teams...
    [OK] Microsoft Teams connected

    Connection status: Graph=[OK] EXO=[OK] SPO=[OK] Teams=[OK]
```

### Sample results summary

```text
----------------------------------------------------------------------------------
    RESULTS SUMMARY
----------------------------------------------------------------------------------

==================================================================================
    CIS Microsoft 365 Foundations Benchmark v6.0.1 - RESULTS SUMMARY
==================================================================================

    SECTION      TITLE                                              STATUS
    ------------ -------------------------------------------------- ------
    1.1.1        Admin accounts are cloud-only                      PASS
    1.1.3        2-4 Global Admins                                  FAIL
                             Too many: 6 (max 4).
    1.1.4        Admin reduced license footprint                    FAIL
                             6 admin(s) with risky licenses.
    1.2.1        No unapproved public groups                        WARN
                             64 public groups found.
    1.2.2        Block shared mailbox sign-in                       PASS
    1.3.1        Password never expire policy                       PASS
    1.3.2        Idle session timeout <=3h                          FAIL
                             No timeout policy configured.
    1.3.3        No external calendar sharing                       FAIL
                             Anonymous calendar sharing enabled.
    1.3.4        User owned apps restricted                         FAIL
                             AllowedToCreateApps = True.
    1.3.5        Forms phishing protection                          PASS
    1.3.6        Customer Lockbox enabled                           FAIL
                             Enabled = False.
    1.3.7        Third-party storage restricted                     PASS
    1.3.9        Bookings restricted                                FAIL
                             BookingsMailboxCreationEnabled = True.
    2.1.2        Common attachment filter                           PASS
    2.1.3        Malware internal notification                      FAIL
                             Notification not configured.
    2.1.5        Safe Attachments SPO/ODB/Teams                     PASS
    2.1.6        Spam admin notification                            FAIL
                             Admin notification missing.
    2.1.8        SPF records published                              PASS
    2.1.9        DKIM enabled all domains                           PASS
    2.1.10       DMARC records published                            PASS
    2.1.13       Connection filter safe list off                    PASS
    2.1.14       No bypass domains in spam policy                   PASS
    2.1.15       Outbound spam limits                               FAIL
                             Check values above.
    3.2.1        DLP policies enabled                               WARN
                             Manual verification required (Purview DLP policies not queried here).
    3.3.1        Sensitivity labels published                       PASS
    4.1          Devices default not-compliant                      FAIL
                             secureByDefault = False.
    4.2          Block personal device enrollment                   WARN
                             Config not found.
    5.1.2.1      Per-user MFA disabled                              PASS
    5.1.2.2      No 3rd party app registration                      FAIL
                             AllowedToCreateApps = True.
    5.1.2.3      Restrict tenant creation                           FAIL
                             AllowedToCreateTenants = True.
    5.1.4.2      Max devices per user                               FAIL
                             Quota = 50 (should be <=20).
    5.1.4.3      GA not local admin on join                         FAIL
                             enableGlobalAdmins = True.
    5.1.4.4      Limit local admin on Entra join                    FAIL
                             Type = #microsoft.graph.allDeviceRegistrationMembership.
    5.1.4.5      LAPS enabled                                       FAIL
                             LAPS = False.
    5.1.4.6      Restrict BitLocker key recovery                    FAIL
                             BitLocker self-recovery = True.
    5.1.5.1      No user consent to apps                            PASS
    5.1.6.1      B2B invitation domain restriction                  FAIL
                             No B2B policy found.
    5.1.6.3      Guest invite limited to Guest Inviter              FAIL
                             AllowInvitesFrom = everyone.
    5.2.2.1      MFA for admin roles                                FAIL
                             No admin-role MFA CA policy.
    5.2.2.2      MFA for all users                                  PASS
    5.2.2.4      Sign-in freq + non-persistent session              FAIL
                             Both policies missing.
    5.2.2.5      Phishing-resistant MFA for admins                  FAIL
                             No phishing-resistant MFA CA.
    5.2.2.8      Block medium/high sign-in risk                     FAIL
                             No risk block CA.
    5.2.2.9      Managed device required                            WARN
                             No all-user managed device CA found.
    5.2.2.10     Managed device for security info reg               FAIL
                             No security info reg CA.
    5.2.2.11     Intune enrollment sign-in freq                     FAIL
                             No everyTime Intune CA.
    5.2.3.1      Authenticator MFA fatigue protection               PASS
    5.2.3.3      On-prem AD password protection                     WARN
                             Cloud-only or not configured.
    5.2.3.6      System-preferred MFA enabled                       PASS
    5.2.3.7      Email OTP disabled                                 FAIL
                             Email OTP = enabled.
    5.3.1        PIM used for role management                       WARN
                             Forbidden - check RoleManagement.Read.Directory permission + P2 license.
    5.3.3        Access reviews for privileged roles                FAIL
                             No active access reviews.
    5.3.4        Approval required for GA activation                WARN
                             Manual PIM portal verification required.
    5.3.5        Approval required for PRA activation               WARN
                             Manual PIM portal verification required.
    6.1.3        AuditBypass not enabled                            PASS
    6.2.1        Mail forwarding blocked                            FAIL
                             Forwarding rules/policies found.
    6.2.2        No domain bypass rules                             PASS
    6.5.1        Exchange modern auth enabled                       PASS
    6.5.2        MailTips enabled                                   PASS
    6.5.3        OWA storage restricted                             FAIL
                             AdditionalStorage = True.
    6.5.4        SMTP AUTH disabled                                 PASS
    7.2.1        SPO modern auth required                           FAIL
                             LegacyAuth = True.
    7.2.2        SPO B2B integration                                PASS
    7.2.5        SPO guest resharing blocked                        FAIL
                             PreventResharing = False.
    7.2.7        SPO link sharing restricted                        FAIL
                             DefaultSharingLink = AnonymousAccess.
    7.2.9        SPO guest access expiry                            FAIL
                             Required=False, Days=60.
    7.2.10       SPO reauth verification                            FAIL
                             Required=False, Days=30.
    7.2.11       SPO default link permission                        FAIL
                             DefaultLinkPermission = None.
    7.3.1        SPO infected file download blocked                 FAIL
                             DisallowInfected = False.
    7.3.2        OneDrive sync restricted                           FAIL
                             Sync not restricted.
    8.1.1        Teams approved cloud storage                       WARN
                             5 3rd party providers enabled.
    8.1.2        Block email to Teams channel                       FAIL
                             AllowEmailIntoChannel = True.
    8.2.1        Teams external domain restriction                  PASS
    8.2.2        Block unmanaged Teams                              FAIL
                             AllowTeamsConsumer = True.
    8.2.3        Block external Teams inbound                       FAIL
                             AllowTeamsConsumerInbound = True.
    8.2.4        Block trial Teams tenants                          PASS
    8.5.2        Block anon start meeting                           PASS
    8.5.7        Block external control                             PASS
    8.5.8        External meeting chat off                          FAIL
                             ExternalChat = True.
    8.5.9        Recording off by default                           FAIL
                             AllowCloudRecording = True.
    9.1.1 (L1)   Ensure guest user access is restricted in Power BI FAIL
                             AllowGuestAccess = True (expected False).
    9.1.4 (L1)   Ensure 'Publish to web' is restricted in Power BI  FAIL
                             PublishToWeb = True (expected False).
    9.1.5 (L2)   Ensure R and Python visuals are Disabled in Pow... FAIL
                             AllowRVisuals = True (expected False).
    9.1.6 (L1)   Ensure 'Allow users to apply sensitivity labels... FAIL
                             SensitivityLabelsEnabled = False (expected True).
    9.1.7 (L1)   Ensure shareable links are restricted in Power BI  FAIL
                             ShareLinkToEntireOrg = True (expected False).
    9.1.10 (L1)  Ensure access to APIs by service principals is ... FAIL
                             ServicePrincipalAccess = True (expected False).
    9.1.11 (L1)  Ensure service principals cannot create and use... FAIL
                             ServicePrincipalProfiles = True (expected False).
    9.1.12 (L1)  Ensure service principals cannot manage workspa... FAIL
                             ServicePrincipalCanManageWorkspaces = True (expected False).

==================================================================================
    Checks run :   88
    PASS       :   28  (32%)
    FAIL       :   51  (58%)
    WARN       :    9  (10%)
==================================================================================

    Connection status:
        Graph  : [OK]
        EXO   : [OK] Connected
        SPO   : [OK] Connected
        Teams : [OK] Connected

    All required Microsoft Graph permissions appear to be granted.

    Results exported to: D:\GIT\microsoft-zero-trust-report\CIS_M365_Results_20260403_164504.csv
```

### Sample detailed section output

```text
----------------------------------------------------------------------------------
    SECTION 1 - Microsoft 365 Admin Center
----------------------------------------------------------------------------------

    [1.1.1 (L1)]  Ensure Administrative accounts are cloud-only (Automated)
    [PASS] No hybrid-synced users found in privileged roles.

    [1.1.3 (L1)]  Ensure between two and four global admins are designated (Automated)
        Global Admins found: 6
            -> MOD Administrator | admin@M365x76064521.onmicrosoft.com
            -> Nestor Wilke | NestorW@M365x76064521.OnMicrosoft.com
            -> Isaiah Langer | IsaiahL@M365x76064521.OnMicrosoft.com
            -> Megan Bowen | MeganB@M365x76064521.OnMicrosoft.com
            -> Lidia Holloway | LidiaH@M365x76064521.OnMicrosoft.com
            -> Allan Deyoung | AllanD@M365x76064521.OnMicrosoft.com
    [FAIL] 6 Global Admins - maximum is 4. Reduce privileged access.

    [1.1.4 (L1)]  Ensure admin accounts use licenses with reduced application footprint (Automated)
        Checking privileged users for assigned service plans (Teams, Exchange, SharePoint)...
            -> MOD Administrator: SharePoint Online (Plan 1) [E3], Microsoft Teams, Exchange Online (Plan 1), SharePoint Online (Plan 1)
            -> Nestor Wilke: Microsoft Teams, Exchange Online (Plan 1), SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1)
            -> Isaiah Langer: Microsoft Teams, Exchange Online (Plan 1), SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1)
            -> Megan Bowen: Microsoft Teams, Exchange Online (Plan 1), SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1)
            -> Lidia Holloway: Microsoft Teams, Exchange Online (Plan 1), SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1)
            -> Allan Deyoung: Microsoft Teams, Exchange Online (Plan 1), SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1)
    [FAIL] 6 admin(s) have productivity services assigned.
            Recommendation: Create dedicated cloud-only admin accounts without productivity licenses.

    [1.2.1 (L2)]  Ensure only organizationally managed/approved public groups exist (Automated)
        Retrieving all Unified (M365) groups (client-side visibility filter)...
        Total M365 groups: 64, Public: 64
    [WARN] 64 public M365 group(s) - verify each is organizationally approved:
            -> All Company | allcompany@M365x76064521.onmicrosoft.com
            -> Group for Answers in Viva Engage – DO NOT DELETE 178029985792 | groupforanswersinvivaengagedonotdelete178029985792638@M365x76064521.onmicrosoft.com
            -> Corporate Operations | CorporateOperations@M365x76064521.onmicrosoft.com
            -> HR and Communications | HRandCommunications@M365x76064521.onmicrosoft.com
            -> Seattle Store 121 | SeattleStore121@M365x76064521.onmicrosoft.com
            -> IT Management | ITManagement@M365x76064521.onmicrosoft.com
            -> Retail Communications | RetailCommunications@M365x76064521.onmicrosoft.com
            -> Seattle 121 Managers | Seattle121Managers@M365x76064521.onmicrosoft.com
            -> North America | NorthAmerica@M365x76064521.onmicrosoft.com
            -> Canada | Canada@M365x76064521.onmicrosoft.com
            -> British Columbia | BritishColumbia@M365x76064521.onmicrosoft.com
            -> Quebec | Quebec@M365x76064521.onmicrosoft.com
            -> West US | WestUS@M365x76064521.onmicrosoft.com
            -> Seattle | Seattle@M365x76064521.onmicrosoft.com
            -> Bellevue | Bellevue@M365x76064521.onmicrosoft.com
            -> Bellevue Store 122 | BellevueStore122@M365x76064521.onmicrosoft.com
            -> Portland | Portland@M365x76064521.onmicrosoft.com
            -> Portland Store 249 | PortlandStore249@M365x76064521.onmicrosoft.com
            -> Los Angeles | LosAngeles@M365x76064521.onmicrosoft.com
            -> Los Angeles Store 289 | LosAngelesStore289@M365x76064521.onmicrosoft.com
            -> East US | EastUS@M365x76064521.onmicrosoft.com
            -> New York | NewYork@M365x76064521.onmicrosoft.com
            -> Ontario | Ontario@M365x76064521.onmicrosoft.com
            -> South America | SouthAmerica@M365x76064521.onmicrosoft.com
            -> Argentina | Argentina@M365x76064521.onmicrosoft.com
            -> Brazil | Brazil@M365x76064521.onmicrosoft.com
            -> Peru | Peru@M365x76064521.onmicrosoft.com
            -> New Jersey | NewJersey@M365x76064521.onmicrosoft.com
            -> Europe | Europe@M365x76064521.onmicrosoft.com
            -> France | France@M365x76064521.onmicrosoft.com
            -> Germany | Germany@M365x76064521.onmicrosoft.com
            -> UK | UK@M365x76064521.onmicrosoft.com
            -> Asia | Asia@M365x76064521.onmicrosoft.com
            -> China | China@M365x76064521.onmicrosoft.com
            -> Japan | Japan@M365x76064521.onmicrosoft.com
            -> South Korea | SouthKorea@M365x76064521.onmicrosoft.com
            -> Store 1 | Store1@M365x76064521.onmicrosoft.com
            -> Store 2 | Store2@M365x76064521.onmicrosoft.com
            -> Store 3 | Store3@M365x76064521.onmicrosoft.com
            -> Store 4 | Store4@M365x76064521.onmicrosoft.com
            -> Store 5 | Store5@M365x76064521.onmicrosoft.com
            -> Store 6 | Store6@M365x76064521.onmicrosoft.com
            -> Store 7 | Store7@M365x76064521.onmicrosoft.com
            -> Store 8 | Store8@M365x76064521.onmicrosoft.com
            -> Store 9 | Store9@M365x76064521.onmicrosoft.com
            -> Store 10 | Store10@M365x76064521.onmicrosoft.com
            -> Store 11 | Store11@M365x76064521.onmicrosoft.com
            -> Store 12 | Store12@M365x76064521.onmicrosoft.com
            -> Store 13 | Store13@M365x76064521.onmicrosoft.com
            -> Store 14 | Store14@M365x76064521.onmicrosoft.com
            -> Store 15 | Store15@M365x76064521.onmicrosoft.com
            -> Store 16 | Store16@M365x76064521.onmicrosoft.com
            -> Store 17 | Store17@M365x76064521.onmicrosoft.com
            -> Store 18 | Store18@M365x76064521.onmicrosoft.com
            -> Store 19 | Store19@M365x76064521.onmicrosoft.com
            -> Store 20 | Store20@M365x76064521.onmicrosoft.com
            -> Store 21 | Store21@M365x76064521.onmicrosoft.com
            -> Store 22 | Store22@M365x76064521.onmicrosoft.com
            -> Store 23 | Store23@M365x76064521.onmicrosoft.com
            -> Store 24 | Store24@M365x76064521.onmicrosoft.com
            -> Store 25 | Store25@M365x76064521.onmicrosoft.com
            -> Store 26 | Store26@M365x76064521.onmicrosoft.com
            -> Store 27 | Store27@M365x76064521.onmicrosoft.com
            -> Store 28 | Store28@M365x76064521.onmicrosoft.com

    [1.2.2 (L1)]  Ensure sign-in to shared mailboxes is blocked (Automated)
    [PASS] All 0 shared mailbox(es) have sign-in blocked.

    [1.3.1 (L1)]  Ensure the Password expiration policy is set to never expire (Automated)
    [PASS] All verified domains have 'Never expire' password policy (value = 2147483647).
```

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
