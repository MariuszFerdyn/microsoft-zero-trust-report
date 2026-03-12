# CIS Microsoft 365 Foundations Benchmark v6.0.1 — Audit Script

## Quick Start

```powershell
.\CIS_M365_Benchmark_Full.ps1 `
    -TenantId           "425b12b1-c9cc-4a2a-98e7-0a7210548876" `
    -AppId              "04e13598-ae12-41f1-90d5-640cf4a3970e" `
    -AppSecret          "xxxx" `
    -SharePointAdminUrl "https://m365x76064521-admin.sharepoint.com" `
    -TenantDomain       "M365x76064521.onmicrosoft.com"
```

---

## App Registration Setup (Azure CLI)

### Prerequisites

#### Local terminal
```bash
az login --tenant "425b12b1-c9cc-4a2a-98e7-0a7210548876"
```

#### Azure Cloud Shell (fix MSI token audience error first)

If you see:  
`Audience 74658136-14ec-4630-ad9b-26e160ff0fc6 is not a supported MSI token audience`

Run this **before anything else**:
```bash
az logout
az login --scope "74658136-14ec-4630-ad9b-26e160ff0fc6/.default"
```

---

### One-liner — Create App + Secret + All Permissions (resolves GUIDs dynamically)

```bash
APP_NAME="CIS-M365-Benchmark-Audit" && APP=$(az ad app create --display-name "$APP_NAME" --query "{appId:appId,id:id}" -o json) && APP_ID=$(echo $APP | python -c "import sys,json;print(json.load(sys.stdin)['appId'])") && SP_OBJ=$(az ad sp create --id $APP_ID --query id -o tsv) && SECRET=$(az ad app credential reset --id $APP_ID --display-name "CISAuditSecret" --years 1 --query password -o tsv) && GRAPH_OBJ=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query "appRoles" -o json) && for PERM in "Policy.Read.All" "AuditLog.Read.All" "Directory.Read.All" "Domain.Read.All" "Group.Read.All" "User.Read.All" "Organization.Read.All" "RoleManagement.Read.All" "DeviceManagementConfiguration.Read.All" "PrivilegedAccess.Read.AzureAD" "InformationProtectionPolicy.Read.All" "SecurityEvents.Read.All" "IdentityRiskyUser.Read.All" "AccessReview.Read.All" "RoleManagement.Read.Directory" "Tenant.Read.All" "OrgSettings-Forms.ReadWrite.All" "Domain.Read.All" "SecurityEvents.Read.All" "IdentityRiskyUser.Read.All"; do GUID=$(echo $GRAPH_OBJ | python -c "import sys,json;roles=json.load(sys.stdin);match=[r['id'] for r in roles if r['value']=='$PERM'];print(match[0] if match else 'NOT_FOUND')"); if [ "$GUID" != "NOT_FOUND" ]; then az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 --api-permissions "$GUID=Role" 2>/dev/null && echo "  + $PERM ($GUID)"; else echo "  ! $PERM NOT FOUND"; fi; done && az ad app permission admin-consent --id $APP_ID && echo "" && echo "=== Done ===" && echo "TenantId:           $(az account show --query tenantId -o tsv)" && echo "AppId:              $APP_ID" && echo "AppSecret:          $SECRET" && echo "ObjectId (SP):      $SP_OBJ"
```

Copy the output values directly into the script parameters.

---

### Step-by-Step (same thing, readable)

#### 1. Login
```bash
az login --tenant "425b12b1-c9cc-4a2a-98e7-0a7210548876"
```

#### 2. Create App Registration + Service Principal + Secret
```bash
APP_NAME="CIS-M365-Benchmark-Audit"

APP_ID=$(az ad app create --display-name "$APP_NAME" --query appId -o tsv)
az ad sp create --id $APP_ID
SECRET=$(az ad app credential reset --id $APP_ID --display-name "CISAuditSecret" --years 1 --query password -o tsv)

echo "AppId:     $APP_ID"
echo "AppSecret: $SECRET"
```

#### 3. Resolve Permission GUIDs Dynamically and Add Them
```bash
# Fetch all Microsoft Graph app roles (GUIDs vary per tenant/environment)
GRAPH_OBJ=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query "appRoles" -o json)

PERMISSIONS=(
    "Policy.Read.All"
    "AuditLog.Read.All"
    "Directory.Read.All"
    "Domain.Read.All"
    "Group.Read.All"
    "User.Read.All"
    "Organization.Read.All"
    "RoleManagement.Read.All"
    "RoleManagement.Read.Directory"          # PIM role schedules
    "DeviceManagementConfiguration.Read.All" # Intune checks (4.x)
    "PrivilegedAccess.Read.AzureAD"          # PIM management (5.3.1)
    "InformationProtectionPolicy.Read.All"   # DLP / sensitivity labels (3.x)
    "SecurityEvents.Read.All"
    "IdentityRiskyUser.Read.All"
    "AccessReview.Read.All"                  # Access reviews (5.3.3)
    "Tenant.Read.All"                        # Power BI via Graph beta (9.x)
    "OrgSettings-Forms.ReadWrite.All"        # Forms phishing protection (1.3.5)
    "Domain.Read.All"                        # SPF/DMARC domain checks (2.1.x)
    "SecurityEvents.Read.All"
    "IdentityRiskyUser.Read.All"
)

for PERM in "${PERMISSIONS[@]}"; do
    GUID=$(echo $GRAPH_OBJ | python -c "
import sys, json
roles = json.load(sys.stdin)
match = [r['id'] for r in roles if r['value'] == '$PERM']
print(match[0] if match else 'NOT_FOUND')
")
    if [ "$GUID" != "NOT_FOUND" ]; then
        az ad app permission add \
            --id $APP_ID \
            --api 00000003-0000-0000-c000-000000000000 \
            --api-permissions "$GUID=Role"
        echo "  + $PERM  ($GUID)"
    else
        echo "  ! $PERM — not found in Graph SP"
    fi
done
```

#### 4. Grant Admin Consent
```bash
az ad app permission admin-consent --id $APP_ID
```

---

### Exchange Online — App-Only Auth (skips interactive browser login)

By default the script uses device-code interactive login for Exchange Online.  
To enable fully automated (unattended) EXO auth:

```bash
# Resolve Exchange Online permission GUID dynamically
EXO_OBJ=$(az ad sp show --id 00000002-0000-0ff1-ce00-000000000000 --query "appRoles" -o json)
EXO_GUID=$(echo $EXO_OBJ | python -c "
import sys, json
roles = json.load(sys.stdin)
match = [r['id'] for r in roles if r['value'] == 'Exchange.ManageAsApp']
print(match[0] if match else 'NOT_FOUND')
")
echo "Exchange.ManageAsApp GUID: $EXO_GUID"

az ad app permission add \
    --id $APP_ID \
    --api 00000002-0000-0ff1-ce00-000000000000 \
    --api-permissions "$EXO_GUID=Role"

az ad app permission admin-consent --id $APP_ID
```

Then in **Exchange Admin Center (EAC)**:  
`Roles → Admin roles → View-Only Organization Management → Members → Add → search for "CIS-M365-Benchmark-Audit"`

---

### Power BI — Add Tenant.Read.All Permission

Required for all Section 9 (Power BI) checks.  
This is a **Microsoft Graph** permission (not Power BI Service) — the script uses the Graph beta endpoint `/admin/powerbi/tenantsettings`.

```bash
# Resolve Microsoft Graph Tenant.Read.All GUID dynamically
GRAPH_OBJ=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query "appRoles" -o json)
TENANT_GUID=$(echo $GRAPH_OBJ | python -c "
import sys, json
roles = json.load(sys.stdin)
match = [r['id'] for r in roles if r['value'] == 'Tenant.Read.All']
print(match[0] if match else 'NOT_FOUND')
")
echo "Microsoft Graph Tenant.Read.All GUID: $TENANT_GUID"

az ad app permission add \
    --id $APP_ID \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions "$TENANT_GUID=Role"

az ad app permission admin-consent --id $APP_ID
```

> **Portal equivalent:** App Registrations → CIS-M365-Benchmark-Audit → API Permissions  
> → Add a permission → Microsoft Graph → Application permissions → search **Tenant.Read.All** → Add → Grant admin consent

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
