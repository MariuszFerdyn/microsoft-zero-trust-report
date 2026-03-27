# CIS Microsoft 365 Foundations Benchmark v6.0.1 — Audit Script

## Quick Start

```powershell
.\CIS_M365_Benchmark_Full.ps1 `
    -TenantId           "425b12b1-c9cc-4a2a-98e7-0a7210548876" `
    -AppId              "7c2ed792-2d24-4ff6-a184-5b3b0a77883e" `
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
APP_NAME="CIS-M365-Benchmark-Audit" && APP=$(az ad app create --display-name "$APP_NAME" --query "{appId:appId,id:id}" -o json) && APP_ID=$(echo $APP | python -c "import sys,json;print(json.load(sys.stdin)['appId'])") && SP_OBJ=$(az ad sp create --id $APP_ID --query id -o tsv) && SECRET=$(az ad app credential reset --id $APP_ID --display-name "CISAuditSecret" --years 1 --query password -o tsv) && GRAPH_OBJ=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query "appRoles" -o json) && for PERM in "Policy.Read.All" "Policy.Read.AuthenticationMethod" "AuditLog.Read.All" "Directory.Read.All" "Domain.Read.All" "Group.Read.All" "User.Read.All" "Organization.Read.All" "RoleManagement.Read.All" "DeviceManagementConfiguration.Read.All" "DeviceManagementServiceConfig.Read.All" "PrivilegedAccess.Read.AzureAD" "InformationProtectionPolicy.Read.All" "SecurityEvents.Read.All" "IdentityRiskyUser.Read.All" "AccessReview.Read.All" "RoleManagement.Read.Directory" "Tenant.Read.All" "OrgSettings-Forms.ReadWrite.All" "Domain.Read.All" "SecurityEvents.Read.All" "IdentityRiskyUser.Read.All"; do GUID=$(echo $GRAPH_OBJ | python -c "import sys,json;roles=json.load(sys.stdin);match=[r['id'] for r in roles if r['value']=='$PERM'];print(match[0] if match else 'NOT_FOUND')"); if [ "$GUID" != "NOT_FOUND" ]; then az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 --api-permissions "$GUID=Role" 2>/dev/null && echo "  + $PERM ($GUID)"; else echo "  ! $PERM NOT FOUND"; fi; done && PBI_OBJ=$(az ad sp show --id 00000009-0000-0000-c000-000000000000 --query "appRoles" -o json) && PBI_GUID=$(echo $PBI_OBJ | python -c "import sys,json;roles=json.load(sys.stdin);match=[r['id'] for r in roles if r.get('value')=='Tenant.Read.All'];print(match[0] if match else 'NOT_FOUND')") && if [ "$PBI_GUID" != "NOT_FOUND" ]; then az ad app permission add --id $APP_ID --api 00000009-0000-0000-c000-000000000000 --api-permissions "$PBI_GUID=Role" 2>/dev/null && echo "  + PowerBI Tenant.Read.All ($PBI_GUID)"; else echo "  ! PowerBI Tenant.Read.All NOT FOUND"; fi && az ad app permission admin-consent --id $APP_ID && echo "" && echo "=== Done ===" && echo "TenantId:           $(az account show --query tenantId -o tsv)" && echo "AppId:              $APP_ID" && echo "AppSecret:          $SECRET" && echo "ObjectId (SP):      $SP_OBJ"
```

#### One-liner (optional) — Same as above + Exchange Online app-only (`Exchange.ManageAsApp`)

Use this if you want the script to attempt **unattended Exchange Online** (no device-code prompt). You still must assign the app in **Exchange Admin Center** to the `View-Only Organization Management` role (see the Exchange section below).

```bash
APP_NAME="CIS-M365-Benchmark-Audit" && APP=$(az ad app create --display-name "$APP_NAME" --query "{appId:appId,id:id}" -o json) && APP_ID=$(echo $APP | python -c "import sys,json;print(json.load(sys.stdin)['appId'])") && SP_OBJ=$(az ad sp create --id $APP_ID --query id -o tsv) && SECRET=$(az ad app credential reset --id $APP_ID --display-name "CISAuditSecret" --years 1 --query password -o tsv) && GRAPH_OBJ=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query "appRoles" -o json) && for PERM in "Policy.Read.All" "Policy.Read.AuthenticationMethod" "AuditLog.Read.All" "Directory.Read.All" "Domain.Read.All" "Group.Read.All" "User.Read.All" "Organization.Read.All" "RoleManagement.Read.All" "DeviceManagementConfiguration.Read.All" "DeviceManagementServiceConfig.Read.All" "PrivilegedAccess.Read.AzureAD" "InformationProtectionPolicy.Read.All" "SecurityEvents.Read.All" "IdentityRiskyUser.Read.All" "AccessReview.Read.All" "RoleManagement.Read.Directory" "Tenant.Read.All" "OrgSettings-Forms.ReadWrite.All" "Domain.Read.All" "SecurityEvents.Read.All" "IdentityRiskyUser.Read.All"; do GUID=$(echo $GRAPH_OBJ | python -c "import sys,json;roles=json.load(sys.stdin);match=[r['id'] for r in roles if r['value']=='$PERM'];print(match[0] if match else 'NOT_FOUND')"); if [ "$GUID" != "NOT_FOUND" ]; then az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 --api-permissions "$GUID=Role" 2>/dev/null && echo "  + $PERM ($GUID)"; else echo "  ! $PERM NOT FOUND"; fi; done && PBI_OBJ=$(az ad sp show --id 00000009-0000-0000-c000-000000000000 --query "appRoles" -o json) && PBI_GUID=$(echo $PBI_OBJ | python -c "import sys,json;roles=json.load(sys.stdin);match=[r['id'] for r in roles if r.get('value')=='Tenant.Read.All'];print(match[0] if match else 'NOT_FOUND')") && if [ "$PBI_GUID" != "NOT_FOUND" ]; then az ad app permission add --id $APP_ID --api 00000009-0000-0000-c000-000000000000 --api-permissions "$PBI_GUID=Role" 2>/dev/null && echo "  + PowerBI Tenant.Read.All ($PBI_GUID)"; else echo "  ! PowerBI Tenant.Read.All NOT FOUND"; fi && EXO_OBJ=$(az ad sp show --id 00000002-0000-0ff1-ce00-000000000000 --query "appRoles" -o json) && EXO_GUID=$(echo $EXO_OBJ | python -c "import sys,json;roles=json.load(sys.stdin);match=[r['id'] for r in roles if r.get('value')=='Exchange.ManageAsApp'];print(match[0] if match else 'NOT_FOUND')") && if [ "$EXO_GUID" != "NOT_FOUND" ]; then az ad app permission add --id $APP_ID --api 00000002-0000-0ff1-ce00-000000000000 --api-permissions "$EXO_GUID=Role" 2>/dev/null && echo "  + EXO Exchange.ManageAsApp ($EXO_GUID)"; else echo "  ! EXO Exchange.ManageAsApp NOT FOUND"; fi && az ad app permission admin-consent --id $APP_ID && echo "" && echo "=== Done ===" && echo "TenantId:           $(az account show --query tenantId -o tsv)" && echo "AppId:              $APP_ID" && echo "AppSecret:          $SECRET" && echo "ObjectId (SP):      $SP_OBJ"
```

#### One-liner (optional) — Assign Entra admin roles to the Service Principal (Power BI + Intune)

Some checks still require Entra **directory roles** on the service principal (this is separate from API permissions). Run this after creating the app.

Prereq: you must be signed in with an account that can assign directory roles (typically Global Admin / Privileged Role Admin).

Note: the **Power BI admin** role name can vary by tenant. In some tenants it appears as **Power BI Administrator**, in others **Power BI Service Administrator** (and in newer tenants you may see **Fabric Administrator** instead). The snippet below tries common names and prints what it finds.

```bash
# Replace with the Service Principal ObjectId that the earlier one-liner prints (SP_OBJ)
SP_OBJ="<service principal objectId>" \
&& PBI_ROLE=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=id,displayName" --query "value[?displayName=='Power BI Administrator'].displayName | [0]" -o tsv) \
&& if [ -z "$PBI_ROLE" ]; then PBI_ROLE=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=id,displayName" --query "value[?displayName=='Power BI Service Administrator'].displayName | [0]" -o tsv); fi \
&& if [ -z "$PBI_ROLE" ]; then PBI_ROLE=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=id,displayName" --query "value[?displayName=='Fabric Administrator'].displayName | [0]" -o tsv); fi \
&& if [ -z "$PBI_ROLE" ]; then echo "  ! Could not find a Power BI admin role template in this tenant."; echo "  i Available templates containing 'Power BI' or 'Fabric':"; az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=displayName" --query "value[?contains(displayName,'Power BI') || contains(displayName,'Fabric')].displayName" -o tsv; exit 1; fi \
&& for ROLE in "$PBI_ROLE" "Intune Administrator"; do \
    TEMPLATE_ID=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=id,displayName" --query "value[?displayName=='$ROLE'].id | [0]" -o tsv); \
    if [ -z "$TEMPLATE_ID" ]; then echo "  ! Role template not found: $ROLE"; continue; fi; \
    ROLE_ID=$(az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoles?$select=id,roleTemplateId" --query "value[?roleTemplateId=='$TEMPLATE_ID'].id | [0]" -o tsv); \
    if [ -z "$ROLE_ID" ]; then ROLE_ID=$(az rest --method POST --url "https://graph.microsoft.com/v1.0/directoryRoles" --headers "Content-Type=application/json" --body "{\"roleTemplateId\":\"$TEMPLATE_ID\"}" --query id -o tsv); fi; \
    if [ -z "$ROLE_ID" ]; then echo "  ! Failed to activate role: $ROLE"; continue; fi; \
    az rest --method POST --url "https://graph.microsoft.com/v1.0/directoryRoles/$ROLE_ID/members/\$ref" --headers "Content-Type=application/json" --body "{\"@odata.id\":\"https://graph.microsoft.com/v1.0/directoryObjects/$SP_OBJ\"}" >/dev/null \
        && echo "  + Assigned: $ROLE" \
        || echo "  ! Failed to assign: $ROLE"; \
done
```

Quick discovery (optional): list role templates containing “Power BI” / “Fabric”:

```bash
az rest --method GET --url "https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=displayName" --query "value[?contains(displayName,'Power BI') || contains(displayName,'Fabric')].displayName" -o table
```

If you enabled **Exchange Online app-only** (`Exchange.ManageAsApp`), also run the **PowerShell block below** to add the app/service principal to the Exchange role group `View-Only Organization Management`.

```powershell
# Run as an Exchange admin
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName "admin@yourtenant.com"

$AppId = "<your app registration AppId (clientId)>"
$sp = Get-ServicePrincipal -Identity $AppId

Add-RoleGroupMember -Identity "View-Only Organization Management" -Member $sp.ObjectId

Disconnect-ExchangeOnline -Confirm:$false
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
    "Policy.Read.AuthenticationMethod"     # Authentication Methods policy (5.2.x)
    "AuditLog.Read.All"
    "Directory.Read.All"
    "Domain.Read.All"
    "Group.Read.All"
    "User.Read.All"
    "Organization.Read.All"
    "RoleManagement.Read.All"
    "RoleManagement.Read.Directory"          # PIM role schedules
    "DeviceManagementConfiguration.Read.All" # Intune device settings (4.1)
    "DeviceManagementServiceConfig.Read.All" # Intune enrollment configurations (4.2)
    "PrivilegedAccess.Read.AzureAD"          # PIM management (5.3.1)
    "InformationProtectionPolicy.Read.All"   # DLP / sensitivity labels (3.x)
    "SecurityEvents.Read.All"
    "IdentityRiskyUser.Read.All"
    "AccessReview.Read.All"                  # Access reviews (5.3.3)
    "Tenant.Read.All"                        # Power BI checks via Graph beta fallback (9.x)
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

# Power BI Service app role (required for Section 9 Power BI REST API access)
PBI_OBJ=$(az ad sp show --id 00000009-0000-0000-c000-000000000000 --query "appRoles" -o json)
PBI_GUID=$(echo $PBI_OBJ | python -c "
import sys, json
roles = json.load(sys.stdin)
match = [r['id'] for r in roles if r.get('value') == 'Tenant.Read.All']
print(match[0] if match else 'NOT_FOUND')
")
echo "Power BI Service Tenant.Read.All GUID: $PBI_GUID"

if [ "$PBI_GUID" != "NOT_FOUND" ]; then
    az ad app permission add \
        --id $APP_ID \
        --api 00000009-0000-0000-c000-000000000000 \
        --api-permissions "$PBI_GUID=Role"
else
    echo "  ! Power BI Service Tenant.Read.All not found"
fi
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

# IMPORTANT: admin-consent silently skips Exchange Online's appRoleAssignment.
# You must create it directly via Graph API — otherwise the token will have no
# 'roles' claim and EXO will return 401 Unauthorized even though the permission
# appears in the portal.
EXO_SP_OBJ=$(az ad sp show --id 00000002-0000-0ff1-ce00-000000000000 --query id -o tsv)
az rest --method POST \
    --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_OBJ/appRoleAssignments" \
    --headers "Content-Type=application/json" \
    --body "{\"principalId\":\"$SP_OBJ\",\"resourceId\":\"$EXO_SP_OBJ\",\"appRoleId\":\"dc50a0fb-09a3-484d-be87-e023b12c6440\"}" \
    --output none 2>/dev/null || true
echo "  + Exchange.ManageAsApp appRoleAssignment created (or already existed)"
```

Then in **Exchange Admin Center (EAC)**:  
`Roles → Admin roles → View-Only Organization Management → Members → Add → search for "CIS-M365-Benchmark-Audit"`

**PowerShell equivalent (does the same as the EAC step):**

```powershell
# Run as an Exchange admin
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName "admin@yourtenant.com"

$AppId = "<your app registration AppId (clientId)>"
$sp = Get-ServicePrincipal -Identity $AppId

# Add the app/service principal to the built-in role group
Add-RoleGroupMember -Identity "View-Only Organization Management" -Member $sp.ObjectId

Disconnect-ExchangeOnline -Confirm:$false
```

---

### Power BI — Add Tenant.Read.All Permission

Required for all Section 9 (Power BI) checks.  
Section 9 attempts the **Power BI REST API** first, then falls back to **Microsoft Graph beta**.

- **Power BI REST API** requires **Power BI Service** → `Tenant.Read.All` (Application) + admin consent.
- **Graph beta fallback** requires **Microsoft Graph** → `Tenant.Read.All` (Application) + admin consent (the one-liner above already includes this).

```bash
# Resolve Power BI Service Tenant.Read.All GUID dynamically
PBI_OBJ=$(az ad sp show --id 00000009-0000-0000-c000-000000000000 --query "appRoles" -o json)
TENANT_GUID=$(echo $PBI_OBJ | python -c "
import sys, json
roles = json.load(sys.stdin)
match = [r['id'] for r in roles if r['value'] == 'Tenant.Read.All']
print(match[0] if match else 'NOT_FOUND')
")
echo "Power BI Service Tenant.Read.All GUID: $TENANT_GUID"

az ad app permission add \
    --id $APP_ID \
    --api 00000009-0000-0000-c000-000000000000 \
    --api-permissions "$TENANT_GUID=Role"

az ad app permission admin-consent --id $APP_ID
```

> **Portal equivalent:** App Registrations → CIS-M365-Benchmark-Audit → API Permissions
> - Add a permission → APIs my organization uses → **Power BI Service** → Application permissions → **Tenant.Read.All** → Add
> - (Optional but recommended) Add a permission → Microsoft Graph → Application permissions → **Tenant.Read.All** → Add
> - Grant admin consent

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
