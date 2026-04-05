<#
.SYNOPSIS
  Step-by-step helper to create/update the CIS audit app registration and set permissions.

.DESCRIPTION
  Uses Azure CLI (az) to:
    - Create or reuse an Entra ID App Registration
    - Ensure a Service Principal exists
    - Create a client secret (optional)
    - Add Microsoft Graph application permissions (app roles)
    - Add Power BI Service application permission: Tenant.Read.All
    - Optionally add Exchange Online application permission: Exchange.ManageAsApp
    - Grant admin consent
    - Create a security group for Power BI / Fabric service-principal access and
      verify the required Fabric tenant settings
    - Assign Entra directory roles to the service principal (by default; use -SkipDirectoryRoles to opt out):
        * Power BI Administrator (or Power BI Service Administrator / Fabric Administrator)
        * Intune Administrator
    - Verify all granted permissions and report missing ones (dynamic check)

  Notes:
    - Directory roles assignment requires you to run this while signed in as an account
      that can assign directory roles (Global Admin / Privileged Role Admin).
    - Exchange app-only also requires adding the SP to an Exchange role group (separate step).

.EXAMPLE
  # Create a new app and configure Graph + Power BI permissions
  .\CIS_M365_Permissions.ps1 -TenantId "<tenant-guid>" -AppName "CIS-M365-Benchmark-Audit"

.EXAMPLE
  # Reuse an existing appId, include Exchange (directory roles are assigned by default)
  .\CIS_M365_Permissions.ps1 -TenantId "<tenant-guid>" -AppId "<app-guid>" -IncludeExchange

.EXAMPLE
  # Skip directory role assignment (Power BI Admin, Intune Admin)
  .\CIS_M365_Permissions.ps1 -TenantId "<tenant-guid>" -SkipDirectoryRoles

.EXAMPLE
  # Auto-login to the expected tenant if Azure CLI is logged into a different one
  .\CIS_M365_Permissions.ps1 -TenantId "<tenant-guid>" -AutoLogin
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)]
  [string]$TenantId,

  [Parameter(Mandatory = $false)]
  [string]$AppName = "CIS-M365-Benchmark-Audit",

  [Parameter(Mandatory = $false)]
  [string]$AppId,

  [Parameter(Mandatory = $false)]
  [switch]$NoSecret,

  [Parameter(Mandatory = $false)]
  [int]$SecretYears = 1,

  [Parameter(Mandatory = $false)]
  [switch]$IncludeExchange,

  [Parameter(Mandatory = $false)]
  [switch]$SkipDirectoryRoles,

  [Parameter(Mandatory = $false)]
  [switch]$NoPause,

  [Parameter(Mandatory = $false)]
  [switch]$AutoLogin,

  # UPN of an Exchange admin - used to connect and run New-ServicePrincipal + Add-RoleGroupMember.
  # Required when -IncludeExchange is set and you want fully automated EXO app-only setup.
  [Parameter(Mandatory = $false)]
  [string]$ExchangeAdminUPN,

  # Primary domain of the tenant (e.g. contoso.onmicrosoft.com).
  # Used to generate the benchmark run command shown at the end.
  [Parameter(Mandatory = $false)]
  [string]$TenantDomain,

  # SharePoint admin URL (e.g. https://contoso-admin.sharepoint.com).
  # Used to generate the benchmark run command shown at the end.
  [Parameter(Mandatory = $false)]
  [string]$SharePointAdminUrl,

  [Parameter(Mandatory = $false)]
  [string]$OutputPath = ".\CIS_M365_Permissions_Output.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# EXO setup is always needed for a full benchmark run — default to enabled.
# Pass -IncludeExchange:$false explicitly to skip it.
if (-not $PSBoundParameters.ContainsKey('IncludeExchange')) {
  $IncludeExchange = [switch]::Present
}

$script:AzReauthAttempted = $false

function Test-AzAuthError([string]$Text) {
  if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
  return (
    $Text -match 'AADSTS50173' -or
    $Text -match '\binvalid_grant\b' -or
    $Text -match 'Status_InteractionRequired' -or
    $Text -match '\binteraction_required\b'
  )
}

function Repair-AzLogin([string]$ExpectedTenantId) {
  if (-not $AutoLogin) { return }
  if ($script:AzReauthAttempted) { return }

  $script:AzReauthAttempted = $true
  Write-Warn "Azure CLI auth needs refresh; re-authenticating for tenant $ExpectedTenantId"

  # Best-effort cleanup; ignore errors
  $prevEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    & az logout 2>&1 | Out-Null
    & az login --tenant $ExpectedTenantId --scope "https://graph.microsoft.com/.default" 2>&1 | Out-Null
  } finally {
    $ErrorActionPreference = $prevEap
  }
}

function Write-Section([string]$Title) {
  Write-Host "" 
  Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) { Write-Host "  + $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "  ! $Message" -ForegroundColor Yellow }
function Write-Info([string]$Message) { Write-Host "  i $Message" -ForegroundColor DarkGray }

function Wait-Step {
  if (-not $NoPause) {
    [void](Read-Host "Press Enter to continue")
  }
}

function Wait-ManualStep([string]$Message = "Complete the manual step above, then type 'continue' to proceed") {
  if (-not $NoPause) {
    do {
      $response = Read-Host $Message
    } while ($response -ne 'continue')
  }
}

function Assert-Command([string]$Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Required command not found on PATH: $Name"
  }
}

function Invoke-Az {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$AzArgs,

    [Parameter(Mandatory = $false)]
    [switch]$ExpectJson
  )

  $cmdLine = "az " + ($AzArgs -join ' ')
  Write-Info $cmdLine

  if ($WhatIfPreference) {
    return $null
  }

  # Azure CLI writes warnings to stderr even on success; with $ErrorActionPreference='Stop'
  # PowerShell would treat that stderr as a terminating NativeCommandError. Avoid that and
  # rely on $LASTEXITCODE for failure detection.
  $prevEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = & az @AzArgs 2>&1
  } finally {
    $ErrorActionPreference = $prevEap
  }
  $exit = $LASTEXITCODE
  if ($exit -ne 0) {
    $raw = ($output | Out-String)
    if ($AutoLogin -and -not $script:AzReauthAttempted -and (Test-AzAuthError -Text $raw)) {
      Repair-AzLogin -ExpectedTenantId $TenantId
      return Invoke-Az -AzArgs $AzArgs -ExpectJson:$ExpectJson
    }
    throw "Azure CLI command failed ($exit): $cmdLine`n$raw"
  }

  if ($ExpectJson) {
    # On Windows PowerShell, 2>&1 captures stderr lines as ErrorRecord objects
    # mixed in with stdout strings. Filter to [string] only so that az.cmd
    # warnings/notices don't corrupt the JSON payload before parsing.
    $textLines = $output | Where-Object { $_ -is [string] }
    $text = ($textLines | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text | ConvertFrom-Json
  }

  # Same filter: drop stderr ErrorRecord objects (az warnings) so they don't
  # corrupt plain-text output such as a freshly-created client secret.
  $textLines = $output | Where-Object { $_ -is [string] }
  return ($textLines | Out-String).TrimEnd()
}

function Invoke-AzRestJson {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$Method,

    [Parameter(Mandatory = $true)]
    [string]$Url,

    [Parameter(Mandatory = $false)]
    [string]$BodyJson
  )

  $azArgs = @("rest", "--method", $Method, "--url", $Url, "-o", "json")
  $tmpBody = $null
  if ($BodyJson) {
    # Write body to a temp file to avoid shell escaping issues with special chars like '@odata.id'
    $tmpBody = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllText($tmpBody, $BodyJson, [System.Text.Encoding]::UTF8)
    $azArgs += @("--headers", "Content-Type=application/json", "--body", "@$tmpBody")
  }

  $cmdLine = "az " + ($azArgs -join ' ')
  Write-Info $cmdLine

  if ($WhatIfPreference) {
    return $null
  }

  $prevEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = & az @azArgs 2>&1
  } finally {
    $ErrorActionPreference = $prevEap
    if ($tmpBody -and (Test-Path $tmpBody)) { Remove-Item $tmpBody -Force -ErrorAction SilentlyContinue }
  }
  $exit = $LASTEXITCODE
  if ($exit -ne 0) {
    $raw = ($output | Out-String).TrimEnd()
    if ($AutoLogin -and -not $script:AzReauthAttempted -and (Test-AzAuthError -Text $raw)) {
      Repair-AzLogin -ExpectedTenantId $TenantId
      return Invoke-AzRestJson -Method $Method -Url $Url -BodyJson $BodyJson
    }
    throw "az rest failed ($exit): $Method $Url`n$raw"
  }

  # Same filter: strip ErrorRecord objects (stderr warnings) before JSON parsing
  $textLines = $output | Where-Object { $_ -is [string] }
  $text = ($textLines | Out-String).Trim()
  if ([string]::IsNullOrWhiteSpace($text)) { return $null }
  return $text | ConvertFrom-Json
}

function Get-AppRoleIdByValue([object[]]$AppRoles, [string]$Value) {
  if (-not $AppRoles) { return $null }

  $match = $AppRoles |
    Where-Object {
      $_.value -eq $Value -and
      ($_.isEnabled -ne $false) -and
      ($_.allowedMemberTypes -contains 'Application')
    } |
    Select-Object -First 1

  if (-not $match) { return $null }
  return $match.id
}

function Add-AppPermissionRole([string]$TargetAppId, [string]$ResourceAppId, [object[]]$ResourceAppRoles, [string]$RoleValue) {
  $roleId = Get-AppRoleIdByValue -AppRoles $ResourceAppRoles -Value $RoleValue
  if (-not $roleId) {
    Write-Warn "$RoleValue not found on resource $ResourceAppId"
    return $false
  }

  Invoke-Az -AzArgs @(
    "ad","app","permission","add",
    "--id", $TargetAppId,
    "--api", $ResourceAppId,
    "--api-permissions", "$roleId=Role"
  ) | Out-Null
  Write-Ok "$RoleValue ($roleId)"
  return $true
}

Write-Section "Preflight"
Assert-Command az

function Ensure-AzTenant([string]$ExpectedTenantId) {
  $acct = $null
  try {
    $acct = Invoke-Az -AzArgs @('account','show','-o','json') -ExpectJson
  } catch {
    if ($AutoLogin) {
      Write-Warn "Azure CLI not logged in. Running: az login --tenant '$ExpectedTenantId'"
      Invoke-Az -AzArgs @('login','--tenant', $ExpectedTenantId) | Out-Null
      $acct = Invoke-Az -AzArgs @('account','show','-o','json') -ExpectJson
    } else {
      Write-Warn "Azure CLI not logged in. Run: az login --tenant '$ExpectedTenantId'"
      throw
    }
  }

  if (-not $acct.tenantId) {
    throw "Could not determine tenantId from 'az account show'."
  }

  if ($acct.tenantId -ne $ExpectedTenantId) {
    if ($AutoLogin) {
      Write-Warn "Azure CLI tenant is $($acct.tenantId), expected $ExpectedTenantId. Running: az login --tenant '$ExpectedTenantId'"
      Invoke-Az -AzArgs @('login','--tenant', $ExpectedTenantId) | Out-Null
      $acct = Invoke-Az -AzArgs @('account','show','-o','json') -ExpectJson
      if ($acct.tenantId -ne $ExpectedTenantId) {
        Write-Warn "Still on tenant $($acct.tenantId) after login attempt."
        throw "Tenant mismatch"
      }
    } else {
      Write-Warn "Azure CLI tenant is $($acct.tenantId), expected $ExpectedTenantId"
      Write-Info "Run: az login --tenant '$ExpectedTenantId'"
      throw "Tenant mismatch"
    }
  }

  return $acct
}

function Wait-ForEntraApplication([string]$TargetAppId, [int]$MaxAttempts = 12, [int]$DelaySeconds = 5) {
  for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    try {
      $app = Invoke-Az -AzArgs @("ad","app","show","--id", $TargetAppId, "-o","json") -ExpectJson
      if ($app -and $app.appId -eq $TargetAppId) {
        if ($attempt -gt 1) {
          Write-Info "App registration is now visible in Entra ID (attempt $attempt/$MaxAttempts)"
        }
        return $app
      }
    } catch {
      if ($attempt -eq 1) {
        Write-Info "Waiting for new app registration to replicate in Entra ID..."
      }
    }

    if ($attempt -lt $MaxAttempts) {
      Start-Sleep -Seconds $DelaySeconds
    }
  }

  throw "Timed out waiting for app registration '$TargetAppId' to become available in Entra ID."
}

function Ensure-ServicePrincipalForApp([string]$TargetAppId, [int]$MaxAttempts = 12, [int]$DelaySeconds = 5) {
  for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
    try {
      $sp = Invoke-Az -AzArgs @("ad","sp","show","--id", $TargetAppId, "-o","json") -ExpectJson
      if ($sp -and $sp.id) {
        return [PSCustomObject]@{ ObjectId = $sp.id; Created = $false }
      }
    } catch { }

    try {
      $spObjId = Invoke-Az -AzArgs @("ad","sp","create","--id", $TargetAppId, "--query","id","-o","tsv")
      if (-not [string]::IsNullOrWhiteSpace($spObjId)) {
        return [PSCustomObject]@{ ObjectId = $spObjId.Trim(); Created = $true }
      }
    } catch {
      $msg = $_.Exception.Message
      $isRetryable = (
        $msg -match "does not reference a valid application object" -or
        $msg -match "does not exist or one of its queried reference-property objects are not present" -or
        $msg -match "Request_ResourceNotFound"
      )

      if ((-not $isRetryable) -or $attempt -eq $MaxAttempts) {
        throw
      }

      if ($attempt -eq 1) {
        Write-Info "Service principal creation is waiting for Entra replication..."
      }
    }

    Start-Sleep -Seconds $DelaySeconds
  }

  throw "Timed out creating service principal for app '$TargetAppId'."
}

# Ensure we are logged in and tenant matches
$acct = Ensure-AzTenant -ExpectedTenantId $TenantId
Write-Ok "Azure CLI logged in to tenant $TenantId"
Wait-Step

Write-Section "Create or reuse App Registration"
if (-not $AppId) {
  $app = Invoke-Az -AzArgs @("ad","app","create","--display-name", $AppName, "-o","json") -ExpectJson
  $AppId = $app.appId
  Wait-ForEntraApplication -TargetAppId $AppId | Out-Null
  Write-Ok "Created app: $AppName"
  Write-Ok "AppId: $AppId"
} else {
  # Verify app exists
  Wait-ForEntraApplication -TargetAppId $AppId | Out-Null
  Write-Ok "Using existing AppId: $AppId"
}
Wait-Step

Write-Section "Ensure Service Principal"
$spResult = Ensure-ServicePrincipalForApp -TargetAppId $AppId
$spObjId = $spResult.ObjectId
if ($spResult.Created) {
  Write-Ok "Created service principal"
} else {
  Write-Ok "Service principal exists"
}
Write-Ok "ObjectId (SP): $spObjId"
Wait-Step

Write-Section "Create client secret (optional)"
$secret = $null
if (-not $NoSecret) {
  $secret = Invoke-Az -AzArgs @(
    "ad","app","credential","reset",
    "--id", $AppId,
    "--display-name", "CISAuditSecret",
    "--years", "$SecretYears",
    "--query","password",
    "-o","tsv"
  )
  Write-Ok "Created client secret (store it securely)"
  Write-Warn "This is the ONLY time you can retrieve the secret value."
  Write-Host "  Secret: $secret" -ForegroundColor Magenta
} else {
  Write-Info "Skipped creating secret"
}
Wait-Step

Write-Section "Add application permissions (Microsoft Graph + Power BI + optional Exchange)"
$graphResource = "00000003-0000-0000-c000-000000000000"
$pbiResource   = "00000009-0000-0000-c000-000000000000"
$exoResource   = "00000002-0000-0ff1-ce00-000000000000"

# Fetch resource appRoles
$graphAppRoles = Invoke-Az -AzArgs @("ad","sp","show","--id", $graphResource, "--query","appRoles","-o","json") -ExpectJson
$pbiAppRoles   = Invoke-Az -AzArgs @("ad","sp","show","--id", $pbiResource, "--query","appRoles","-o","json") -ExpectJson
$exoAppRoles   = $null
if ($IncludeExchange) {
  $exoAppRoles = Invoke-Az -AzArgs @("ad","sp","show","--id", $exoResource, "--query","appRoles","-o","json") -ExpectJson
}

# Graph permissions needed by the audit script
$graphPerms = @(
  "Policy.Read.All",
  "Policy.Read.AuthenticationMethod",
  "AuditLog.Read.All",
  "Directory.Read.All",
  "Domain.Read.All",
  "Group.Read.All",
  "User.Read.All",
  "Organization.Read.All",
  "RoleManagement.Read.All",
  "RoleManagement.Read.Directory",
  "DeviceManagementConfiguration.Read.All",
  "DeviceManagementServiceConfig.Read.All",
  "PrivilegedAccess.Read.AzureAD",
  "InformationProtectionPolicy.Read.All",
  "SecurityEvents.Read.All",
  "IdentityRiskyUser.Read.All",
  "AccessReview.Read.All",
  "OrgSettings-Forms.ReadWrite.All",
  "UserAuthenticationMethod.Read.All"
) | Sort-Object -Unique

Write-Info "Adding Microsoft Graph app roles..."
foreach ($perm in $graphPerms) {
  Add-AppPermissionRole -TargetAppId $AppId -ResourceAppId $graphResource -ResourceAppRoles $graphAppRoles -RoleValue $perm | Out-Null
}

Write-Info "Adding Power BI Service app role..."
Add-AppPermissionRole -TargetAppId $AppId -ResourceAppId $pbiResource -ResourceAppRoles $pbiAppRoles -RoleValue "Tenant.Read.All" | Out-Null

if ($IncludeExchange) {
  Write-Info "Adding Exchange Online app role..."
  Add-AppPermissionRole -TargetAppId $AppId -ResourceAppId $exoResource -ResourceAppRoles $exoAppRoles -RoleValue "Exchange.ManageAsApp" | Out-Null
}

Wait-Step

Write-Section "Grant admin consent"
Invoke-Az -AzArgs @("ad","app","permission","admin-consent","--id", $AppId) | Out-Null
Write-Ok "Admin consent granted"

# 'az ad app permission admin-consent' often silently skips non-Graph APIs
# (Power BI Service, Exchange Online). We must create the appRoleAssignment
# directly via Graph API to ensure the permission is actually granted.

# --- Power BI: Tenant.Read.All ---
Write-Info "Directly creating Power BI Tenant.Read.All appRoleAssignment (admin-consent may skip PBI)..."
$pbiSpObjectId = $null
try {
  $pbiSpObjectId = Invoke-Az -AzArgs @("ad","sp","show","--id", $pbiResource, "--query","id","-o","tsv")
  $pbiSpObjectId = $pbiSpObjectId.Trim()
} catch {
  Write-Warn "Could not resolve Power BI Service SP ObjectId - skipping direct appRoleAssignment: $_"
}

if ($pbiSpObjectId) {
  $pbiTenantReadRole = ($pbiAppRoles | Where-Object { $_.value -eq "Tenant.Read.All" }).id
  if ($pbiTenantReadRole) {
    $assignBody = @{
      principalId = $spObjId
      resourceId  = $pbiSpObjectId
      appRoleId   = $pbiTenantReadRole
    } | ConvertTo-Json -Compress

    try {
      Invoke-AzRestJson -Method POST `
        -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjId/appRoleAssignments" `
        -BodyJson $assignBody | Out-Null
      Write-Ok "Power BI Tenant.Read.All appRoleAssignment created"
    } catch {
      $msg = $_.Exception.Message
      if ($msg -match "already exist" -or $msg -match "Permission being assigned already exists") {
        Write-Ok "Power BI Tenant.Read.All appRoleAssignment already exists"
      } else {
        Write-Warn "Failed to create Power BI Tenant.Read.All appRoleAssignment: $msg"
      }
    }
  } else {
    Write-Warn "Could not find Tenant.Read.All role ID in Power BI Service app roles"
  }
}

# --- Exchange Online: Exchange.ManageAsApp ---
if ($IncludeExchange) {
  Write-Info "Directly creating Exchange.ManageAsApp appRoleAssignment (admin-consent skips EXO)..."

  # Resolve the Exchange Online SP ObjectId in this tenant
  $exoSpObjectId = $null
  try {
    $exoSpObjectId = Invoke-Az -AzArgs @("ad","sp","show","--id", $exoResource, "--query","id","-o","tsv")
    $exoSpObjectId = $exoSpObjectId.Trim()
  } catch {
    Write-Warn "Could not resolve Exchange Online SP ObjectId - skipping direct appRoleAssignment: $_"
  }

  if ($exoSpObjectId) {
    $exoManageAsAppRoleId = "dc50a0fb-09a3-484d-be87-e023b12c6440"
    $assignBody = @{
      principalId = $spObjId
      resourceId  = $exoSpObjectId
      appRoleId   = $exoManageAsAppRoleId
    } | ConvertTo-Json -Compress

    try {
      Invoke-AzRestJson -Method POST `
        -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjId/appRoleAssignments" `
        -BodyJson $assignBody | Out-Null
      Write-Ok "Exchange.ManageAsApp appRoleAssignment created"
    } catch {
      $msg = $_.Exception.Message
      if ($msg -match "already exist" -or $msg -match "Permission being assigned already exists") {
        Write-Ok "Exchange.ManageAsApp appRoleAssignment already exists"
      } else {
        Write-Warn "Failed to create Exchange.ManageAsApp appRoleAssignment: $msg"
      }
    }
  }
}

Wait-Step

if ($IncludeExchange) {
  Write-Section "Register SP in Exchange Online (New-ServicePrincipal + role group)"

  # Two steps are BOTH required for app-only EXO access:
  #   1. New-ServicePrincipal  - registers the app SP inside Exchange Online's own RBAC directory.
  #      Without this, Connect-ExchangeOnline -AccessToken fails even if the Entra
  #      appRoleAssignment (Exchange.ManageAsApp) already exists.
  #   2. Add-RoleGroupMember   — grants the SP the read permissions it needs for audit checks.

  $exoUpn = $ExchangeAdminUPN
  if (-not $exoUpn -and -not $NoPause) {
    $exoUpn = Read-Host "  Exchange admin UPN (e.g. admin@tenant.com)  [blank = skip this step]"
  }

  $exoNeedsManualConfirm = $false

  if ($exoUpn) {
    try {
      if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue)) {
        Write-Warn "ExchangeOnlineManagement module not found. Installing..."
        Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
      }
      Import-Module ExchangeOnlineManagement -ErrorAction Stop -WarningAction SilentlyContinue
      Write-Info "Connecting to Exchange Online as $exoUpn ..."
      Connect-ExchangeOnline -UserPrincipalName $exoUpn -ShowBanner:$false -ErrorAction Stop

      Write-Info "Running New-ServicePrincipal ..."
      try {
        New-ServicePrincipal -AppId $AppId -ObjectId $spObjId -DisplayName $AppName -ErrorAction Stop | Out-Null
        Write-Ok "Registered SP in Exchange Online directory"
      } catch {
        $msg = $_.Exception.Message
        if ($msg -match "already exist" -or $msg -match "already registered") {
          Write-Ok "SP already registered in Exchange Online (OK)"
        } else {
          Write-Warn "New-ServicePrincipal: $msg"
        }
      }

      Write-Info "Running Add-RoleGroupMember ..."
      try {
        Add-RoleGroupMember -Identity "View-Only Organization Management" -Member $spObjId -ErrorAction Stop
        Write-Ok "Added SP to 'View-Only Organization Management'"
      } catch {
        $msg = $_.Exception.Message
        if ($msg -match "already a member") {
          Write-Ok "SP already in 'View-Only Organization Management' (OK)"
        } else {
          Write-Warn "Add-RoleGroupMember: $msg"
        }
      }

      Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
      Write-Ok "Exchange Online disconnected"
      # Automated setup completed -- no manual confirmation needed
    } catch {
      Write-Warn "Exchange Online setup failed: $($_.Exception.Message)"
      Write-Info "Run manually as Exchange admin:"
      Write-Info "  Connect-ExchangeOnline -UserPrincipalName $exoUpn"
      Write-Info "  New-ServicePrincipal -AppId '$AppId' -ObjectId '$spObjId' -DisplayName '$AppName'"
      Write-Info "  Add-RoleGroupMember -Identity 'View-Only Organization Management' -Member '$spObjId'"
      Write-Info "  Disconnect-ExchangeOnline -Confirm:`$false"
      $exoNeedsManualConfirm = $true
    }
  } else {
    $manualUpn = if ($domain -and $domain -notmatch 'YOUR-TENANT') { "admin@$domain" } else { 'admin@yourtenant.com' }
    Write-Warn "ExchangeAdminUPN not supplied - run these commands manually as Exchange admin:"
    Write-Info "  Connect-ExchangeOnline -UserPrincipalName $manualUpn"
    Write-Info "  New-ServicePrincipal -AppId '$AppId' -ObjectId '$spObjId' -DisplayName '$AppName'"
    Write-Info "  Add-RoleGroupMember -Identity 'View-Only Organization Management' -Member '$spObjId'"
    Write-Info "  Disconnect-ExchangeOnline -Confirm:`$false"
    $exoNeedsManualConfirm = $true
  }

  # Only ask for manual confirmation when the script couldn't do it automatically
  if ($exoNeedsManualConfirm -and -not $NoPause) {
    Write-Host ''
    Write-Host '  Have you run it manually?' -ForegroundColor Cyan
    Write-Host '  If so, type  continue  and press Enter to proceed.' -ForegroundColor Cyan
    Write-Host '  You can also skip by pressing Enter -- Exchange Online will NOT be examined in the benchmark.' -ForegroundColor DarkGray
    Write-Host ''
    $exoAnswer = Read-Host '  Your answer'
    if ($exoAnswer -notmatch '^\s*continue\s*$') {
      Write-Warn 'EXO step skipped -- Exchange Online will be excluded from the benchmark command.'
      $IncludeExchange = [switch]::new($false)
    }
  }
}

# ---------------------------------------------------------------------------
#  Power BI / Fabric: verify service principal API access requirements
#  This requires:
#    a) a security group that contains the service principal
#    b) Fabric Admin API settings allowing that group
# ---------------------------------------------------------------------------
Write-Section "Power BI / Fabric: Verify service principal API access"

$pbiSecGroupName = "CIS-Audit-PowerBI-ServicePrincipals"
$pbiSecGroupId   = $null

# 1. Create or find the security group
try {
  $existingGroup = Invoke-Az -AzArgs @("ad","group","show","--group", $pbiSecGroupName, "-o","json") -ExpectJson
  $pbiSecGroupId = $existingGroup.id
  Write-Ok "Security group already exists: $pbiSecGroupName ($pbiSecGroupId)"
} catch {
  try {
    $newGroup = Invoke-Az -AzArgs @(
      "ad","group","create",
      "--display-name", $pbiSecGroupName,
      "--mail-nickname", "CISAuditPBISPs",
      "--description", "Service principals allowed to use Power BI Admin APIs for CIS benchmark audit",
      "-o","json"
    ) -ExpectJson
    $pbiSecGroupId = $newGroup.id
    Write-Ok "Created security group: $pbiSecGroupName ($pbiSecGroupId)"
  } catch {
    Write-Warn "Could not create security group: $($_.Exception.Message)"
  }
}

# 2. Add the service principal to the group
if ($pbiSecGroupId) {
  try {
    $isMember = $false
    try {
      $members = Invoke-Az -AzArgs @("ad","group","member","list","--group", $pbiSecGroupId, "--query","[].id","-o","json") -ExpectJson
      $isMember = $spObjId -in $members
    } catch { }

    if ($isMember) {
      Write-Ok "SP already a member of $pbiSecGroupName"
    } else {
      Invoke-Az -AzArgs @("ad","group","member","add","--group", $pbiSecGroupId, "--member-id", $spObjId) | Out-Null
      Write-Ok "Added SP to security group: $pbiSecGroupName"
    }
  } catch {
    $msg = $_.Exception.Message
    if ($msg -match "already exist") {
      Write-Ok "SP already a member of $pbiSecGroupName"
    } else {
      Write-Warn "Could not add SP to security group: $msg"
    }
  }
}

# 3. Read current Fabric tenant settings using the signed-in admin user
$pbiSettingDone = $false
if ($pbiSecGroupId) {
  try {
    $pbiAccessToken = Invoke-Az -AzArgs @("account","get-access-token","--resource","https://api.fabric.microsoft.com","--query","accessToken","-o","tsv")
    $pbiAccessToken = $pbiAccessToken.Trim()

    if ($pbiAccessToken) {
      $pbiHeaders = @{
        Authorization  = "Bearer $pbiAccessToken"
        'Content-Type' = 'application/json'
      }

      try {
        $currentSettings = Invoke-RestMethod -Method GET `
          -Uri "https://api.fabric.microsoft.com/v1/admin/tenantsettings" `
          -Headers $pbiHeaders -ErrorAction Stop

        $tenantSettings = @($currentSettings.value)
        $readAdminSetting = $tenantSettings | Where-Object { $_.settingName -eq "AllowServicePrincipalsUseReadAdminAPIs" } | Select-Object -First 1
        $publicApiSetting = $tenantSettings | Where-Object { $_.settingName -eq "ServicePrincipalAccessPermissionAPIs" } | Select-Object -First 1
        $profilesSetting = $tenantSettings | Where-Object { $_.settingName -eq "AllowServicePrincipalsCreateAndUseProfiles" } | Select-Object -First 1
        $workspaceSetting = $tenantSettings | Where-Object { $_.settingName -eq "ServicePrincipalAccessGlobalAPIs" } | Select-Object -First 1

        $readAdminGroupIds = @($readAdminSetting.enabledSecurityGroups | ForEach-Object { $_.graphId })
        $readAdminAppliesToSp = ($readAdminGroupIds.Count -eq 0) -or ($pbiSecGroupId -in $readAdminGroupIds)

        if ($readAdminSetting) {
          Write-Info "Fabric setting: $($readAdminSetting.title) => enabled=$($readAdminSetting.enabled)"
          if ($readAdminSetting.enabled -and $readAdminAppliesToSp) {
            Write-Ok "Fabric read-only admin APIs are enabled for this service principal (or its group)"
            $pbiSettingDone = $true
          }
        }
        if ($publicApiSetting) {
          Write-Info "Fabric setting: $($publicApiSetting.title) => enabled=$($publicApiSetting.enabled)"
        }
        if ($profilesSetting) {
          Write-Info "Fabric setting: $($profilesSetting.title) => enabled=$($profilesSetting.enabled)"
        }
        if ($workspaceSetting) {
          Write-Info "Fabric setting: $($workspaceSetting.title) => enabled=$($workspaceSetting.enabled)"
        }
      } catch { }
    }
  } catch {
    Write-Info "  Could not get Fabric API token: $($_.Exception.Message.Split([char]10)[0].Trim())"
  }
}

if (-not $pbiSettingDone) {
  Write-Warn "Manual step required for Power BI / Fabric Section 9 checks:"
  Write-Host "  1. Go to: https://app.powerbi.com/admin-portal/tenantSettings?experience=power-bi" -ForegroundColor Yellow
  Write-Host "  2. Under 'Admin API settings', enable 'Service principals can access read-only admin APIs'" -ForegroundColor Yellow
  if ($pbiSecGroupId) {
    Write-Host "  3. Under 'Apply to:', select 'Specific security groups' and add:" -ForegroundColor Yellow
    Write-Host "     Group: $pbiSecGroupName" -ForegroundColor Cyan
  } else {
    Write-Host "  3. Under 'Apply to:', add a security group containing the service principal" -ForegroundColor Yellow
  }
  Write-Host "  4. Under 'Developer settings', review the service-principal settings used by CIS 9.1.10-9.1.12:" -ForegroundColor Yellow
  Write-Host "     - Service principals can call Fabric public APIs" -ForegroundColor Yellow
  Write-Host "     - Allow service principals to create and use profiles" -ForegroundColor Yellow
  Write-Host "     - Service principals can create workspaces, connections, and deployment pipelines" -ForegroundColor Yellow
  Write-Host ""
  Wait-ManualStep
} else {
  Wait-Step
}

if (-not $SkipDirectoryRoles) {
  Write-Section "Assign Entra directory roles"

  $templates = Invoke-AzRestJson -Method GET -Url 'https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=id,displayName'
  $templateList = @($templates.value)

  $pbiRoleCandidates = @(
    "Power BI Administrator",
    "Power BI Service Administrator",
    "Fabric Administrator"
  )

  $pbiTemplate = $null
  foreach ($candidate in $pbiRoleCandidates) {
    $pbiTemplate = $templateList | Where-Object { $_.displayName -eq $candidate } | Select-Object -First 1
    if ($pbiTemplate) { break }
  }

  if (-not $pbiTemplate) {
    Write-Warn "Could not find a Power BI/Fabric admin role template by common names."
    $maybe = $templateList | Where-Object { $_.displayName -like '*Power BI*' -or $_.displayName -like '*Fabric*' } | Select-Object -ExpandProperty displayName
    if ($maybe) {
      Write-Info "Templates containing 'Power BI' or 'Fabric':"
      $maybe | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
    } else {
      Write-Info "No templates matched 'Power BI' or 'Fabric'."
    }
    throw "Power BI directory role template not found"
  }

  $rolesToAssign = @(
    @{ Name = $pbiTemplate.displayName; TemplateId = $pbiTemplate.id },
    @{ Name = "Intune Administrator"; TemplateId = ($templateList | Where-Object { $_.displayName -eq "Intune Administrator" } | Select-Object -First 1).id }
  )

  foreach ($r in $rolesToAssign) {
    if (-not $r.TemplateId) {
      Write-Warn "Role template not found: $($r.Name)"
      continue
    }

    # Find or activate directory role instance
    $dirRoles = Invoke-AzRestJson -Method GET -Url 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,roleTemplateId,displayName'
    $dirRole = @($dirRoles.value) | Where-Object { $_.roleTemplateId -eq $r.TemplateId } | Select-Object -First 1

    if (-not $dirRole) {
      Write-Info "Activating role: $($r.Name)"
      $activateBody = @{ roleTemplateId = $r.TemplateId } | ConvertTo-Json -Compress
      $dirRole = Invoke-AzRestJson -Method POST -Url "https://graph.microsoft.com/v1.0/directoryRoles" -BodyJson $activateBody
    }

    if (-not $dirRole.id) {
      Write-Warn "Failed to activate/find role: $($r.Name)"
      continue
    }

    $memberRefUrl = "https://graph.microsoft.com/v1.0/directoryRoles/$($dirRole.id)/members/`$ref"
    $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$spObjId" } | ConvertTo-Json -Compress

    try {
      Invoke-AzRestJson -Method POST -Url $memberRefUrl -BodyJson $body | Out-Null
      Write-Ok "Assigned directory role: $($r.Name)"
    } catch {
      # If already assigned, Graph returns a 400 with a message like "One or more added object references already exist"
      $msg = $_.Exception.Message
      if ($msg -match "already exist" -or $msg -match "added object references") {
        Write-Ok "Already assigned: $($r.Name)"
      } else {
        Write-Warn "Failed to assign: $($r.Name)"
        throw
      }
    }
  }

  Wait-Step
}

# Resolve display values for the benchmark run command.
# Fetch verified domains once so we can derive both TenantDomain and the SPO admin URL.
$orgDomains = @()
try {
  $orgDomains = @(Invoke-Az -AzArgs @(
    "rest","--method","get",
    "--url","https://graph.microsoft.com/v1.0/organization",
    "--query","value[0].verifiedDomains[].{name:name,isDefault:isDefault}",
    "-o","json"
  ) -ExpectJson)
} catch {
  Write-Warn "Could not auto-resolve tenant domains: $($_.Exception.Message)"
}

if ($TenantDomain) {
  $domain = $TenantDomain
} else {
  $defaultDomain = ($orgDomains | Where-Object { $_.isDefault } | Select-Object -First 1).name
  $domain = if ($defaultDomain) { $defaultDomain } else { 'YOUR-TENANT.onmicrosoft.com' }
}

if ($SharePointAdminUrl) {
  $spoUrl = $SharePointAdminUrl
} else {
  $onmsDomain = ($orgDomains | Where-Object { $_.name -like '*.onmicrosoft.com' } | Select-Object -First 1).name
  if ($onmsDomain) {
    $prefix = $onmsDomain -replace '\.onmicrosoft\.com$', ''
    $spoUrl = "https://$prefix-admin.sharepoint.com"
  } else {
    $spoUrl = 'https://YOUR-TENANT-admin.sharepoint.com'
  }
}

if ($secret) { $secretDisplay = $secret } else { $secretDisplay = 'YOUR-CLIENT-SECRET' }

Write-Section "Output"

# ---------------------------------------------------------------------------
#  Verify granted permissions (dynamic check)
# ---------------------------------------------------------------------------
Write-Info "Verifying granted permissions..."
$grantedRoles = @()
try {
  $grantedRoles = @(Invoke-AzRestJson -Method GET `
    -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjId/appRoleAssignments?`$select=appRoleId,resourceDisplayName" |
    Select-Object -ExpandProperty value)
} catch {
  Write-Warn "Could not query granted permissions: $($_.Exception.Message)"
}

if ($grantedRoles.Count -gt 0) {
  # Build a lookup: appRoleId -> permission name for Graph, PBI, EXO
  $allAppRoleLookup = @{}
  @($graphAppRoles) | ForEach-Object { $allAppRoleLookup[$_.id] = $_.value }
  @($pbiAppRoles)   | ForEach-Object { $allAppRoleLookup[$_.id] = $_.value }
  if ($exoAppRoles) {
    @($exoAppRoles)  | ForEach-Object { $allAppRoleLookup[$_.id] = $_.value }
  }

  $grantedPermNames = $grantedRoles | ForEach-Object { $allAppRoleLookup[$_.appRoleId] } | Where-Object { $_ }

  # Required permissions list
  $requiredPerms = @(
    @{ Scope = "Policy.Read.All";                          Api = "Graph" },
    @{ Scope = "Policy.Read.AuthenticationMethod";         Api = "Graph" },
    @{ Scope = "AuditLog.Read.All";                        Api = "Graph" },
    @{ Scope = "Directory.Read.All";                       Api = "Graph" },
    @{ Scope = "Domain.Read.All";                          Api = "Graph" },
    @{ Scope = "Group.Read.All";                           Api = "Graph" },
    @{ Scope = "User.Read.All";                            Api = "Graph" },
    @{ Scope = "Organization.Read.All";                    Api = "Graph" },
    @{ Scope = "RoleManagement.Read.All";                  Api = "Graph" },
    @{ Scope = "RoleManagement.Read.Directory";            Api = "Graph" },
    @{ Scope = "DeviceManagementConfiguration.Read.All";   Api = "Graph" },
    @{ Scope = "DeviceManagementServiceConfig.Read.All";   Api = "Graph" },
    @{ Scope = "PrivilegedAccess.Read.AzureAD";            Api = "Graph" },
    @{ Scope = "InformationProtectionPolicy.Read.All";     Api = "Graph" },
    @{ Scope = "SecurityEvents.Read.All";                  Api = "Graph" },
    @{ Scope = "IdentityRiskyUser.Read.All";               Api = "Graph" },
    @{ Scope = "AccessReview.Read.All";                    Api = "Graph" },
    @{ Scope = "OrgSettings-Forms.ReadWrite.All";          Api = "Graph" },
    @{ Scope = "UserAuthenticationMethod.Read.All";        Api = "Graph" },
    @{ Scope = "Tenant.Read.All";                          Api = "Power BI" }
  )
  if ($IncludeExchange) {
    $requiredPerms += @{ Scope = "Exchange.ManageAsApp"; Api = "Exchange" }
  }

  $missing  = @($requiredPerms | Where-Object { $_.Scope -notin $grantedPermNames })
  $granted  = @($requiredPerms | Where-Object { $_.Scope -in $grantedPermNames })

  Write-Host ""
  if ($granted.Count -gt 0) {
    Write-Host "  Granted permissions ($($granted.Count)):" -ForegroundColor Green
    foreach ($p in $granted) {
      Write-Host "    [OK] $($p.Scope)  ($($p.Api))" -ForegroundColor Green
    }
  }
  if ($missing.Count -gt 0) {
    Write-Host "  Missing permissions ($($missing.Count)):" -ForegroundColor Red
    foreach ($p in $missing) {
      Write-Host "    [!!] $($p.Scope)  ($($p.Api))" -ForegroundColor Red
    }
    Write-Host ""
    Write-Warn "Some permissions were not granted. Re-run admin consent or check the Entra portal."
    Write-Host "  az ad app permission admin-consent --id $AppId" -ForegroundColor Gray
  } else {
    Write-Host ""
    Write-Ok "All required API permissions are granted."
  }
  Write-Host ""

  # Check directory role assignments
  $roleAssignments = @()
  try {
    $memberOf = Invoke-AzRestJson -Method GET `
      -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjId/memberOf?`$select=displayName,roleTemplateId"
    $roleAssignments = @($memberOf.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' })
  } catch { }

  $requiredRoles = @("Power BI Administrator", "Power BI Service Administrator", "Fabric Administrator", "Intune Administrator")
  $hasPBI    = $roleAssignments | Where-Object { $_.displayName -in @("Power BI Administrator","Power BI Service Administrator","Fabric Administrator") }
  $hasIntune = $roleAssignments | Where-Object { $_.displayName -eq "Intune Administrator" }

  Write-Host "  Directory role assignments:" -ForegroundColor Yellow
  if ($hasPBI)    { Write-Host "    [OK] $($hasPBI.displayName | Select-Object -First 1)" -ForegroundColor Green }
  else            { Write-Host "    [!!] Power BI / Fabric Administrator  (not assigned)" -ForegroundColor Red }
  if ($hasIntune) { Write-Host "    [OK] Intune Administrator" -ForegroundColor Green }
  else            { Write-Host "    [!!] Intune Administrator  (not assigned)" -ForegroundColor Red }

  # Power BI API access check
  if (-not $pbiSettingDone) {
    Write-Host "    [!!] 'Service principals can access read-only admin APIs' may need manual enablement (see above)" -ForegroundColor Yellow
  } else {
    Write-Host "    [OK] Service principals can access read-only admin APIs" -ForegroundColor Green
  }
  Write-Host ""
}
$result = [ordered]@{
  TenantId                 = $TenantId
  TenantDomain             = $domain
  AppName                  = $AppName
  AppId                    = $AppId
  ServicePrincipalObjectId = $spObjId
  ClientSecret             = $secret
  SharePointAdminUrl       = $spoUrl
  IncludeExchange          = [bool]$IncludeExchange
  AssignedDirectoryRoles   = (-not $SkipDirectoryRoles)
  GeneratedAt              = (Get-Date).ToString('o')
}

($result | ConvertTo-Json -Depth 5) | Set-Content -Path $OutputPath -Encoding UTF8
Write-Ok "Wrote: $OutputPath"

Write-Host ''
Write-Host '  === Run the benchmark with: ===' -ForegroundColor Cyan
Write-Host ''
Write-Host "  .\CIS_M365_Benchmark_Full.ps1" -ForegroundColor White
Write-Host "      -TenantId           $TenantId" -ForegroundColor White
Write-Host "      -AppId              $AppId" -ForegroundColor White
Write-Host "      -AppSecret          $secretDisplay" -ForegroundColor White
Write-Host "      -TenantDomain       $domain" -ForegroundColor White
Write-Host "      -SharePointAdminUrl $spoUrl" -ForegroundColor White
if (-not $IncludeExchange) {
  Write-Host "      -GraphOnlyMode" -ForegroundColor DarkYellow
  Write-Host '' 
  Write-Host '  Note: -GraphOnlyMode added because EXO registration was skipped.' -ForegroundColor DarkYellow
  Write-Host '  Re-run CIS_M365_Permissions.ps1 with -ExchangeAdminUPN to enable EXO checks.' -ForegroundColor DarkYellow
}
Write-Host ''

if (-not $NoPause) {
  $runNow = Read-Host '  Run benchmark now? [Y/N]'
  if ($runNow -match '^[Yy]') {
    $benchmarkPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'CIS_M365_Benchmark_Full.ps1'
    if (Test-Path $benchmarkPath) {
      $benchmarkArgs = @{
        TenantId           = $TenantId
        AppId              = $AppId
        AppSecret          = $secretDisplay
        TenantDomain       = $domain
        SharePointAdminUrl = $spoUrl
      }
      if (-not $IncludeExchange) { $benchmarkArgs['GraphOnlyMode'] = $true }
      & $benchmarkPath @benchmarkArgs
    } else {
      Write-Warn "Script not found: $benchmarkPath"
      Write-Info 'Make sure both scripts are in the same directory.'
    }
  }
}

