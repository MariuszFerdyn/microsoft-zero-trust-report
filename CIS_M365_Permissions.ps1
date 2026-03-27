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
    - Optionally assign Entra directory roles to the service principal:
        * Power BI Administrator (or Power BI Service Administrator / Fabric Administrator)
        * Intune Administrator

  Notes:
    - Directory roles assignment requires you to run this while signed in as an account
      that can assign directory roles (Global Admin / Privileged Role Admin).
    - Exchange app-only also requires adding the SP to an Exchange role group (separate step).

.EXAMPLE
  # Create a new app and configure Graph + Power BI permissions
  .\CIS_M365_Permissions.ps1 -TenantId "<tenant-guid>" -AppName "CIS-M365-Benchmark-Audit"

.EXAMPLE
  # Reuse an existing appId, include Exchange, and assign Entra admin roles
  .\CIS_M365_Permissions.ps1 -TenantId "<tenant-guid>" -AppId "<app-guid>" -IncludeExchange -AssignDirectoryRoles

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
  [switch]$AssignDirectoryRoles,

  [Parameter(Mandatory = $false)]
  [switch]$NoPause,

  [Parameter(Mandatory = $false)]
  [switch]$AutoLogin,

  [Parameter(Mandatory = $false)]
  [string]$OutputPath = ".\CIS_M365_Permissions_Output.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Wait-Step([string]$Message = "Press Enter to continue") {
  if (-not $NoPause) {
    [void](Read-Host $Message)
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
    $text = ($output | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text | ConvertFrom-Json
  }

  return ($output | Out-String).TrimEnd()
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

  $text = ($output | Out-String).Trim()
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

# Ensure we are logged in and tenant matches
$acct = Ensure-AzTenant -ExpectedTenantId $TenantId
Write-Ok "Azure CLI logged in to tenant $TenantId"
Wait-Step

Write-Section "Create or reuse App Registration"
if (-not $AppId) {
  $app = Invoke-Az -AzArgs @("ad","app","create","--display-name", $AppName, "-o","json") -ExpectJson
  $AppId = $app.appId
  Write-Ok "Created app: $AppName"
  Write-Ok "AppId: $AppId"
} else {
  # Verify app exists
  Invoke-Az -AzArgs @("ad","app","show","--id", $AppId, "-o","json") -ExpectJson | Out-Null
  Write-Ok "Using existing AppId: $AppId"
}
Wait-Step

Write-Section "Ensure Service Principal"
$spObjId = $null
try {
  $sp = Invoke-Az -AzArgs @("ad","sp","show","--id", $AppId, "-o","json") -ExpectJson
  $spObjId = $sp.id
  Write-Ok "Service principal exists"
} catch {
  $spObjId = Invoke-Az -AzArgs @("ad","sp","create","--id", $AppId, "--query","id","-o","tsv")
  Write-Ok "Created service principal"
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
  "Tenant.Read.All"                   # Graph beta fallback for Power BI checks (9.x)
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

# 'az ad app permission admin-consent' handles Graph + Power BI correctly,
# but silently skips Exchange Online (Office 365 Exchange Online). We must
# create the appRoleAssignment for Exchange.ManageAsApp directly via Graph API.
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

if ($AssignDirectoryRoles) {
  Write-Section "Assign Entra directory roles (optional)"

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

Write-Section "Output"
$result = [ordered]@{
  TenantId = $TenantId
  AppName = $AppName
  AppId = $AppId
  ServicePrincipalObjectId = $spObjId
  ClientSecret = $secret
  IncludeExchange = [bool]$IncludeExchange
  AssignedDirectoryRoles = [bool]$AssignDirectoryRoles
  GeneratedAt = (Get-Date).ToString('o')
}

($result | ConvertTo-Json -Depth 5) | Set-Content -Path $OutputPath -Encoding UTF8
Write-Ok "Wrote: $OutputPath"

Write-Host "" 
Write-Host "Next:" -ForegroundColor Cyan
Write-Host "  - Use AppId / ClientSecret in CIS_M365_Benchmark_Full.ps1 parameters" -ForegroundColor DarkGray
if ($IncludeExchange) {
  Write-Host "  - For Exchange app-only: add the SP to 'View-Only Organization Management' in EAC (or use ExchangeOnlineManagement PowerShell)" -ForegroundColor DarkGray
}
