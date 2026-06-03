<#
.SYNOPSIS
  Step-by-step helper to create / update the CIS Power Platform audit app
  registration and set permissions for CIS_Power_Platform_Benchmark_Full.ps1.

.DESCRIPTION
  Uses Azure CLI (az) to:
    - Create or reuse an Entra ID App Registration
    - Ensure a Service Principal exists
    - Create a client secret (default; -NoSecret to skip)
    - Add Microsoft Graph application permissions (app roles)
    - Grant admin consent
    - Assign the Entra "Power Platform Administrator" directory role to the SP
      (so the SP can call the Power Platform BAP / governance APIs)
    - Print instructions to register the SP as a Power Platform Management App
      (must be run once by an interactive Power Platform admin using
       Microsoft.PowerApps.Administration.PowerShell)
    - Verify all granted permissions and report missing ones (dynamic check)
    - Offer to run the benchmark immediately ("Run benchmark now? [Y/N]")

  Coverage: the Graph application permissions granted by this helper
  (Directory.Read.All, User.Read.All, Group.Read.All, RoleManagement.Read.All,
  Organization.Read.All, Policy.Read.All, AuditLog.Read.All) cover the
  Graph-based enrichment of the 16 MANL checks in
  CIS_Power_Platform_Benchmark_Full.ps1 (admin account enumeration,
  Conditional Access policies for MFA / location, etc.). Power Platform
  BAP API access requires the Power Platform Administrator directory role
  AND that the SP is registered via New-PowerAppManagementApp.

.EXAMPLE
  # Create a new app and configure all permissions
  .\CIS_Power_Platform_Permissions.ps1 -TenantId "<tenant-guid>"

.EXAMPLE
  # Reuse an existing app
  .\CIS_Power_Platform_Permissions.ps1 -TenantId "<tenant-guid>" -AppId "<app-guid>"

.EXAMPLE
  # Skip secret rotation (only update role assignments)
  .\CIS_Power_Platform_Permissions.ps1 -TenantId "<tenant-guid>" -AppId "<app-guid>" -NoSecret
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)]
  [string]$TenantId,

  [Parameter(Mandatory = $false)]
  [string]$AppName = "CIS-PowerPlatform-Benchmark-Audit",

  [Parameter(Mandatory = $false)]
  [string]$AppId,

  [Parameter(Mandatory = $false)]
  # Retained for backward compatibility. Secret creation is on by default.
  [switch]$CreateSecret,

  [Parameter(Mandatory = $false)]
  # Skip client-secret creation on this run.
  [switch]$NoSecret,

  [Parameter(Mandatory = $false)]
  [int]$SecretYears = 1,

  [Parameter(Mandatory = $false)]
  [switch]$SkipDirectoryRoles,

  [Parameter(Mandatory = $false)]
  [switch]$NoPause,

  [Parameter(Mandatory = $false)]
  [switch]$AutoLogin,

  # If supplied, attempt to register the SP as a Power Platform Management App
  # automatically. Requires Microsoft.PowerApps.Administration.PowerShell and
  # the interactive admin to sign in to Power Platform.
  [Parameter(Mandatory = $false)]
  [switch]$RegisterAsPowerAppMgmtApp,

  [Parameter(Mandatory = $false)]
  [string]$TenantDomain,

  [Parameter(Mandatory = $false)]
  [string]$OutputPath = ".\CIS_PowerPlatform_Permissions_Output.json"
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

function Write-Ok([string]$Message)   { Write-Host "  + $Message" -ForegroundColor Green }
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
    [switch]$ExpectJson
  )

  $cmdLine = "az " + ($AzArgs -join ' ')
  Write-Info $cmdLine
  if ($WhatIfPreference) { return $null }

  $prevEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $azArgsWithFlag = $AzArgs
    if (($AzArgs -notcontains '--only-show-errors') -and
        ($AzArgs -notcontains '--verbose') -and
        ($AzArgs -notcontains '--debug')) {
      $azArgsWithFlag = @($AzArgs) + '--only-show-errors'
    }
    $output = & az @azArgsWithFlag 2>&1
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
    $textLines = $output | Where-Object { $_ -is [string] }
    $text = ($textLines | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return $text | ConvertFrom-Json
  }
  $textLines = $output | Where-Object { $_ -is [string] }
  return ($textLines | Out-String).TrimEnd()
}

function Invoke-AzRestJson {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$Method,
    [Parameter(Mandatory = $true)][string]$Url,
    [string]$BodyJson
  )
  $azArgs = @("rest", "--method", $Method, "--url", $Url, "-o", "json")
  $tmpBody = $null
  if ($BodyJson) {
    $tmpBody = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllText($tmpBody, $BodyJson, [System.Text.Encoding]::UTF8)
    $azArgs += @("--headers", "Content-Type=application/json", "--body", "@$tmpBody")
  }
  $cmdLine = "az " + ($azArgs -join ' ')
  Write-Info $cmdLine
  if ($WhatIfPreference) { return $null }

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
  if (-not $acct.tenantId) { throw "Could not determine tenantId from 'az account show'." }
  if ($acct.tenantId -ne $ExpectedTenantId) {
    if ($AutoLogin) {
      Write-Warn "Azure CLI tenant is $($acct.tenantId), expected $ExpectedTenantId. Re-logging in..."
      Invoke-Az -AzArgs @('login','--tenant', $ExpectedTenantId) | Out-Null
      $acct = Invoke-Az -AzArgs @('account','show','-o','json') -ExpectJson
      if ($acct.tenantId -ne $ExpectedTenantId) { throw "Tenant mismatch" }
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
        if ($attempt -gt 1) { Write-Info "App registration is now visible (attempt $attempt/$MaxAttempts)" }
        return $app
      }
    } catch {
      if ($attempt -eq 1) { Write-Info "Waiting for app registration to replicate..." }
    }
    if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
  }
  throw "Timed out waiting for app registration '$TargetAppId'."
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
        $msg -match "Request_ResourceNotFound"
      )
      if ((-not $isRetryable) -or $attempt -eq $MaxAttempts) { throw }
      if ($attempt -eq 1) { Write-Info "SP creation is waiting for Entra replication..." }
    }
    Start-Sleep -Seconds $DelaySeconds
  }
  throw "Timed out creating service principal for '$TargetAppId'."
}

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
  Wait-ForEntraApplication -TargetAppId $AppId | Out-Null
  Write-Ok "Using existing AppId: $AppId"
}
Wait-Step

Write-Section "Ensure Service Principal"
$spResult = Ensure-ServicePrincipalForApp -TargetAppId $AppId
$spObjId = $spResult.ObjectId
if ($spResult.Created) { Write-Ok "Created service principal" } else { Write-Ok "Service principal exists" }
Write-Ok "ObjectId (SP): $spObjId"
Wait-Step

Write-Section "Create client secret"
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
  Write-Info "Skipped creating secret (-NoSecret was passed)"
}
Wait-Step

Write-Section "Add application permissions (Microsoft Graph)"
$graphResource = "00000003-0000-0000-c000-000000000000"
$graphAppRoles = Invoke-Az -AzArgs @("ad","sp","show","--id", $graphResource, "--query","appRoles","-o","json") -ExpectJson

$graphPerms = @(
  "Directory.Read.All",
  "User.Read.All",
  "Group.Read.All",
  "RoleManagement.Read.All",
  "Organization.Read.All",
  "Policy.Read.All",
  "AuditLog.Read.All"
) | Sort-Object -Unique

Write-Info "Adding Microsoft Graph app roles..."
foreach ($perm in $graphPerms) {
  Add-AppPermissionRole -TargetAppId $AppId -ResourceAppId $graphResource -ResourceAppRoles $graphAppRoles -RoleValue $perm | Out-Null
}
Wait-Step

Write-Section "Grant admin consent"
Invoke-Az -AzArgs @("ad","app","permission","admin-consent","--id", $AppId) | Out-Null
Write-Ok "Admin consent granted"
Wait-Step

# ---------------------------------------------------------------------------
#  Assign Entra directory role: Power Platform Administrator
# ---------------------------------------------------------------------------
if (-not $SkipDirectoryRoles) {
  Write-Section "Assign Entra directory role (Power Platform Administrator)"

  $templates = Invoke-AzRestJson -Method GET -Url 'https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=id,displayName'
  $templateList = @($templates.value)

  $ppCandidates = @(
    "Power Platform Administrator",
    "Dynamics 365 Administrator",
    "Dynamics 365 Service Administrator"
  )
  $ppTemplate = $null
  foreach ($c in $ppCandidates) {
    $ppTemplate = $templateList | Where-Object { $_.displayName -eq $c } | Select-Object -First 1
    if ($ppTemplate) { break }
  }

  if (-not $ppTemplate) {
    Write-Warn "Could not find Power Platform / Dynamics 365 admin role template."
    $maybe = $templateList | Where-Object { $_.displayName -like '*Power Platform*' -or $_.displayName -like '*Dynamics*' } | Select-Object -ExpandProperty displayName
    if ($maybe) {
      Write-Info "Templates matching 'Power Platform' / 'Dynamics':"
      $maybe | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
    }
  } else {
    $dirRoles = Invoke-AzRestJson -Method GET -Url 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,roleTemplateId,displayName'
    $dirRole = @($dirRoles.value) | Where-Object { $_.roleTemplateId -eq $ppTemplate.id } | Select-Object -First 1
    if (-not $dirRole) {
      Write-Info "Activating role: $($ppTemplate.displayName)"
      $activateBody = @{ roleTemplateId = $ppTemplate.id } | ConvertTo-Json -Compress
      $dirRole = Invoke-AzRestJson -Method POST -Url "https://graph.microsoft.com/v1.0/directoryRoles" -BodyJson $activateBody
    }
    if ($dirRole -and $dirRole.id) {
      $memberRefUrl = "https://graph.microsoft.com/v1.0/directoryRoles/$($dirRole.id)/members/`$ref"
      $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$spObjId" } | ConvertTo-Json -Compress
      try {
        Invoke-AzRestJson -Method POST -Url $memberRefUrl -BodyJson $body | Out-Null
        Write-Ok "Assigned directory role: $($ppTemplate.displayName)"
      } catch {
        $msg = $_.Exception.Message
        if ($msg -match "already exist" -or $msg -match "added object references") {
          Write-Ok "Already assigned: $($ppTemplate.displayName)"
        } else {
          Write-Warn "Failed to assign $($ppTemplate.displayName): $msg"
        }
      }
    } else {
      Write-Warn "Failed to activate role: $($ppTemplate.displayName)"
    }
  }
  Wait-Step
}

# ---------------------------------------------------------------------------
#  Register SP as Power Platform Management App
# ---------------------------------------------------------------------------
Write-Section "Register SP as Power Platform Management App"
Write-Info "The Power Platform BAP API only accepts service-principal tokens AFTER the"
Write-Info "SP has been registered via New-PowerAppManagementApp. This must be done once"
Write-Info "by an interactive Power Platform admin and cannot be done with Azure CLI."

$registeredOk = $false
if ($RegisterAsPowerAppMgmtApp) {
  try {
    if (-not (Get-Module -ListAvailable -Name Microsoft.PowerApps.Administration.PowerShell -ErrorAction SilentlyContinue)) {
      Write-Warn "Microsoft.PowerApps.Administration.PowerShell not installed. Installing..."
      Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module Microsoft.PowerApps.Administration.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
    Write-Info "Signing in to Power Platform interactively (Add-PowerAppsAccount) ..."
    Add-PowerAppsAccount -Endpoint prod -ErrorAction Stop | Out-Null
    Write-Info "Calling New-PowerAppManagementApp -ApplicationId $AppId ..."
    try {
      New-PowerAppManagementApp -ApplicationId $AppId -ErrorAction Stop | Out-Null
      Write-Ok "SP registered as Power Platform Management App"
      $registeredOk = $true
    } catch {
      $msg = $_.Exception.Message
      if ($msg -match "already" -or $msg -match "exists") {
        Write-Ok "SP already registered as Power Platform Management App"
        $registeredOk = $true
      } else {
        Write-Warn "New-PowerAppManagementApp failed: $msg"
      }
    }
  } catch {
    Write-Warn "Power Platform Management App registration failed: $($_.Exception.Message)"
  }
}

if (-not $registeredOk) {
  Write-Host ""
  Write-Host "  Run these commands ONCE as a Power Platform admin (interactive):" -ForegroundColor Yellow
  Write-Host "    Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Scope CurrentUser -Force" -ForegroundColor Cyan
  Write-Host "    Add-PowerAppsAccount" -ForegroundColor Cyan
  Write-Host "    New-PowerAppManagementApp -ApplicationId '$AppId'" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "  Without this registration, the benchmark will still run but the BAP-driven" -ForegroundColor DarkYellow
  Write-Host "  enrichment (environments, tenant settings, DLP, cross-tenant isolation)" -ForegroundColor DarkYellow
  Write-Host "  will be skipped and the affected MANL checks will show CIS guidance only." -ForegroundColor DarkYellow
  Write-Host ""
  Wait-ManualStep
}

# ---------------------------------------------------------------------------
#  Per-environment Dataverse Application User registration (REQUIRED for
#  the Dataverse-driven enrichment of items 1.2, 2.3, 3.2, 3.3, 4.1, 4.2)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "----- PER-ENVIRONMENT APPLICATION USER (Dataverse) ----------------" -ForegroundColor Yellow
Write-Host "  Several CIS items audit settings stored INSIDE each Dataverse environment" -ForegroundColor Yellow
Write-Host "  (session timeouts, blocked attachments, public queues, security roles," -ForegroundColor Yellow
Write-Host "  audit flags, privacy privileges). The Power Platform Administrator role" -ForegroundColor Yellow
Write-Host "  does NOT grant access to Dataverse data plane - the service principal" -ForegroundColor Yellow
Write-Host "  must additionally be registered as an Application User in EACH" -ForegroundColor Yellow
Write-Host "  environment, with the System Administrator security role." -ForegroundColor Yellow
Write-Host ""
Write-Host "  STEP A - Self-elevate yourself to System Administrator in the env" -ForegroundColor Cyan
Write-Host "  (do this BEFORE trying to add the service principal):" -ForegroundColor Cyan
Write-Host "    1. Sign in to https://admin.powerplatform.microsoft.com" -ForegroundColor Cyan
Write-Host "    2. Navigation pane > Manage" -ForegroundColor Cyan
Write-Host "    3. In the Manage pane, select Environments" -ForegroundColor Cyan
Write-Host "    4. On the Environments page, choose the target environment" -ForegroundColor Cyan
Write-Host "    5. Command bar > Membership (this is the self-elevation request)" -ForegroundColor Cyan
Write-Host "    6. In the System Administrators pane, click 'Add me'" -ForegroundColor Cyan
Write-Host "       -> grants your own account the Dataverse System Administrator role" -ForegroundColor Cyan
Write-Host ""
Write-Host "  STEP B - Add the service principal as an Application User:" -ForegroundColor Cyan
Write-Host "    1. Open the environment list:" -ForegroundColor Cyan
Write-Host "         https://admin.powerplatform.microsoft.com/manage/environments/" -ForegroundColor Cyan
Write-Host "       then click the target environment." -ForegroundColor Cyan
Write-Host "    2. Click Membership and 'Add me' (if you have not already self-elevated in STEP A)." -ForegroundColor Cyan
Write-Host "    3. Settings > Users + permissions > Application users" -ForegroundColor Cyan
Write-Host "    4. + New app user > Add an app > select '$AppName' ($AppId)" -ForegroundColor Cyan
Write-Host "    5. Pick the appropriate Business unit > Create" -ForegroundColor Cyan
Write-Host "    6. Open the new app user > Manage Roles > select System Administrator > Save" -ForegroundColor Cyan
Write-Host ""
Write-Host "  If STEP B shows: 'We couldn''t be able to fetch app users' / 403" -ForegroundColor DarkYellow
Write-Host "  with 'missing prvReadApplicationUser privilege', it means STEP A was" -ForegroundColor DarkYellow
Write-Host "  skipped or did not finish. Power Platform / Global Admin in Entra ID" -ForegroundColor DarkYellow
Write-Host "  is not enough - you need a Dataverse security role inside the env." -ForegroundColor DarkYellow
Write-Host "  Re-run STEP A (Membership > Add me), then sign out and back in." -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  Note: in newer (Sandbox/Trial) envs you may also need to enable the env" -ForegroundColor DarkYellow
Write-Host "  for your account via PIM activation of the 'Dynamics 365 Administrator'" -ForegroundColor DarkYellow
Write-Host "  role, since Power Platform Admin alone does not auto-provision in every env." -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  References:" -ForegroundColor DarkYellow
Write-Host "    https://learn.microsoft.com/power-platform/admin/manage-application-users" -ForegroundColor DarkYellow
Write-Host "    https://learn.microsoft.com/power-platform/admin/security-roles-privileges" -ForegroundColor DarkYellow
Write-Host "    https://learn.microsoft.com/power-platform/admin/manage-group-teams (Membership / self-elevation)" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  Without this step, Dataverse-backed MANL checks will print '401 Unauthorized'" -ForegroundColor DarkYellow
Write-Host "  and fall back to CIS guidance only." -ForegroundColor DarkYellow
Write-Host ""
Wait-ManualStep


# ---------------------------------------------------------------------------
#  Resolve display values for the benchmark run command
# ---------------------------------------------------------------------------
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

if ($secret) { $secretDisplay = $secret } else { $secretDisplay = 'YOUR-CLIENT-SECRET' }

# ---------------------------------------------------------------------------
#  Verify granted permissions (dynamic check)
# ---------------------------------------------------------------------------
Write-Section "Output"
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
  $allAppRoleLookup = @{}
  @($graphAppRoles) | ForEach-Object { $allAppRoleLookup[$_.id] = $_.value }

  $grantedPermNames = $grantedRoles | ForEach-Object { $allAppRoleLookup[$_.appRoleId] } | Where-Object { $_ }

  $requiredPerms = @(
    @{ Scope = "Directory.Read.All";      Api = "Graph" },
    @{ Scope = "User.Read.All";           Api = "Graph" },
    @{ Scope = "Group.Read.All";          Api = "Graph" },
    @{ Scope = "RoleManagement.Read.All"; Api = "Graph" },
    @{ Scope = "Organization.Read.All";   Api = "Graph" },
    @{ Scope = "Policy.Read.All";         Api = "Graph" },
    @{ Scope = "AuditLog.Read.All";       Api = "Graph" }
  )

  $missing = @($requiredPerms | Where-Object { $_.Scope -notin $grantedPermNames })
  $granted = @($requiredPerms | Where-Object { $_.Scope -in $grantedPermNames })

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
    Write-Ok "All required Microsoft Graph permissions are granted."
  }
  Write-Host ""

  $roleAssignments = @()
  try {
    $memberOf = Invoke-AzRestJson -Method GET `
      -Url "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjId/memberOf?`$select=displayName,roleTemplateId"
    $roleAssignments = @($memberOf.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' })
  } catch { }

  $hasPP = $roleAssignments | Where-Object {
    $_.displayName -in @('Power Platform Administrator','Dynamics 365 Administrator','Dynamics 365 Service Administrator')
  }
  Write-Host "  Directory role assignments:" -ForegroundColor Yellow
  if ($hasPP) { Write-Host "    [OK] $($hasPP.displayName | Select-Object -First 1)" -ForegroundColor Green }
  else        { Write-Host "    [!!] Power Platform Administrator  (not assigned)" -ForegroundColor Red }
  if ($registeredOk) {
    Write-Host "    [OK] SP registered as Power Platform Management App" -ForegroundColor Green
  } else {
    Write-Host "    [??] SP Power Platform Management App registration not verified (run New-PowerAppManagementApp manually)" -ForegroundColor Yellow
  }
  Write-Host ""
}

$result = [ordered]@{
  TenantId                 = $TenantId
  TenantDomain             = $domain
  AppName                  = $AppName
  AppId                    = $AppId
  ServicePrincipalObjectId = $spObjId
  ClientSecret             = $null
  AssignedDirectoryRoles   = (-not $SkipDirectoryRoles)
  GeneratedAt              = (Get-Date).ToString('o')
}
($result | ConvertTo-Json -Depth 5) | Set-Content -Path $OutputPath -Encoding UTF8
Write-Ok "Wrote: $OutputPath"

Write-Host ''
Write-Host '  === Run the benchmark with: ===' -ForegroundColor Cyan
Write-Host ''
Write-Host "  .\CIS_Power_Platform_Benchmark_Full.ps1" -ForegroundColor White
Write-Host "      -TenantId           $TenantId" -ForegroundColor White
Write-Host "      -AppId              $AppId" -ForegroundColor White
Write-Host "      -AppSecret          $secretDisplay" -ForegroundColor White
Write-Host "      -TenantDomain       $domain" -ForegroundColor White
Write-Host ''

if (-not $NoPause) {
  $runNow = Read-Host '  Run benchmark now? [Y/N]'
  if ($runNow -match '^[Yy]') {
    $secretForRun = $secret
    if (-not $secretForRun) {
      Write-Host ''
      Write-Host '  No client secret was created this run (-NoSecret was passed).' -ForegroundColor DarkYellow
      Write-Host "  Paste an existing client secret for app $AppId to run the benchmark now," -ForegroundColor DarkYellow
      Write-Host '  or press Enter to skip.' -ForegroundColor DarkYellow
      $secureSecret = Read-Host '  AppSecret' -AsSecureString
      if ($secureSecret.Length -gt 0) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
        try { $secretForRun = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
      }
    }
    if (-not $secretForRun) {
      Write-Warn 'No client secret provided -- benchmark run skipped.'
    } else {
      $benchmarkPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'CIS_Power_Platform_Benchmark_Full.ps1'
      if (Test-Path $benchmarkPath) {
        $benchmarkArgs = @{
          TenantId     = $TenantId
          AppId        = $AppId
          AppSecret    = $secretForRun
          TenantDomain = $domain
        }
        & $benchmarkPath @benchmarkArgs
      } else {
        Write-Warn "Script not found: $benchmarkPath"
        Write-Info 'Make sure both scripts are in the same directory.'
      }
    }
  }
}
