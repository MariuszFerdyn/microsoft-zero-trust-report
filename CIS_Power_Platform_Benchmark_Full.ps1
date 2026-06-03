#Requires -Version 5.1
<#
.SYNOPSIS
    CIS Microsoft Dynamics 365 / Power Platform Foundations Benchmark v1.0.0
    All 16 recommendations from the CIS PDF (all marked "Manual" by CIS).

.DESCRIPTION
    Every recommendation in CIS Microsoft Dynamics 365 Power Platform v1.0.0
    is documented as Manual. Each is implemented as a Check-MANL-<section>
    function that prints:
      - the portal path,
      - the CIS Audit steps,
      - the CIS Remediation steps,
      - references.
    Where an API allows it, the function also pulls live diagnostic data
    (Graph for users / roles / Conditional Access; the Power Platform BAP API
    for environments, tenant settings, DLP policies, etc.) so the operator
    can answer the item without leaving the console.

    Several CIS items (1.2 session timeouts, 2.3 blocked attachments,
    3.2 privacy privileges, 3.3 public queues, 4.1 System Administrator
    role membership, 4.2 audit flags) audit settings that *only exist
    inside a Dataverse environment*. There is no non-Dataverse
    alternative for those settings - Power Apps canvas-only or
    Power Automate-only environments simply do not have a "session
    timeout" column or a "System Administrator" security role. For
    those environments the script reports those items as
    Not Applicable; for Dataverse-backed environments it calls the
    Dataverse Web API directly.

    Auth model (mirrors CIS_M365_Benchmark_Full.ps1):
        - App-only via client credentials.
        - Microsoft Graph: connected with Connect-MgGraph -ClientSecretCredential
        - Power Platform BAP API (https://api.bap.microsoft.com): client-credential
          token for resource https://service.powerapps.com/.default. This works
          only after the service principal has been registered as a Power Platform
          management app via:
              Add-PowerAppsAccount
              New-PowerAppManagementApp -ApplicationId '<app-id>'
          CIS_Power_Platform_Permissions.ps1 performs that registration for you.

    All recommendations are Manual; the script does NOT mark them PASS / FAIL.
    Items are surfaced with Status = MANL in the CSV output, with the diagnostic
    data appended to the Detail column.

.NOTES
    Required PowerShell modules (installed on demand):
        Install-Module Microsoft.Graph                        -Scope CurrentUser -Force

    Required Microsoft Graph application permissions:
        Directory.Read.All, User.Read.All, Group.Read.All,
        RoleManagement.Read.All, Organization.Read.All,
        Policy.Read.All, AuditLog.Read.All

    Required Entra ID role assignments (on the service principal):
        Power Platform Administrator (or Dynamics 365 Administrator) so the
        BAP API enumerates environments / tenant settings / DLP policies.

    EXO and SPO are NOT required for this benchmark.
#>

param(
    [Parameter(Mandatory=$false)][string]$TenantId,
    [Parameter(Mandatory=$false)][string]$AppId,
    [Parameter(Mandatory=$false)][string]$AppSecret,
    [Parameter(Mandatory=$false)][string]$TenantDomain,
    [switch]$GraphOnlyMode = $false,
    [string]$OutputPath    = "$PSScriptRoot\CIS_PowerPlatform_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# ===============================================================================
#  RESULT TRACKING
# ===============================================================================
$Script:PassCount   = 0
$Script:FailCount   = 0
$Script:WarnCount   = 0
$Script:ManlCount   = 0
$Script:Results     = [System.Collections.Generic.List[object]]::new()
$Script:GraphConnected = $false
$Script:BapConnected   = $false
$Script:Environments   = @()
$Script:TenantSettings = $null
# Cache of Dataverse tokens per environment instance URL
$Script:DataverseTokens = @{}
# Cache of Dataverse readiness per env (so we don't print "App User not registered" once per check)
$Script:DataverseStatus = @{}
# Captured root-cause errors keyed by source ('BAP', 'Graph:<endpoint>',
# 'DV:<envName>', 'TenantSettings'). Surfaced verbatim by Show-Summary so the
# operator can see exactly why an automated verdict came out as UNKNOWN.
$Script:LastErrors = [ordered]@{}

# ===============================================================================
#  HELPERS
# ===============================================================================
function Write-Banner {
    param([string]$Text)
    $line = "-" * 82
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-CheckHeader {
    param([string]$Section, [string]$Title)
    Write-Host ""
    Write-Host ("  [{0}]" -f $Section) -ForegroundColor Yellow -NoNewline
    Write-Host "  $Title" -ForegroundColor White
}

function Write-Pass { param([string]$M); Write-Host "  [PASS] $M" -ForegroundColor Green;   $Script:PassCount++ }
function Write-Fail { param([string]$M); Write-Host "  [FAIL] $M" -ForegroundColor Red;     $Script:FailCount++ }
function Write-Warn { param([string]$M); Write-Host "  [WARN] $M" -ForegroundColor Magenta; $Script:WarnCount++ }
function Write-Manl { param([string]$M); Write-Host "  [MANL] $M" -ForegroundColor Cyan;    $Script:ManlCount++ }
function Write-Info { param([string]$M); Write-Host "    $M"       -ForegroundColor Gray }
function Write-Skip { param([string]$M); Write-Host "  [SKIP] $M" -ForegroundColor DarkGray }

function Add-Result {
    param([string]$Section, [string]$Title, [string]$Status, [string]$Detail, [string]$AutoVerdict)
    if ($AutoVerdict -and $Detail -notmatch '^\[AUTO:') {
        $Detail = "[AUTO: $AutoVerdict] $Detail"
    }
    $Script:Results.Add([PSCustomObject]@{
        Section = $Section; Title = $Title; Status = $Status; Detail = $Detail
    })
}

# Convenience wrapper for MANL items: pass the automated verdict (PASS, FAIL,
# WARN, NA, UNKNOWN) and a short evidence string. Status remains MANL per CIS,
# but the Detail column now carries the auto-verdict so the summary can show
# real PASS/FAIL signal in addition to the MANL flag.
function Add-MANL {
    param(
        [string]$Section, [string]$Title,
        [ValidateSet('PASS','FAIL','WARN','NA','UNKNOWN')][string]$Verdict,
        [string]$Evidence
    )
    Add-Result -Section $Section -Title $Title -Status 'MANL' -Detail $Evidence -AutoVerdict $Verdict
}

function Invoke-Check {
    param([string]$Section, [string]$Title, [scriptblock]$Body)
    Write-CheckHeader $Section $Title
    try { & $Body }
    catch {
        $ex      = $_.Exception
        $full    = $ex.Message
        $type    = $ex.GetType().FullName
        $where   = "$($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)"
        # Display the raw PowerShell error (multi-line, with type and location)
        # so the operator sees the same thing they would see at the prompt.
        Write-Warn "Unexpected error in [$Section]: $type"
        foreach ($line in ($full -split [char]10)) {
            if ($line.Trim()) { Write-Host "      $line" -ForegroundColor Magenta }
        }
        Write-Host "      at $where" -ForegroundColor DarkMagenta
        $Script:LastErrors["Check $Section"] = "$type @ $where :: $full"
        Add-Result $Section $Title "WARN" "Error: $type @ $where :: $full"
    }
}

function Write-ManualAudit {
    param(
        [string[]]$AuditSteps,
        [string[]]$Remediation,
        [string]  $Portal,
        [string[]]$References
    )
    if ($Portal)      { Write-Info "Portal: $Portal" }
    if ($AuditSteps)  { Write-Info "Audit:";       foreach ($s in $AuditSteps)  { Write-Info "  - $s" } }
    if ($Remediation) { Write-Info "Remediation:"; foreach ($s in $Remediation) { Write-Info "  - $s" } }
    if ($References)  { Write-Info "References:";  foreach ($r in $References)  { Write-Info "  - $r" } }
}

function Ensure-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)) {
        Write-Host "    Installing module: $Name ..." -ForegroundColor Yellow
        Install-Module $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module $Name -ErrorAction Stop -WarningAction SilentlyContinue
}

# ===============================================================================
#  CONNECTION
# ===============================================================================
function Get-OAuthToken {
    param([Parameter(Mandatory=$true)][string]$Scope)
    if (-not $TenantId -or -not $AppId -or -not $AppSecret) {
        throw "TenantId / AppId / AppSecret are required for app-only token acquisition."
    }
    $Body = @{
        client_id     = $AppId
        client_secret = $AppSecret
        scope         = $Scope
        grant_type    = "client_credentials"
    }
    $Resp = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $Body -ErrorAction Stop
    return $Resp.access_token
}

function Connect-AllServices {
    Write-Banner "Connecting to Microsoft Services"

    # ---- Microsoft Graph -------------------------------------------------------
    Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor Yellow
    if (-not ($TenantId -and $AppId -and $AppSecret)) {
        Write-Host "  [SKIP] Graph credentials not supplied (TenantId/AppId/AppSecret)" -ForegroundColor Yellow
        Write-Host "         Running interactive Connect-MgGraph (fallback) ..." -ForegroundColor DarkYellow
        try {
            Ensure-Module "Microsoft.Graph.Authentication"
            Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","User.Read.All","Group.Read.All","RoleManagement.Read.All","Organization.Read.All","AuditLog.Read.All" -NoWelcome -ErrorAction Stop
            $Script:GraphConnected = $true
            Write-Host "  [OK] Graph connected (interactive)" -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] Graph connection failed: $_" -ForegroundColor Red
        }
    } else {
        try {
            foreach ($mod in @(
                "Microsoft.Graph.Authentication",
                "Microsoft.Graph.Identity.DirectoryManagement",
                "Microsoft.Graph.Identity.SignIns",
                "Microsoft.Graph.Users",
                "Microsoft.Graph.Groups"
            )) { Ensure-Module $mod }

            $SecureSecret = ConvertTo-SecureString $AppSecret -AsPlainText -Force
            $ClientCred   = New-Object System.Management.Automation.PSCredential($AppId, $SecureSecret)
            Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientCred -NoWelcome -ErrorAction Stop
            $Script:GraphConnected = $true
            Write-Host "  [OK] Graph connected (Tenant: $TenantId)" -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] Graph connection failed: $_" -ForegroundColor Red
        }
    }

    # ---- Power Platform BAP API (app-only token) -------------------------------
    if (-not $GraphOnlyMode -and $TenantId -and $AppId -and $AppSecret) {
        Write-Host "  Acquiring Power Platform BAP API token..." -ForegroundColor Yellow
        try {
            $Script:BapToken = Get-OAuthToken -Scope "https://service.powerapps.com/.default"
            $Script:BapConnected = $true
            Write-Host "  [OK] BAP token acquired" -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] Could not acquire BAP token: $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Yellow
            Write-Host "         Cause is usually that the SP was not registered via" -ForegroundColor DarkYellow
            Write-Host "         New-PowerAppManagementApp. Power Platform-specific MANL checks" -ForegroundColor DarkYellow
            Write-Host "         will print CIS guidance without live data." -ForegroundColor DarkYellow
            $Script:BapConnected = $false
        }
    } else {
        Write-Host "  [SKIP] Power Platform BAP API (GraphOnlyMode or missing credentials)" -ForegroundColor DarkGray
        $Script:BapConnected = $false
    }

    Write-Host ""
    Write-Host "  Connection status: Graph=$(if($Script:GraphConnected){'[OK]'}else{'[--]'})" -NoNewline -ForegroundColor $(if($Script:GraphConnected){'Green'}else{'Red'})
    Write-Host " BAP=$(if($Script:BapConnected){'[OK]'}else{'[--]'})" -ForegroundColor $(if($Script:BapConnected){'Green'}else{'Yellow'})
}

# Helper: call BAP API with the cached token
function Invoke-BapApi {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [string]$Method = "GET",
        [object]$Body
    )
    if (-not $Script:BapConnected) { throw "BAP API not connected." }
    $headers = @{ Authorization = "Bearer $Script:BapToken"; "Content-Type" = "application/json" }
    $params  = @{ Uri = $Url; Method = $Method; Headers = $headers; ErrorAction = "Stop" }
    if ($Body) { $params["Body"] = ($Body | ConvertTo-Json -Depth 10 -Compress) }
    return Invoke-RestMethod @params
}

# Helper: enumerate environments once and cache the result.
# Tries multiple api-versions; older versions are tolerated by tenants where the
# SP isn't yet registered for newer schemas. Drops $expand options that can
# 400/403 on tenants without the corresponding licenses.
function Get-AllEnvironments {
    if ($Script:Environments -and $Script:Environments.Count -gt 0) { return $Script:Environments }
    if (-not $Script:BapConnected) {
        $Script:LastErrors['BAP'] = 'BAP not connected (no token acquired - check SP credentials and -RegisterAsPowerAppMgmtApp).'
        return @()
    }
    $apiVersions = @('2022-05-01','2021-04-01','2020-10-01','2020-08-01-preview','2019-05-01')
    $lastErr   = $null
    $emptyVer  = $null
    foreach ($ver in $apiVersions) {
        try {
            $url  = "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=$ver"
            $resp = Invoke-BapApi -Url $url
            if ($resp -and $resp.value -and @($resp.value).Count -gt 0) {
                $Script:Environments = @($resp.value)
                if ($ver -ne $apiVersions[0]) { Write-Info "  Environments enumerated via fallback api-version=$ver." }
                return $Script:Environments
            } else {
                # 200 OK but empty value array: SP authenticated to BAP but cannot
                # see any environments. This is the SP-not-registered-with-PP-mgmt
                # case (admin SP role missing) - distinct from a hard API failure.
                $emptyVer = $ver
                $valueCount = if ($resp.value) { @($resp.value).Count } else { 'null' }
                $Script:LastErrors["BAP env-list api-version=$ver"] = "HTTP 200 OK but value=[$valueCount] env(s) - SP authenticated but has zero environments visible (likely missing admin role / not registered with PowerApps management)."
            }
        } catch {
            $lastErr = $_.Exception.Message.Split([char]10)[0]
            $Script:LastErrors["BAP env-list api-version=$ver"] = $_.Exception.Message
            continue
        }
    }
    if ($lastErr) {
        Write-Info "  BAP env enumeration failed on all api-versions. Last error: $lastErr"
        $Script:LastErrors['BAP'] = $lastErr
    } elseif ($emptyVer) {
        Write-Info "  BAP env enumeration: API returned 0 environments (SP authenticated but cannot see any envs)."
        $Script:LastErrors['BAP'] = "BAP returned 0 environments. SP authenticated OK but is not registered as a PowerApps management app, so it sees no envs. Run once interactively as a Global / Power Platform admin: Add-PowerAppsAccount; New-PowerAppManagementApp -ApplicationId <appId>"
    }
    Write-Info "  Most common cause: SP not registered. Run once interactively as a PP admin:"
    Write-Info "    Add-PowerAppsAccount; New-PowerAppManagementApp -ApplicationId <appId>"
    $Script:Environments = @()
    return @()
}

function Get-BapErrorHint {
    $err = $Script:LastErrors['BAP']
    if (-not $err) { $err = 'no BAP error captured (BAP may not be connected)' }
    return $err
}

function Get-DataverseFallbackDetail {
    param([int]$EnvCount)
    if ($EnvCount -eq 0) {
        return "Not Applicable - no Dataverse-backed environments in the tenant (item only applies to Dynamics 365 / Dataverse environments)."
    } else {
        # Surface the actual per-env error(s) so the operator can see if it
        # was a 401 (SP not added as App User) vs 403 (missing privilege) vs
        # network/TLS error vs throttling.
        $dvErrors = @()
        foreach ($k in $Script:LastErrors.Keys) {
            if ($k -like 'DV:*') { $dvErrors += "$($k.Substring(3))=$($Script:LastErrors[$k])" }
        }
        $errSummary = if ($dvErrors.Count -gt 0) { ' [' + ($dvErrors -join '; ') + ']' } else { '' }
        return "Dataverse Web API unavailable for all $EnvCount candidate env(s) (SP not registered as App User, or missing Dataverse role) - manual review required.$errSummary"
    }
}

# Helper: split environments into Dataverse-backed vs non-Dataverse and emit a
# one-line summary. Items 1.2 / 2.3 / 3.2 / 3.3 / 4.1 / 4.2 audit *Dataverse*
# settings (organization columns, security roles, queues), so envs without a
# linked Dataverse instance (canvas-apps-only / Flow-only) are Not Applicable
# for those checks - the underlying setting simply does not exist.
function Get-DataverseEnvironments {
    param([string]$ContextLabel = 'Dataverse audit')
    $all = Get-AllEnvironments
    $inScope    = @()
    $noDv       = @()
    $excludedSku = @()
    foreach ($e in $all) {
        $sku  = $e.properties.environmentSku
        $name = $e.properties.displayName
        if ($sku -notin @('Production','Sandbox','Trial','Default')) {
            $excludedSku += "$name [$sku]"
            continue
        }
        $url = Get-EnvInstanceUrl $e
        if (-not $url) { $noDv += "$name [$sku]"; continue }
        $inScope += $e
    }
    Write-Info "$ContextLabel scope: $($inScope.Count) Dataverse env(s); $($noDv.Count) without Dataverse (N/A); $($excludedSku.Count) excluded SKU."
    if ($noDv.Count -gt 0) { Write-Info "  Skipped (no Dataverse): $($noDv -join '; ')" }
    return $inScope
}

# Helper: extract per-environment instance URL (https://orgxxx.crm.dynamics.com)
function Get-EnvInstanceUrl {
    param([object]$Env)
    try {
        if ($Env.properties.linkedEnvironmentMetadata.instanceApiUrl) {
            return ($Env.properties.linkedEnvironmentMetadata.instanceApiUrl -replace '/$','')
        }
        if ($Env.properties.linkedEnvironmentMetadata.instanceUrl) {
            return ($Env.properties.linkedEnvironmentMetadata.instanceUrl -replace '/$','')
        }
    } catch { }
    return $null
}

# Helper: acquire (and cache) a Dataverse Web API token for one environment.
# SP must be added as an Application User in that environment (see Permissions
# helper) - otherwise this call succeeds but subsequent /api/data/v9.2/* return 401.
function Get-DataverseToken {
    param([Parameter(Mandatory=$true)][string]$InstanceUrl)
    if ($Script:DataverseTokens.ContainsKey($InstanceUrl)) { return $Script:DataverseTokens[$InstanceUrl] }
    try {
        $tok = Get-OAuthToken -Scope "$InstanceUrl/.default"
        $Script:DataverseTokens[$InstanceUrl] = $tok
        return $tok
    } catch {
        throw "Failed to acquire Dataverse token for $InstanceUrl : $($_.Exception.Message.Split([char]10)[0])"
    }
}

# Helper: GET a Dataverse Web API path. Returns the .value array (or the root
# object) and writes any auth/access error inline with a helpful next step.
# Caches the per-env readiness state ($Script:DataverseStatus).
function Invoke-DataverseApi {
    param(
        [Parameter(Mandatory=$true)][string]$InstanceUrl,
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$EnvName = $InstanceUrl
    )
    $url = "$InstanceUrl/api/data/v9.2/$Path"
    try {
        $token   = Get-DataverseToken -InstanceUrl $InstanceUrl
        $headers = @{
            Authorization        = "Bearer $token"
            Accept               = "application/json"
            'OData-Version'      = "4.0"
            'OData-MaxVersion'   = "4.0"
            Prefer               = 'odata.include-annotations="*"'
        }
        $resp = Invoke-RestMethod -Method GET -Uri $url -Headers $headers -ErrorAction Stop
        $Script:DataverseStatus[$InstanceUrl] = 'OK'
        return $resp
    } catch {
        $status = 'ERROR'
        $msg = $_.Exception.Message
        if ($_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
        }
        $Script:DataverseStatus[$InstanceUrl] = $status
        $shortMsg = $msg.Split([char]10)[0]
        $Script:LastErrors["DV:$EnvName"] = "HTTP $status - $msg"
        if ($status -eq 401 -or $msg -match 'Unauthorized|401') {
            Write-Info "    [$EnvName] Dataverse 401: SP is not registered as an Application User in this environment."
            Write-Info "    Fix once per env (TWO steps):"
            Write-Info "      1) Self-elevate yourself: Power Platform Admin Center > Manage > Environments > pick env > Membership > 'Add me' (grants you Dataverse System Administrator)."
            Write-Info "      2) Then add the SP: same env > Settings > Users + permissions > Application users > + New app user > select the app > assign 'System Administrator'."
        } elseif ($status -eq 403 -or $msg -match 'Forbidden|403|prv[A-Z]') {
            Write-Info "    [$EnvName] Dataverse 403: SP is registered but missing a privilege ($($msg -replace '.*missing (prv\w+).*','$1'))."
            Write-Info "    Fix: open the app user > Manage Roles > assign 'System Administrator' (or a role that includes the missing prv*)."
        } else {
            Write-Info "    [$EnvName] Dataverse call failed ($status): $($msg.Split([char]10)[0])"
        }
        return $null
    }
}

# Helper: fetch tenant settings via BAP API (POST)
function Get-PPTenantSettings {
    if ($Script:TenantSettings) { return $Script:TenantSettings }
    if (-not $Script:BapConnected) { return $null }
    try {
        $url = "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/listTenantSettings?api-version=2020-08-01"
        $resp = Invoke-BapApi -Url $url -Method "POST" -Body @{}
        $Script:TenantSettings = $resp
        return $resp
    } catch {
        $msg = $_.Exception.Message.Split([char]10)[0]
        Write-Info "  Could not read tenant settings: $msg"
        $Script:LastErrors['TenantSettings'] = $msg
        return $null
    }
}

# ===============================================================================
#  SECTION 1 - Accounts and Authentication
# ===============================================================================

function Check-MANL-1_1 {
    Invoke-Check "1.1 (L1)" "Ensure 'User access to environments is controlled with Security Groups' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > select the environment",
                "Click Edit on the Details pane",
                "Click the pencil icon under Security group",
                "Ensure the appropriate Entra ID security group(s) are selected"
            ) `
            -Remediation @(
                "Edit the environment > under Security group, select the appropriate group",
                "Click Done > Save"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/control-user-access"
            )

        # Automated audit: per-env securityGroupId from BAP linkedEnvironmentMetadata
        $envs = Get-AllEnvironments
        if ($envs -and $envs.Count -gt 0) {
            Write-Info "Environments enumerated via BAP API: $($envs.Count)"
            $missing = @()
            $ok      = @()
            foreach ($e in $envs) {
                $name    = $e.properties.displayName
                $envType = $e.properties.environmentSku
                $sgId    = $null
                try { $sgId = $e.properties.linkedEnvironmentMetadata.securityGroupId } catch { }
                $hasSg   = $sgId -and $sgId -ne '00000000-0000-0000-0000-000000000000'
                $marker  = if ($hasSg) { "SG=$sgId" } else { "[NO SECURITY GROUP]" }
                Write-Info "  -> [$envType] $name :: $marker"
                if ($envType -eq 'Default') { continue }   # CIS allows Default env without SG
                if ($hasSg) { $ok += $name } else { $missing += $name }
            }
            if ($missing.Count -eq 0) {
                Write-Info "All non-Default environments have a security group attached."
            } else {
                Write-Info "Non-Default environments WITHOUT a security group ($($missing.Count)): $($missing -join '; ')"
            }
            $detail = "Envs=$($envs.Count); with SG=$($ok.Count); without SG (excl. Default)=$($missing.Count): $($missing -join '; ')"
            Write-Manl "Review each environment above against organizational policy."
            $verdict = if ($missing.Count -eq 0) { 'PASS' } else { 'FAIL' }
            Add-MANL "1.1" "User access to environments controlled with Security Groups" $verdict $detail
        } else {
            Write-Manl "Could not enumerate environments via BAP API - verify in the Power Platform Admin Center."
            Add-MANL "1.1" "User access to environments controlled with Security Groups" 'UNKNOWN' "BAP API unavailable - $(Get-BapErrorHint)"
        }
    }
}

function Check-MANL-1_2 {
    Invoke-Check "1.2 (L1)" "Ensure 'User sessions are terminated upon time limit exceeded and user logoff' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > select environment > Settings",
                "Expand Product > Privacy + Security",
                "Under Session Expiration ensure the slider is set to On (recommended: 120 minutes)",
                "Under Inactivity timeout ensure the slider is set to On with org-defined duration",
                "Click Save"
            ) `
            -Remediation @(
                "Set Session Expiration to On, length per org policy (CIS recommends 120 minutes)",
                "Set Inactivity timeout to On with appropriate idle duration and warning"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/user-session-management"
            )

        # Automated audit: Dataverse organization entity (session + inactivity timeout columns)
        $envs = Get-DataverseEnvironments -ContextLabel "1.2 session timeouts"
        $rows = @()
        foreach ($e in $envs) {
            $envType = $e.properties.environmentSku
            $name    = $e.properties.displayName
            if ($envType -notin @('Production','Sandbox','Trial')) { continue }
            $url = Get-EnvInstanceUrl $e
            if (-not $url) { continue }
            $sel = 'sessiontimeoutenabled,sessiontimeoutinminutes,sessiontimeoutreminderinminutes,inactivitytimeoutenabled,inactivitytimeoutinminutes,inactivitytimeoutreminderinminutes'
            $org = Invoke-DataverseApi -InstanceUrl $url -EnvName $name -Path "organizations?`$select=$sel"
            if ($null -eq $org) { continue }
            $o = @($org.value)[0]
            $rows += [PSCustomObject]@{
                Env     = $name
                SesOn   = $o.sessiontimeoutenabled
                SesMin  = $o.sessiontimeoutinminutes
                IdleOn  = $o.inactivitytimeoutenabled
                IdleMin = $o.inactivitytimeoutinminutes
            }
        }
        if ($rows.Count -gt 0) {
            $bad = @()
            foreach ($r in $rows) {
                $sesOk  = $r.SesOn  -eq $true -and $r.SesMin  -and $r.SesMin  -le 1440
                $idleOk = $r.IdleOn -eq $true -and $r.IdleMin -and $r.IdleMin -le 60
                $flag   = if ($sesOk -and $idleOk) { 'OK' } else { 'FAIL' }
                Write-Info "  -> [$flag] $($r.Env) :: session=$($r.SesOn)/$($r.SesMin)m  inactivity=$($r.IdleOn)/$($r.IdleMin)m"
                if (-not ($sesOk -and $idleOk)) { $bad += $r.Env }
            }
            $detail = "Envs queried=$($rows.Count); non-compliant=$($bad.Count): $($bad -join '; ')"
            $verdict = if ($bad.Count -eq 0) { 'PASS' } else { 'FAIL' }
            Add-MANL "1.2" "User sessions terminated on time limit / logoff" $verdict $detail
        } else {
            Add-MANL "1.2" "User sessions terminated on time limit / logoff" $(if (@($envs).Count -eq 0) { 'NA' } else { 'UNKNOWN' }) (Get-DataverseFallbackDetail @($envs).Count)
        }
        Write-Manl "Verify the per-env values above against organizational policy."
    }
}

function Check-MANL-1_3 {
    Invoke-Check "1.3 (L1)" "Ensure 'Administrative accounts are separate, unassigned, and cloud-only' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.microsoft.com" `
            -AuditSteps @(
                "M365 Admin Center > Users > Active users",
                "Sort by User type and verify administrators have a dedicated admin account separate from their daily account",
                "Admin accounts should be cloud-only (no on-prem sync) and unlicensed for productivity workloads"
            ) `
            -Remediation @(
                "Create a separate cloud-only account for each admin (no productivity license)",
                "Assign Power Platform / Dynamics 365 admin roles only to the admin accounts",
                "Apply least-privilege security roles within Power Platform environments"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/create-users",
                "https://learn.microsoft.com/power-platform/admin/prevent-elevation-security-role-privilege"
            )

        # Diagnostic: enumerate Power Platform / Dynamics / Global admins and flag hybrid
        if ($Script:GraphConnected) {
            try {
                $rolesOfInterest = @(
                    'Global Administrator',
                    'Power Platform Administrator',
                    'Dynamics 365 Administrator',
                    'Dynamics 365 Service Administrator'
                )
                $dirRoles = Get-MgDirectoryRole -All -EA Stop |
                    Where-Object { $_.DisplayName -in $rolesOfInterest }
                $members = @()
                foreach ($r in $dirRoles) {
                    $rm = Get-MgDirectoryRoleMember -DirectoryRoleId $r.Id -EA SilentlyContinue
                    foreach ($m in $rm) {
                        if ($m.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.user') { continue }
                        $u = Get-MgUser -UserId $m.Id -Property DisplayName,UserPrincipalName,OnPremisesSyncEnabled -EA SilentlyContinue
                        if ($u) {
                            $members += [PSCustomObject]@{
                                Role  = $r.DisplayName
                                Name  = $u.DisplayName
                                UPN   = $u.UserPrincipalName
                                OnPrem= [bool]$u.OnPremisesSyncEnabled
                            }
                        }
                    }
                }
                $hybrid = @($members | Where-Object { $_.OnPrem })
                Write-Info "Power Platform / Dynamics / Global admins enumerated: $($members.Count)"
                foreach ($m in $members) {
                    $flag = if ($m.OnPrem) { '[HYBRID]' } else { '[CLOUD]' }
                    Write-Info "  -> $flag $($m.Role) :: $($m.Name) <$($m.UPN)>"
                }
                $detail = "Admins=$($members.Count); hybrid-synced=$($hybrid.Count): $(@($hybrid.UPN) -join '; ')"
                Write-Manl "Verify each listed admin has a separate admin-only account."
                Add-MANL "1.3" "Administrative accounts separate / unassigned / cloud-only" 'UNKNOWN' $detail
            } catch {
                $emsg = $_.Exception.Message.Split([char]10)[0]
                $Script:LastErrors['Graph:directoryRoles'] = $emsg
                Write-Manl "Could not enumerate admin accounts: $emsg"
                Add-MANL "1.3" "Administrative accounts separate / unassigned / cloud-only" 'UNKNOWN' "Could not query admins via Graph - $emsg"
            }
        } else {
            Write-Manl "Graph not connected - verify in the M365 Admin Center."
            Add-MANL "1.3" "Administrative accounts separate / unassigned / cloud-only" 'UNKNOWN' "Graph not connected - manual review required."
        }
    }
}

function Check-MANL-1_4 {
    Invoke-Check "1.4 (L2)" "Ensure 'Multifactor authentication for all users' is 'Enabled' (Manual)" {
        Write-ManualAudit `
            -Portal "https://entra.microsoft.com/" `
            -AuditSteps @(
                "Entra ID > Protection > Conditional Access > Policies",
                "Confirm a policy exists that REQUIRES Multifactor Authentication for All users",
                "Verify the policy is enabled (not Report-only)",
                "Confirm at least one break-glass account is excluded from the policy"
            ) `
            -Remediation @(
                "Create a Conditional Access policy: Assignments > Users = All users",
                "Cloud apps = All cloud apps",
                "Grant > Require multi-factor authentication, State = On",
                "Exclude emergency-access accounts from the policy"
            ) `
            -References @(
                "https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa"
            )

        # Diagnostic: look for an enabled CA policy that requires MFA for all users
        if ($Script:GraphConnected) {
            try {
                $url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
                $resp = Invoke-MgGraphRequest -Method GET -Uri $url -EA Stop
                $pol = @($resp.value)
                $mfaAll = $pol | Where-Object {
                    $_.state -eq 'enabled' -and
                    $_.conditions.users.includeUsers -contains 'All' -and
                    $_.grantControls.builtInControls -contains 'mfa'
                }
                Write-Info "Conditional Access policies (enabled): $((@($pol | Where-Object { $_.state -eq 'enabled' })).Count) / total $($pol.Count)"
                if ($mfaAll -and $mfaAll.Count -gt 0) {
                    Write-Info "Policies enforcing MFA for All users:"
                    foreach ($p in $mfaAll) { Write-Info "  -> $($p.displayName)" }
                    Add-MANL "1.4" "MFA for all users is enabled (CA)" 'PASS' "Candidate policies: $($mfaAll.displayName -join '; ')"
                } else {
                    Write-Info "No enabled CA policy that requires MFA for All users was detected."
                    Add-MANL "1.4" "MFA for all users is enabled (CA)" 'FAIL' "No enabled All-users + MFA CA policy detected."
                }
                Write-Manl "Verify scope (Power Platform / Dataverse cloud apps) and break-glass exclusions in the Entra portal."
            } catch {
                $emsg = $_.Exception.Message.Split([char]10)[0]
                $Script:LastErrors['Graph:CAPolicies(1.4)'] = $emsg
                Write-Manl "Could not read CA policies (need Policy.Read.All / Entra ID P1+): $emsg"
                Add-MANL "1.4" "MFA for all users is enabled (CA)" 'UNKNOWN' "Could not query CA policies via Graph - $emsg"
            }
        } else {
            Write-Manl "Graph not connected - verify in the Entra portal."
            Add-MANL "1.4" "MFA for all users is enabled (CA)" 'UNKNOWN' "Graph not connected - manual review required."
        }
    }
}

# ===============================================================================
#  SECTION 2 - Permissions
# ===============================================================================

function Check-MANL-2_1 {
    Invoke-Check "2.1 (L1)" "Ensure 'Creation of new trial, production, and sandbox environments' is restricted to 'Administrators' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > gear icon > Power Platform Settings",
                "Under 'Who can create production and sandbox environments' = Only specific admins",
                "Under 'Who can create trial environments'                 = Only specific admins"
            ) `
            -Remediation @(
                "Set both 'Who can create...' settings to 'Only specific admins' and Save",
                "Or via PowerShell (Microsoft.PowerApps.Administration.PowerShell):",
                "  Set-TenantSettings -RequestBody @{ powerPlatform = @{ governance = @{ disableEnvironmentCreationByNonAdminUsers = `$true; disableTrialEnvironmentCreationByNonAdminUsers = `$true } } }"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/control-environment-creation"
            )

        # Diagnostic: pull tenant settings via BAP API
        $ts = Get-PPTenantSettings
        if ($ts) {
            $disableProd  = $null
            $disableTrial = $null
            try {
                $disableProd  = $ts.powerPlatform.governance.disableEnvironmentCreationByNonAdminUsers
                $disableTrial = $ts.powerPlatform.governance.disableTrialEnvironmentCreationByNonAdminUsers
            } catch { }
            Write-Info "disableEnvironmentCreationByNonAdminUsers      = $disableProd"
            Write-Info "disableTrialEnvironmentCreationByNonAdminUsers = $disableTrial"
            if ($disableProd -eq $true -and $disableTrial -eq $true) {
                Write-Manl "Both flags are True - environment creation appears restricted. Verify in the admin center."
                Add-MANL "2.1" "Env creation restricted to admins" 'PASS' "prod=$disableProd; trial=$disableTrial (restricted)"
            } else {
                Write-Manl "One or both flags are not True - environment creation may NOT be restricted."
                Add-MANL "2.1" "Env creation restricted to admins" 'FAIL' "prod=$disableProd; trial=$disableTrial (NOT fully restricted)"
            }
        } else {
            Write-Manl "Could not read tenant settings via BAP API - verify in the Power Platform Admin Center."
            Add-MANL "2.1" "Env creation restricted to admins" 'UNKNOWN' "BAP API unavailable - $(Get-BapErrorHint)"
        }
    }
}

function Check-MANL-2_2 {
    Invoke-Check "2.2 (L1)" "Ensure 'Security roles provide access to the minimum amount of business data required' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > select environment > Settings",
                "Expand Users + permissions > Security roles",
                "Review each predefined security role and validate that custom roles follow least-privilege",
                "Copy (do not edit) predefined roles before customizing"
            ) `
            -Remediation @(
                "Edit each Security Role to fit environmental needs; apply least privilege and need-to-know",
                "Avoid granting tenant-wide System Administrator to general users"
            ) `
            -References @(
                "https://learn.microsoft.com/dynamics365/customerengagement/on-premises/developer/security-dev/how-role-based-security-control-access-entities"
            )
        Write-Manl "Per-role privilege review requires Dataverse Web API per environment - verify in the admin center."
        Add-MANL "2.2" "Security roles use minimum business-data access" 'UNKNOWN' "Per-environment Dataverse security role review required."
    }
}

function Check-MANL-2_3 {
    Invoke-Check "2.3 (L1)" "Ensure 'Set blocked file extensions' is configured to match the enterprise block list (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > select environment > Settings",
                "Expand Product > Privacy + Security",
                "Review the blocked file extensions list and compare against the organizational block list"
            ) `
            -Remediation @(
                "Add extensions as required by the organizational policy",
                "Defaults include: ade adp app asa ashx asmx asp bas bat cdx cer chm class cmd com config cpl crt csh dll exe fxp hlp hta htr htw ida idc idq inf ins isp its jar js jse ksh lnk ... wsf wsh"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/settings-privacy-security"
            )

        # Automated audit: read blockedattachments from organization entity per env
        $cisDefault = @('ade','adp','app','asa','ashx','asmx','asp','bas','bat','cdx','cer','chm','class','cmd','com','config','cpl','crt','csh','dll','exe','fxp','hlp','hta','htr','htw','ida','idc','idq','inf','ins','isp','its','jar','js','jse','ksh','lnk','mad','maf','mag','mam','maq','mar','mas','mat','mau','mav','maw','mda','mdb','mde','mdt','mdw','mdz','msc','msh','msh1','msh2','mshxml','msh1xml','msh2xml','msi','msp','mst','ops','pcd','pif','plg','prf','prg','printer','pst','reg','rem','scf','scr','sct','shb','shs','shtm','shtml','soap','stm','svc','url','vb','vbe','vbs','vsmacros','vss','vst','vsw','ws','wsc','wsf','wsh')
        $envs = Get-DataverseEnvironments -ContextLabel "2.3 blocked attachments"
        $missing = @()
        $okEnvs  = 0
        foreach ($e in $envs) {
            $envType = $e.properties.environmentSku
            $name    = $e.properties.displayName
            if ($envType -notin @('Production','Sandbox','Trial')) { continue }
            $url = Get-EnvInstanceUrl $e
            if (-not $url) { continue }
            $org = Invoke-DataverseApi -InstanceUrl $url -EnvName $name -Path "organizations?`$select=blockedattachments"
            if ($null -eq $org) { continue }
            $okEnvs++
            $list = @($org.value)[0].blockedattachments
            $current = @()
            if ($list) { $current = $list.Split(';') | ForEach-Object { $_.Trim().TrimStart('.').ToLower() } | Where-Object { $_ } }
            $absent  = @($cisDefault | Where-Object { $_ -notin $current })
            $flag    = if ($absent.Count -eq 0) { 'OK' } else { 'PARTIAL' }
            Write-Info "  -> [$flag] $name :: extensions=$($current.Count); missing from CIS default=$($absent.Count)"
            if ($absent.Count -gt 0) {
                $sample = if ($absent.Count -gt 12) { ($absent[0..11] -join ',') + ',...' } else { $absent -join ',' }
                Write-Info "       missing: $sample"
                $missing += "$name (-$($absent.Count))"
            }
        }
        if ($okEnvs -gt 0) {
            $detail = "Envs queried=$okEnvs; missing CIS defaults in: $($missing -join '; ')"
            if ($missing.Count -eq 0) { $detail = "Envs queried=$okEnvs; all envs cover CIS default block list." }
            $verdict = if ($missing.Count -eq 0) { 'PASS' } else { 'FAIL' }
            Add-MANL "2.3" "Blocked file extensions match enterprise block list" $verdict $detail
        } else {
            Add-MANL "2.3" "Blocked file extensions match enterprise block list" $(if (@($envs).Count -eq 0) { 'NA' } else { 'UNKNOWN' }) (Get-DataverseFallbackDetail @($envs).Count)
        }
        Write-Manl "Verify the per-env extension list against the organizational block list."
    }
}

function Check-MANL-2_4 {
    Invoke-Check "2.4 (L2)" "Ensure 'Access to the environment is restricted by location' (Manual)" {
        Write-ManualAudit `
            -Portal "https://entra.microsoft.com/" `
            -AuditSteps @(
                "Entra ID > Protection > Conditional Access > Policies",
                "Ensure a policy exists that restricts location for Microsoft Dataverse / Dynamics 365 ERP cloud apps",
                "Confirm the policy is enabled (not Report-only)"
            ) `
            -Remediation @(
                "Create a CA policy: Cloud apps > Select apps > Microsoft Dataverse (or Microsoft Dynamics ERP)",
                "Conditions > Locations > Include = Selected locations (the blocked Named location)",
                "Access controls > Block Access, State = On",
                "Exclude break-glass accounts from the policy"
            ) `
            -References @(
                "https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-location",
                "https://learn.microsoft.com/power-platform/admin/restrict-access-online-trusted-ip-rules"
            )

        if ($Script:GraphConnected) {
            try {
                $url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
                $resp = Invoke-MgGraphRequest -Method GET -Uri $url -EA Stop
                $pol = @($resp.value)
                # Dataverse / Dynamics CRM app GUIDs
                $dataverseAppIds = @(
                    '00000007-0000-0000-c000-000000000000',  # Dataverse / D365 Online
                    '00000015-0000-0000-c000-000000000000'   # Dynamics ERP
                )
                $matches = $pol | Where-Object {
                    $_.state -eq 'enabled' -and
                    ($_.conditions.applications.includeApplications | Where-Object { $_ -in $dataverseAppIds -or $_ -eq 'All' }) -and
                    ($_.conditions.locations -ne $null)
                }
                if ($matches -and $matches.Count -gt 0) {
                    Write-Info "CA policies targeting Dataverse/Dynamics with a location condition:"
                    foreach ($p in $matches) { Write-Info "  -> $($p.displayName)" }
                    Add-MANL "2.4" "Access restricted by location (CA)" 'PASS' "Candidate policies: $($matches.displayName -join '; ')"
                } else {
                    Write-Info "No enabled CA policy with Dataverse/Dynamics apps + location condition detected."
                    Add-MANL "2.4" "Access restricted by location (CA)" 'FAIL' "No matching CA policy detected."
                }
                Write-Manl "Verify the location list and excluded users in the Entra portal."
            } catch {
                $emsg = $_.Exception.Message.Split([char]10)[0]
                $Script:LastErrors['Graph:CAPolicies(2.4)'] = $emsg
                Write-Manl "Could not read CA policies: $emsg"
                Add-MANL "2.4" "Access restricted by location (CA)" 'UNKNOWN' "Could not query CA policies via Graph - $emsg"
            }
        } else {
            Write-Manl "Graph not connected - verify in the Entra portal."
            Add-MANL "2.4" "Access restricted by location (CA)" 'UNKNOWN' "Graph not connected - manual review required."
        }
    }
}

function Check-MANL-2_5 {
    Invoke-Check "2.5 (L1)" "Ensure 'Cross-tenant isolation is enabled for Power Platform Apps and Flows' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > Policies > Tenant isolation (preview)",
                "Confirm Tenant Isolation is set to On",
                "Review the allow-list of tenants and inbound/outbound direction"
            ) `
            -Remediation @(
                "Enable Tenant Isolation for outbound and inbound traffic",
                "Add only explicitly trusted tenants to the allow-list",
                "Note: blocking inbound also requires an Azure AD proxy header configuration; see references"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/cross-tenant-restrictions",
                "https://learn.microsoft.com/entra/identity/manage-apps/tenant-restrictions"
            )

        if ($Script:BapConnected) {
            $resp = $null
            $tenantId = $TenantId
            $endpoints = @(
                "https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v1/tenants/$tenantId/crossTenantAccessPolicy?api-version=2020-10-01",
                "https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v1/tenantIsolationPolicy?api-version=2020-10-01"
            )
            foreach ($u in $endpoints) {
                try { $resp = Invoke-BapApi -Url $u; if ($resp) { break } } catch { }
            }
            if ($resp) {
                $enabled = $null
                try { $enabled = $resp.properties.isDisabled -eq $false } catch { }
                if ($null -eq $enabled) {
                    try { $enabled = [bool]$resp.properties.tenantIsolation.isEnabled } catch { }
                }
                $allow = @()
                try { $allow = @($resp.properties.allowedTenants) } catch { }
                if (-not $allow) { try { $allow = @($resp.properties.tenantIsolation.allowedTenants) } catch { } }
                Write-Info "Cross-tenant isolation enabled = $enabled"
                if ($allow) {
                    Write-Info "Allowed tenants ($($allow.Count)):"
                    foreach ($t in $allow) {
                        $inb = $null; $out = $null
                        try { $inb = $t.direction.inbound }  catch { }
                        try { $out = $t.direction.outbound } catch { }
                        Write-Info "  -> $($t.tenantId) inbound=$inb outbound=$out"
                    }
                }
                $verdict = if ($enabled -eq $true) { 'PASS' } elseif ($enabled -eq $false) { 'FAIL' } else { 'UNKNOWN' }
                Add-MANL "2.5" "Cross-tenant isolation enabled" $verdict "Enabled=$enabled; allow-list count=$(@($allow).Count)"
                Write-Manl "Verify the allow-list and direction in the Power Platform Admin Center."
            } else {
                Write-Manl "Could not read tenant isolation policy via BAP API (tried crossTenantAccessPolicy and tenantIsolationPolicy)."
                Add-MANL "2.5" "Cross-tenant isolation enabled" 'UNKNOWN' "BAP API unavailable - $(Get-BapErrorHint)"
            }
        } else {
            Write-Manl "BAP API not connected - verify in the Power Platform Admin Center."
            Add-MANL "2.5" "Cross-tenant isolation enabled" 'UNKNOWN' "BAP API not connected - manual review required."
        }
    }
}

# ===============================================================================
#  SECTION 3 - Data Management
# ===============================================================================

function Check-MANL-3_1 {
    Invoke-Check "3.1 (L2)" "Ensure 'Environments with Critical Data are Encrypted with Customer Managed Keys' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > select environment > Settings",
                "Expand Encryption > Data encryption",
                "Ensure Encryption status = Active and a self-managed (CMK) key is in use"
            ) `
            -Remediation @(
                "Apply a Customer Managed Key (CMK) to the environment; key must be safeguarded externally",
                "CMK requires tenants with >= 1,000 users; smaller tenants need an exception"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/data-encryption",
                "https://learn.microsoft.com/power-platform/admin/manage-encryption-key"
            )

        $envs = Get-AllEnvironments
        if ($envs -and $envs.Count -gt 0) {
            $cmkUnknown = @()
            foreach ($e in $envs) {
                $name = $e.properties.displayName
                $sku  = $e.properties.environmentSku
                $byok = $null
                try { $byok = $e.properties.linkedEnvironmentMetadata.encryptionStatus } catch { }
                try { if (-not $byok) { $byok = $e.properties.encryption.state } } catch { }
                Write-Info "  -> [$sku] $name :: encryptionStatus=$byok"
                if ($sku -in @('Production','Sandbox') -and -not $byok) { $cmkUnknown += $name }
            }
            $detail = "Envs=$($envs.Count); Production/Sandbox without explicit CMK signal=$($cmkUnknown.Count): $($cmkUnknown -join '; ')"
            Write-Manl "BAP API only exposes encryption status partially; verify CMK in the admin center."
            Add-MANL "3.1" "Critical-data environments use CMK" 'UNKNOWN' $detail
        } else {
            Write-Manl "Could not enumerate environments - verify in the admin center."
            Add-MANL "3.1" "Critical-data environments use CMK" 'UNKNOWN' "BAP API unavailable - $(Get-BapErrorHint)"
        }
    }
}

function Check-MANL-3_2 {
    Invoke-Check "3.2 (L1)" "Ensure 'Extract customer data privileges from Microsoft Dynamics 365 is controlled' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > select environment > Settings",
                "Expand Users + permissions > Security roles",
                "Edit each role > Business Management tab > review 'Privacy Related Privileges' (Export to Excel, Mail Merge, Print, Go Offline, etc.)",
                "Ensure each privilege is granted only to roles that require it"
            ) `
            -Remediation @(
                "Disable Privacy Related Privileges on roles that should not extract customer data",
                "Document any granted privilege per organizational policy"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/create-edit-security-role"
            )

        # Automated audit: list which roles per env hold any Privacy-Related privilege.
        # Names from CIS: prvExportToExcel, prvUseMailMerge, prvPrint, prvGoOffline,
        # prvAllowQuickCampaign, prvUseExternalReader, prvDataExport, prvPublishDuplicateDetectionRule.
        $privacyPrivs = @(
            'prvExportToExcel','prvUseMailMerge','prvPrint','prvGoOffline',
            'prvAllowQuickCampaign','prvUseExternalReader','prvDataExport',
            'prvPublishDuplicateDetectionRule'
        )
        $envs = Get-DataverseEnvironments -ContextLabel "3.2 privacy privileges"
        $envsOk = 0
        foreach ($e in $envs) {
            $envType = $e.properties.environmentSku
            $name    = $e.properties.displayName
            if ($envType -notin @('Production','Sandbox','Trial')) { continue }
            $url = Get-EnvInstanceUrl $e
            if (-not $url) { continue }
            $filter = ($privacyPrivs | ForEach-Object { "name eq '$_'" }) -join ' or '
            $p = Invoke-DataverseApi -InstanceUrl $url -EnvName $name -Path "privileges?`$select=privilegeid,name&`$filter=$filter"
            if ($null -eq $p) { continue }
            $envsOk++
            $privs = @($p.value)
            Write-Info "  -> $name :: privacy privileges resolved=$($privs.Count)"
            foreach ($pr in $privs) {
                $assoc = Invoke-DataverseApi -InstanceUrl $url -EnvName $name -Path "roleprivileges?`$select=roleid&`$filter=privilegeid eq $($pr.privilegeid)"
                $cnt = if ($assoc) { @($assoc.value).Count } else { 0 }
                Write-Info "       $($pr.name) granted on $cnt role(s)"
            }
        }
        if ($envsOk -gt 0) {
            Add-MANL "3.2" "Extract customer data privileges controlled" 'UNKNOWN' "Envs queried=$envsOk; review per-role privacy privilege counts above."
        } else {
            Add-MANL "3.2" "Extract customer data privileges controlled" $(if (@($envs).Count -eq 0) { 'NA' } else { 'UNKNOWN' }) (Get-DataverseFallbackDetail @($envs).Count)
        }
        Write-Manl "Privacy-related privileges should be granted only to roles that strictly need them."
    }
}

function Check-MANL-3_3 {
    Invoke-Check "3.3 (L1)" "Ensure 'Dynamics 365 restricts incoming email actions for public queue mailboxes' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > select environment > Settings",
                "Expand Business > Queues",
                "Open each public queue mailbox and verify EMAIL SETTINGS > 'Convert Incoming Email to Activities'",
                "Recommended value: 'Email messages from Dynamics 365 Leads, Contacts, and Accounts'"
            ) `
            -Remediation @(
                "Set 'Convert Incoming Email to Activities' to 'Email messages from Dynamics 365 Leads, Contacts, and Accounts'",
                "Do NOT set to 'All email messages' (will track spam)"
            ) `
            -References @(
                "https://learn.microsoft.com/dynamics365/outlook-addin/user-guide/set-option-automatically-track-incoming-outlook-email"
            )

        # Automated audit: enumerate queues and inspect incomingemaildeliverymethod
        # OptionSet values: 0 None, 1 ServerSide, 2 MicrosoftDynamics365ForOutlook,
        # 3 EmailRouter, 4 ForwardMailbox. CIS-aligned values are 0 or 4.
        $methodMap = @{ 0='None'; 1='ServerSideSync'; 2='OutlookAddin'; 3='EmailRouter'; 4='ForwardMailbox' }
        $envs = Get-DataverseEnvironments -ContextLabel "3.3 public queue email"
        $bad = @()
        $okEnvs = 0
        foreach ($e in $envs) {
            $envType = $e.properties.environmentSku
            $name    = $e.properties.displayName
            if ($envType -notin @('Production','Sandbox','Trial')) { continue }
            $url = Get-EnvInstanceUrl $e
            if (-not $url) { continue }
            $q = Invoke-DataverseApi -InstanceUrl $url -EnvName $name -Path "queues?`$select=name,emailaddress,incomingemaildeliverymethod,queueviewtype&`$filter=queueviewtype eq 0"
            if ($null -eq $q) { continue }
            $okEnvs++
            $queues = @($q.value)
            Write-Info "  -> $name :: public queues=$($queues.Count)"
            foreach ($qu in $queues) {
                $m  = [int]$qu.incomingemaildeliverymethod
                $mn = if ($methodMap.ContainsKey($m)) { $methodMap[$m] } else { "Code$m" }
                $compliant = $m -in @(0,4)
                $flag = if ($compliant) { 'OK' } else { 'FLAG' }
                Write-Info "       [$flag] $($qu.name) <$($qu.emailaddress)> method=$mn"
                if (-not $compliant) { $bad += "$name/$($qu.name)=$mn" }
            }
        }
        if ($okEnvs -gt 0) {
            $detail = if ($bad.Count -eq 0) { "Envs queried=$okEnvs; no public queues with ServerSide/Outlook/EmailRouter delivery." }
                      else { "Envs queried=$okEnvs; non-compliant public queues=$($bad.Count): $($bad -join '; ')" }
            $verdict = if ($bad.Count -eq 0) { 'PASS' } else { 'FAIL' }
            Add-MANL "3.3" "Public-queue incoming email actions restricted" $verdict $detail
        } else {
            Add-MANL "3.3" "Public-queue incoming email actions restricted" $(if (@($envs).Count -eq 0) { 'NA' } else { 'UNKNOWN' }) (Get-DataverseFallbackDetail @($envs).Count)
        }
        Write-Manl "CIS-compliant incoming methods are 'None' (0) or 'Forward Mailbox' (4)."
    }
}

function Check-MANL-3_4 {
    Invoke-Check "3.4 (L1)" "Ensure 'DLP policies are enabled and restrict the connectors usage' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > Policies > Data policies",
                "Verify at least one DLP policy exists and is applied to the appropriate environments",
                "Verify connectors are categorized (Business / Non-business / Blocked)"
            ) `
            -Remediation @(
                "Create a DLP policy: Policies > Data policies > New Policy",
                "Categorize each connector into Business / Non-business / Blocked",
                "Scope the policy to all applicable environments (or tenant-wide)"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/wp-data-loss-prevention",
                "https://learn.microsoft.com/power-platform/admin/create-dlp-policy"
            )

        if ($Script:BapConnected) {
            try {
                $url = "https://api.bap.microsoft.com/providers/PowerPlatform.Governance/v2/policies?api-version=2020-10-01"
                $resp = Invoke-BapApi -Url $url
                $policies = @($resp.value)
                Write-Info "DLP policies via BAP API: $($policies.Count)"
                foreach ($p in $policies) {
                    $scope = if ($p.environmentType) { $p.environmentType } else { 'unknown' }
                    Write-Info "  -> $($p.displayName) :: scope=$scope"
                }
                if ($policies.Count -gt 0) {
                    Add-MANL "3.4" "DLP policies enabled and restrict connectors" 'PASS' "Policies=$($policies.Count): $($policies.displayName -join '; ')"
                } else {
                    Write-Fail "No DLP policies found in the tenant."
                    Add-MANL "3.4" "DLP policies enabled and restrict connectors" 'FAIL' "No DLP policies found - CIS requires at least one."
                }
                Write-Manl "Verify connector categorization and scope in the admin center."
            } catch {
                Write-Manl "Could not read DLP policies via BAP API: $($_.Exception.Message.Split([char]10)[0])"
                Add-MANL "3.4" "DLP policies enabled and restrict connectors" 'UNKNOWN' "BAP API unavailable - $(Get-BapErrorHint)"
            }
        } else {
            Write-Manl "BAP API not connected - verify in the Power Platform Admin Center."
            Add-MANL "3.4" "DLP policies enabled and restrict connectors" 'UNKNOWN' "BAP API not connected - manual review required."
        }
    }
}

# ===============================================================================
#  SECTION 4 - Logging and Auditing
# ===============================================================================

function Check-MANL-4_1 {
    Invoke-Check "4.1 (L1)" "Ensure 'System Administrator security role changes are reviewed periodically' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > select environment > Edit > Settings",
                "Expand Users + permissions > Security roles",
                "Click on 'System Administrator' (the role name, not the three dots)",
                "Review the list of users assigned to System Administrator and confirm each is authorized"
            ) `
            -Remediation @(
                "Remove unauthorized users from the System Administrator role",
                "Document an approval and review cadence (e.g. quarterly) for changes to this role"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/database-security",
                "https://learn.microsoft.com/power-platform/admin/security-roles-privileges"
            )

        # Automated audit: per env, find System Administrator role and enumerate
        # assigned systemusers (excluding disabled / application users).
        $envs = Get-DataverseEnvironments -ContextLabel "4.1 SysAdmin role"
        $totalAdmins = 0
        $envsOk = 0
        foreach ($e in $envs) {
            $envType = $e.properties.environmentSku
            $name    = $e.properties.displayName
            if ($envType -notin @('Production','Sandbox','Trial')) { continue }
            $url = Get-EnvInstanceUrl $e
            if (-not $url) { continue }
            $r = Invoke-DataverseApi -InstanceUrl $url -EnvName $name -Path "roles?`$select=roleid,name&`$filter=name eq 'System Administrator'"
            if ($null -eq $r) { continue }
            $envsOk++
            $roles = @($r.value)
            if ($roles.Count -eq 0) { Write-Info "  -> $name :: System Administrator role not found"; continue }
            $admins = @()
            foreach ($role in $roles) {
                $rid = $role.roleid
                $users = Invoke-DataverseApi -InstanceUrl $url -EnvName $name -Path "systemuserroles?`$select=systemuserid,roleid&`$filter=roleid eq $rid"
                if ($null -eq $users) { continue }
                foreach ($u in @($users.value)) {
                    $uid = $u.systemuserid
                    $user = Invoke-DataverseApi -InstanceUrl $url -EnvName $name -Path "systemusers($uid)?`$select=fullname,domainname,isdisabled,applicationid"
                    if ($null -eq $user) { continue }
                    if ($user.isdisabled) { continue }
                    $kind = if ($user.applicationid) { 'app' } else { 'user' }
                    $admins += "$($user.fullname) <$($user.domainname)> [$kind]"
                }
            }
            $totalAdmins += $admins.Count
            Write-Info "  -> $name :: System Administrator members=$($admins.Count)"
            foreach ($a in $admins) { Write-Info "       $a" }
        }
        if ($envsOk -gt 0) {
            Add-MANL "4.1" "System Administrator role changes reviewed" 'UNKNOWN' "Envs queried=$envsOk; total admin assignments=$totalAdmins"
        } else {
            Add-MANL "4.1" "System Administrator role changes reviewed" $(if (@($envs).Count -eq 0) { 'NA' } else { 'UNKNOWN' }) (Get-DataverseFallbackDetail @($envs).Count)
        }
        Write-Manl "Review the per-env System Administrator membership above and remove unauthorized users."
    }
}

function Check-MANL-4_2 {
    Invoke-Check "4.2 (L1)" "Ensure 'Environment Activity logging is Enabled' (Manual)" {
        Write-ManualAudit `
            -Portal "https://admin.powerplatform.microsoft.com" `
            -AuditSteps @(
                "Power Platform Admin Center > select environment > Settings",
                "Expand Audit and logs > Audit settings",
                "Ensure the following are enabled: Start Auditing, Log access, Read logs",
                "Verify retention matches organizational policy"
            ) `
            -Remediation @(
                "Enable 'Start Auditing', 'Audit Log access' and 'Read logs', then Save",
                "Set the retention period per organizational policy",
                "Logs are surfaced in the Microsoft Purview / Security & Compliance Center"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/admin/enable-use-comprehensive-auditing",
                "https://learn.microsoft.com/power-platform/admin/logging-powerapps"
            )

        # Automated audit: org entity audit flags
        $envs = Get-DataverseEnvironments -ContextLabel "4.2 audit flags"
        $bad = @()
        $okEnvs = 0
        foreach ($e in $envs) {
            $envType = $e.properties.environmentSku
            $name    = $e.properties.displayName
            if ($envType -notin @('Production','Sandbox','Trial')) { continue }
            $url = Get-EnvInstanceUrl $e
            if (-not $url) { continue }
            $sel = 'isauditenabled,isuseraccessauditenabled,isreadauditenabled,auditretentionperiodv2'
            $org = Invoke-DataverseApi -InstanceUrl $url -EnvName $name -Path "organizations?`$select=$sel"
            if ($null -eq $org) { continue }
            $okEnvs++
            $o = @($org.value)[0]
            $au  = [bool]$o.isauditenabled
            $ua  = [bool]$o.isuseraccessauditenabled
            $ra  = [bool]$o.isreadauditenabled
            $ret = $o.auditretentionperiodv2
            $compliant = $au -and $ua -and $ra
            $flag = if ($compliant) { 'OK' } else { 'FAIL' }
            Write-Info "  -> [$flag] $name :: Start=$au LogAccess=$ua ReadLogs=$ra Retention=$ret days"
            if (-not $compliant) { $bad += "$name(Start=$au,LogAccess=$ua,ReadLogs=$ra)" }
        }
        if ($okEnvs -gt 0) {
            $detail = if ($bad.Count -eq 0) { "Envs queried=$okEnvs; auditing fully enabled in all." }
                      else { "Envs queried=$okEnvs; non-compliant=$($bad.Count): $($bad -join '; ')" }
            $verdict = if ($bad.Count -eq 0) { 'PASS' } else { 'FAIL' }
            Add-MANL "4.2" "Environment Activity logging enabled" $verdict $detail
        } else {
            Add-MANL "4.2" "Environment Activity logging enabled" $(if (@($envs).Count -eq 0) { 'NA' } else { 'UNKNOWN' }) (Get-DataverseFallbackDetail @($envs).Count)
        }
        Write-Manl "All three audit flags (Start, Log Access, Read Logs) must be enabled per CIS."
    }
}

function Check-MANL-4_3 {
    Invoke-Check "4.3 (L1)" "Ensure 'App creation notification is enabled in the environment' (Manual)" {
        Write-ManualAudit `
            -Portal "https://purview.microsoft.com / https://compliance.microsoft.com" `
            -AuditSteps @(
                "Microsoft Purview compliance portal > Policies > Alert > Alert policies",
                "Verify an alert policy exists that triggers on PowerApps app publish/create",
                "Activity = PowerApps app (or filter on 'Publish'); recipients are configured"
            ) `
            -Remediation @(
                "Compliance portal > Policies > Alert policies > +New alert policy",
                "Choose Severity and Category, then set Activity = PowerApps app (or search 'Publish')",
                "Add recipient emails for the alert",
                "Note: requires Audit logging enabled at the tenant level"
            ) `
            -References @(
                "https://learn.microsoft.com/power-platform/guidance/adoption/sharing-alerts"
            )
        Write-Manl "Defender / Purview alert policies are not exposed via standard Graph - verify in the Compliance portal."
        Add-MANL "4.3" "App creation notification enabled" 'UNKNOWN' "Requires Purview / Compliance portal verification."
    }
}

# ===============================================================================
#  SUMMARY
# ===============================================================================
function Show-Summary {
    $total  = $Script:Results.Count
    $line92 = "=" * 92
    Write-Host ""
    Write-Host $line92 -ForegroundColor Cyan
    Write-Host "  CIS Power Platform Foundations Benchmark v1.0.0 - RESULTS SUMMARY" -ForegroundColor Cyan
    Write-Host $line92 -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Status column = CIS classification (all 16 items are Manual per CIS)." -ForegroundColor DarkGray
    Write-Host "  AUTO column   = automated verdict from this script (PASS/FAIL/N/A/UNKNOWN)." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host ("  {0,-8} {1,-50} {2,-6} {3}" -f "SECTION","TITLE","STATUS","AUTO")
    Write-Host ("  {0,-8} {1,-50} {2,-6} {3}" -f ("-"*8),("-"*50),("-"*6),("-"*8))

    $autoCounts = @{ PASS=0; FAIL=0; WARN=0; NA=0; UNKNOWN=0 }
    $unknownRows = @()
    foreach ($r in $Script:Results) {
        $col = switch ($r.Status) { "PASS"{"Green"} "FAIL"{"Red"} "MANL"{"Cyan"} default{"Magenta"} }
        $t   = if ($r.Title.Length -gt 50) { $r.Title.Substring(0,47) + "..." } else { $r.Title }
        $auto = 'UNKNOWN'
        if ($r.Detail -match '^\[AUTO:\s*([A-Z/]+)\]') { $auto = $matches[1].Trim() }
        if ($autoCounts.ContainsKey($auto)) { $autoCounts[$auto]++ } else { $autoCounts[$auto] = 1 }
        $autoCol = switch ($auto) { 'PASS'{'Green'} 'FAIL'{'Red'} 'NA'{'DarkGray'} 'WARN'{'Magenta'} default{'Yellow'} }
        Write-Host ("  {0,-8} {1,-50} " -f $r.Section, $t) -NoNewline
        Write-Host ("{0,-6} " -f $r.Status) -ForegroundColor $col -NoNewline
        Write-Host $auto -ForegroundColor $autoCol
        if ($r.Status -ne "PASS") {
            $detailNoTag = $r.Detail -replace '^\[AUTO:[^\]]+\]\s*',''
            Write-Host ("           $detailNoTag") -ForegroundColor DarkGray
        }
        if ($auto -eq 'UNKNOWN') { $unknownRows += $r }
    }

    Write-Host ""
    Write-Host $line92 -ForegroundColor Cyan
    Write-Host ("  Items in report : {0,4}" -f $total)
    Write-Host ""
    Write-Host "  CSV Status counts (CIS classification):" -ForegroundColor Yellow
    $statusGroup = $Script:Results | Group-Object Status
    foreach ($g in $statusGroup) {
        $sc = switch ($g.Name) { 'PASS'{'Green'} 'FAIL'{'Red'} 'MANL'{'Cyan'} 'WARN'{'Magenta'} default{'Gray'} }
        Write-Host ("    {0,-6} : {1,4}" -f $g.Name, $g.Count) -ForegroundColor $sc
    }
    Write-Host ""
    Write-Host "  AUTO verdict counts (automated assessment, all rows are MANL by CIS):" -ForegroundColor Yellow
    Write-Host ("    PASS    : {0,4}" -f $autoCounts.PASS)    -ForegroundColor Green
    Write-Host ("    FAIL    : {0,4}" -f $autoCounts.FAIL)    -ForegroundColor Red
    Write-Host ("    N/A     : {0,4}" -f $autoCounts.NA)      -ForegroundColor DarkGray
    Write-Host ("    UNKNOWN : {0,4}" -f $autoCounts.UNKNOWN) -ForegroundColor Yellow
    Write-Host $line92 -ForegroundColor Cyan
    Write-Host ""

    # Why-UNKNOWN diagnosis: classify each UNKNOWN row by root cause so the
    # operator can see at a glance which ones are fixable vs review-only.
    if ($unknownRows.Count -gt 0) {
        Write-Host "  Why AUTO=UNKNOWN ($($unknownRows.Count) item$(if($unknownRows.Count -ne 1){'s'})):" -ForegroundColor Yellow
        # Review-only items (no automated signal exists, by design)
        $reviewOnly = @('1.3','2.2','3.2','4.1','4.3')
        foreach ($r in $unknownRows) {
            $detail = $r.Detail -replace '^\[AUTO:[^\]]+\]\s*',''
            $cause  = ''
            $hint   = ''
            if     ($r.Section -eq '3.1')                                    { $cause = 'API does not expose CMK state'; $hint = 'Verify in: Power Platform Admin Center > env > Settings > Encryption > Data encryption.' }
            elseif ($detail -match 'Graph not connected')                    { $cause = 'Graph not connected';            $hint = 'Re-run after Connect-MgGraph succeeds (check app permissions and admin consent).' }
            elseif ($detail -match 'BAP API not connected')                  { $cause = 'BAP not connected';              $hint = 'Re-run with -RegisterAsPowerAppMgmtApp or run: Add-PowerAppsAccount; New-PowerAppManagementApp -ApplicationId <appId>.' }
            elseif ($detail -match 'BAP API unavailable')                    { $cause = 'BAP endpoint failed';            $hint = 'SP probably not registered. Run: Add-PowerAppsAccount; New-PowerAppManagementApp -ApplicationId <appId>.' }
            elseif ($detail -match 'no Dataverse-backed environments')       { $cause = 'No Dataverse envs (verdict should be N/A)'; $hint = 'If verdict is UNKNOWN here, the BAP env list returned an env without instanceApiUrl that is still being audited - report a bug.' }
            elseif ($detail -match 'Dataverse Web API unavailable')          { $cause = 'Dataverse 401/403';              $hint = 'SP needs Application User + System Administrator in each env (Permissions helper STEP A + STEP B).' }
            elseif ($detail -match 'Could not query CA policies')            { $cause = 'Graph CA query failed';          $hint = 'Verify Policy.Read.All grant + Entra ID P1 / P2 license.' }
            elseif ($detail -match 'Could not query admins')                 { $cause = 'Graph role query failed';        $hint = 'Verify RoleManagement.Read.All grant.' }
            elseif ($r.Section -in $reviewOnly)                              { $cause = 'Review-only item';               $hint = 'No PASS/FAIL signal possible via API - human review required.' }
            else                                                             { $cause = 'Other';                          $hint = 'See Detail column for specifics.' }
            Write-Host ("    {0,-5} {1}" -f $r.Section, $cause) -ForegroundColor Yellow
            Write-Host ("           detail: $detail") -ForegroundColor DarkGray
            Write-Host ("           hint  : $hint")   -ForegroundColor DarkGray
        }
        Write-Host ""
    }

    # Captured raw errors (HTTP responses, exception messages) keyed by source.
    # Useful to copy-paste into a bug report or to spot tenant-specific issues
    # like throttling, missing consent, or expired tokens.
    if ($Script:LastErrors -and $Script:LastErrors.Count -gt 0) {
        Write-Host "  Captured raw errors ($($Script:LastErrors.Count)):" -ForegroundColor Yellow
        foreach ($k in $Script:LastErrors.Keys) {
            $v = [string]$Script:LastErrors[$k]
            Write-Host ("    [{0}]" -f $k) -ForegroundColor Yellow
            foreach ($line in ($v -split [char]10)) {
                $trim = $line.TrimEnd([char]13)
                if ($trim) { Write-Host ("        {0}" -f $trim) -ForegroundColor DarkGray }
            }
        }
        Write-Host ""
    }

    Write-Host "  Connection status:" -ForegroundColor Yellow
    $g = if ($Script:GraphConnected) { "[OK] Connected"   } else { "[--] Not connected" }
    $b = if ($Script:BapConnected)   { "[OK] Connected"   } else { "[--] Not connected (BAP-based diagnostics skipped)" }
    Write-Host ("    Graph : {0}" -f $g) -ForegroundColor $(if($Script:GraphConnected){'Green'}else{'Red'})
    Write-Host ("    BAP   : {0}" -f $b) -ForegroundColor $(if($Script:BapConnected){'Green'}else{'Yellow'})
    Write-Host ""

    try {
        $Script:Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "  Results exported to: $OutputPath" -ForegroundColor Yellow
    } catch {
        Write-Host "  CSV export failed: $_" -ForegroundColor Red
    }
    Write-Host ""
}

# ===============================================================================
#  MAIN
# ===============================================================================
$StartTime = Get-Date
Clear-Host

Write-Host ""
Write-Host "+==================================================================================+" -ForegroundColor Cyan
Write-Host "|  CIS Microsoft Dynamics 365 / Power Platform Foundations Benchmark v1.0.0        |" -ForegroundColor Cyan
Write-Host "|  16 recommendations - all Manual per CIS                                         |" -ForegroundColor Cyan
Write-Host "+==================================================================================+" -ForegroundColor Cyan

Connect-AllServices

Write-Banner "SECTION 1 - Accounts and Authentication"
Check-MANL-1_1
Check-MANL-1_2
Check-MANL-1_3
Check-MANL-1_4

Write-Banner "SECTION 2 - Permissions"
Check-MANL-2_1
Check-MANL-2_2
Check-MANL-2_3
Check-MANL-2_4
Check-MANL-2_5

Write-Banner "SECTION 3 - Data Management"
Check-MANL-3_1
Check-MANL-3_2
Check-MANL-3_3
Check-MANL-3_4

Write-Banner "SECTION 4 - Logging and Auditing"
Check-MANL-4_1
Check-MANL-4_2
Check-MANL-4_3

Write-Banner "RESULTS SUMMARY"
Show-Summary

$elapsed = (Get-Date) - $StartTime
Write-Host "  Total runtime: $([Math]::Round($elapsed.TotalSeconds, 1))s" -ForegroundColor Gray

if ($Script:GraphConnected) { Disconnect-MgGraph -EA SilentlyContinue | Out-Null }
Write-Host "  All sessions disconnected." -ForegroundColor Gray
Write-Host ""
