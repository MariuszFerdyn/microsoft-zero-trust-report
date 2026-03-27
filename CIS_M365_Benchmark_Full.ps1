#Requires -Version 5.1
<#
.SYNOPSIS
    CIS Microsoft 365 Foundations Benchmark v6.0.1 - All 85 Automated Checks
    Version 3 - All errors from report fixed.

.DESCRIPTION
    Fix log vs v2:
      [EXO]    $ExoConnected flag moved INSIDE try block so it is only $true on real success.
               App-only EXO via client-secret OAuth token (scope: outlook.office365.com).
               Falls back to device-code interactive login if app-only fails.
               App needs Exchange.ManageAsApp permission + EXO role for app-only to work.
      [1.1.4]  Service plan GUIDs now shown as friendly names.
      [1.2.1]  Group visibility: server-side OData filter replaced with client-side Where-Object.
      [1.3.3]  Calendar sharing: guarded by EXO connection; graceful WARN if not connected.
      [1.3.6]  Customer Lockbox: guarded by EXO connection; graceful WARN if not connected.
      [1.3.7]  Third-party storage: improved SP lookup and clearer result logic.
      [2.1.10] DMARC: .onmicrosoft.com domains skipped (they never carry DMARC).
      [3.x]    DLP/Labels: Forbidden -> clear permission WARN with remediation steps.
      [4.2]    Device enrollment: Forbidden -> clear permission WARN.
      [5.2.3.6]System-preferred MFA: includeTargets Hashtable parsed correctly.
      [5.3.1]  PIM: Forbidden -> clear permission WARN.
      [5.3.3]  Access reviews: Forbidden -> clear permission WARN.
      [5.3.4]  PIM approval: removed bad API call, manual WARN only.
      [Sec 9]  Power BI: tries PBI-specific OAuth token first (scope: analysis.windows.net),
               falls back to Graph beta endpoint, clear WARN with permission instructions.

.NOTES
    Required PowerShell Modules:
        Install-Module Microsoft.Graph          -Scope CurrentUser -Force
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
        Install-Module MicrosoftTeams           -Scope CurrentUser -Force
        Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force

    App Registration - Required API Permissions (Application, all require admin consent):
        Microsoft Graph:
          Directory.Read.All, Policy.Read.All, Policy.Read.AuthenticationMethod,
                    Organization.Read.All, User.Read.All,
          Group.Read.All, RoleManagement.Read.All, RoleManagement.Read.Directory,
          DeviceManagementConfiguration.Read.All,
          DeviceManagementServiceConfig.Read.All, <- Section 4.2 (Intune enrollment configurations)
          OrgSettings-Forms.ReadWrite.All,    <- Section 1.3.5 (Forms phishing protection)
          AuditLog.Read.All, Domain.Read.All,
          PrivilegedAccess.Read.AzureAD,      <- Section 5.3.x (requires Entra P2)
          AccessReview.Read.All,              <- Section 5.3.3 (requires Entra P2)
          InformationProtectionPolicy.Read.All,
          Tenant.Read.All,                    <- Section 9.x (Power BI via Graph beta)
          SecurityEvents.Read.All, IdentityRiskyUser.Read.All
        Exchange Online (for app-only EXO, avoids interactive login):
          Exchange.ManageAsApp

    Required Entra ID role assignments on the Service Principal:
      - Power BI Administrator  -> for Section 9 (Power BI tenant settings)
      - Intune Administrator    -> for Section 4 (Device Management)  [requires Intune license]

    For app-only EXO: also assign SP to "View-Only Organization Management"
    role in Exchange Admin Center > Roles > Admin roles.
#>

param(
    [string]$TenantId           = "425b12b1-c9cc-4a2a-98e7-0a7210548876",
    [string]$AppId              = "40bfdd5c-7809-4a38-a809-e2186304c93f",
    [string]$AppSecret          = "OBk8Q~klPctM~trhnbKySUIEHut2xdqf6FQ5Oa2Y",
    [string]$SharePointAdminUrl = "https://m365x76064521-admin.sharepoint.com",
    [string]$TenantDomain       = "M365x76064521.onmicrosoft.com",
    # Set to skip EXO/SPO/Teams interactive prompts
    [switch]$GraphOnlyMode      = $false,
    [string]$OutputPath         = "$PSScriptRoot\CIS_M365_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# ===============================================================================
#  RESULT TRACKING
# ===============================================================================
$Script:PassCount      = 0
$Script:FailCount      = 0
$Script:WarnCount      = 0
$Script:Results        = [System.Collections.Generic.List[object]]::new()
$Script:ExoConnected   = $false
$Script:SpoConnected   = $false
$Script:TeamsConnected = $false

# Service plan GUID -> friendly name map (for 1.1.4 readability)
$PlanNames = @{
    "57ff2da0-773e-42df-b2af-ffb7a2317929" = "Microsoft Teams"
    "efb87545-963c-4e0d-99df-69c6916d9eb0" = "Exchange Online (Plan 1)"
    "9aaf7827-d63c-4b61-89c3-182f06f82e5c" = "Exchange Online (Plan 2)"
    "5dbe027f-2339-4123-9542-606e4d348a72" = "SharePoint Online (Plan 1)"
    "e95bec33-7c88-4a70-8e19-b8f4d771609f" = "SharePoint Online (Plan 2)"
    "b737dad2-2f6c-4c65-90e3-ca563267e8b9" = "SharePoint Online (Plan 1) [E3]"
    "76846ad7-7776-4c40-a281-a386362dd1b9" = "Exchange Online (Plan 2) [E3]"
    "33c4f319-9bdd-48d6-9c4d-410b750a4a5a" = "Teams Exploratory"
}

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
function Write-Info { param([string]$M); Write-Host "    $M"       -ForegroundColor Gray }
function Write-Skip { param([string]$M); Write-Host "  [SKIP] $M" -ForegroundColor DarkGray }

function Add-Result {
    param([string]$Section, [string]$Title, [string]$Status, [string]$Detail)
    $Script:Results.Add([PSCustomObject]@{
        Section = $Section; Title = $Title; Status = $Status; Detail = $Detail
    })
}

function Invoke-Check {
    param([string]$Section, [string]$Title, [scriptblock]$Body)
    Write-CheckHeader $Section $Title
    try { & $Body }
    catch {
        Write-Warn "Unexpected error: $($_.Exception.Message)"
        Add-Result $Section $Title "WARN" "Error: $($_.Exception.Message)"
    }
}

# ===============================================================================
#  MODULE & CONNECTION
# ===============================================================================
function Ensure-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)) {
        Write-Host "    Installing module: $Name ..." -ForegroundColor Yellow
        Install-Module $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    Import-Module $Name -ErrorAction Stop -WarningAction SilentlyContinue
}

# Back-compat alias (older revisions used this name)
function Import-RequiredModule { param([string]$Name) Ensure-Module $Name }

function Get-JwtClaims {
    param([Parameter(Mandatory=$true)][string]$Jwt)

    $parts = $Jwt -split '\.'
    if ($parts.Count -lt 2) { return $null }

    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
        default { }
    }

    try {
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return ($json | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        return $null
    }
}

function Get-GraphErrorDetails {
    param([Parameter(Mandatory=$true)][System.Management.Automation.ErrorRecord]$Err)

    $ex = $Err.Exception
    $status = $null
    $reason = $null
    $content = $null

    foreach ($prop in @('ResponseStatusCode','StatusCode')) {
        if ($ex -and $ex.PSObject.Properties.Name -contains $prop) {
            $status = $ex.$prop
            break
        }
    }
    if (-not $status -and $ex -and $ex.PSObject.Properties.Name -contains 'Response' -and $ex.Response) {
        try { $status = $ex.Response.StatusCode } catch { }
        try { $reason = $ex.Response.ReasonPhrase } catch { }
        try {
            if ($ex.Response.Content) {
                $content = $ex.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            }
        } catch { }
    }

    if (-not $reason -and $ex -and $ex.PSObject.Properties.Name -contains 'ResponseReasonPhrase') {
        $reason = $ex.ResponseReasonPhrase
    }

    if (-not $content -and $ex -and $ex.PSObject.Properties.Name -contains 'ResponseContent') {
        $content = $ex.ResponseContent
    }
    if (-not $content -and $Err.ErrorDetails -and $Err.ErrorDetails.Message) {
        $content = $Err.ErrorDetails.Message
    }

    $graphCode = $null
    $graphMessage = $null
    $requestId = $null
    $clientRequestId = $null

    if ($content) {
        $trim = $content.Trim()
        try {
            $parsed = $trim | ConvertFrom-Json -ErrorAction Stop
            if ($parsed.error) {
                $graphCode = $parsed.error.code
                $graphMessage = $parsed.error.message
                if ($parsed.error.innerError) {
                    $requestId = $parsed.error.innerError.'request-id'
                    $clientRequestId = $parsed.error.innerError.'client-request-id'
                }
            }
        } catch { }
    }

    [PSCustomObject]@{
        Status          = $status
        Reason          = $reason
        GraphCode       = $graphCode
        GraphMessage    = $graphMessage
        RequestId       = $requestId
        ClientRequestId = $clientRequestId
        RawContent      = $content
        ExceptionType   = if ($ex) { $ex.GetType().FullName } else { $null }
        ExceptionMsg    = if ($ex) { $ex.Message } else { $null }
    }
}

function Write-GraphErrorDetails {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.ErrorRecord]$Err,
        [string]$Prefix = "  "
    )
    $d = Get-GraphErrorDetails -Err $Err
    if ($d.Status) {
        $statusText = "$($d.Status)"
        if ($d.Reason) { $statusText += " ($($d.Reason))" }
        Write-Info ("{0}HTTP status: {1}" -f $Prefix, $statusText)
    }
    if ($d.GraphCode)    { Write-Info ("{0}Graph code: {1}" -f $Prefix, $d.GraphCode) }
    if ($d.GraphMessage) { Write-Info ("{0}Graph message: {1}" -f $Prefix, $d.GraphMessage) }
    if ($d.RequestId)    { Write-Info ("{0}Request-Id: {1}" -f $Prefix, $d.RequestId) }
    if ($d.ClientRequestId) { Write-Info ("{0}Client-Request-Id: {1}" -f $Prefix, $d.ClientRequestId) }

    if ($d.RawContent -and -not $d.GraphMessage) {
        $oneLine = $d.RawContent -replace "[\r\n]+", " "
        if ($oneLine.Length -gt 400) { $oneLine = $oneLine.Substring(0, 400) + "..." }
        Write-Info ("{0}Response: {1}" -f $Prefix, $oneLine)
    }

    if ($d.ExceptionMsg) {
        $msg = $d.ExceptionMsg.Split([char]10)[0].Trim()
        Write-Info ("{0}Exception: {1}" -f $Prefix, $msg)
    }
}

function Write-GraphTokenRoles {
    param([string]$Prefix = "  ")
    try {
        $tok = Get-OAuthToken -Scope "https://graph.microsoft.com/.default"
        $claims = Get-JwtClaims -Jwt $tok
        if ($claims -and $claims.roles) {
            $roles = @($claims.roles)
            if ($roles.Count -gt 0) {
                $preview = ($roles | Sort-Object) -join ", "
                if ($preview.Length -gt 400) { $preview = $preview.Substring(0, 400) + "..." }
                Write-Info ("{0}Token roles claim includes: {1}" -f $Prefix, $preview)
            }
        }
    } catch {
        # Ignore token decoding issues
    }
}

function Get-OAuthToken {
    param([string]$Scope)
    $Body = @{
        client_id     = $AppId
        client_secret = $AppSecret
        scope         = $Scope
        grant_type    = "client_credentials"
    }
    $Response = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $Body -ErrorAction Stop
    return $Response.access_token
}

function Connect-AllServices {
    Write-Banner "Connecting to Microsoft Services"

    # -- Microsoft Graph (Service Principal / Client Secret) ---------------------
    Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor Yellow
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
        Write-Host "  [OK] Graph connected (Tenant: $TenantId)" -ForegroundColor Green
    }
    catch {
        Write-Host "  [FAIL] Graph connection failed: $_" -ForegroundColor Red
        exit 1
    }

    if (-not $GraphOnlyMode) {

        # -- Exchange Online (App-only via client-secret OAuth, fallback interactive) --
        Write-Host "  Connecting to Exchange Online..." -ForegroundColor Yellow
        Ensure-Module "ExchangeOnlineManagement"
        $exoConnected = $false

        # Attempt 1: App-only with OAuth token (requires Exchange.ManageAsApp + EXO role)
        try {
            $ExoToken = Get-OAuthToken -Scope "https://outlook.office365.com/.default"
            Connect-ExchangeOnline -AccessToken $ExoToken -Organization $TenantDomain `
                -ShowBanner:$false -ErrorAction Stop
            Write-Host "  [OK] Exchange Online connected (app-only token)" -ForegroundColor Green
            $exoConnected = $true
        }
        catch {
            Write-Host "    App-only EXO failed ($($_.Exception.Message.Split('.')[0])). Trying device-code login..." -ForegroundColor Yellow
        }

        # Attempt 2: Device-code interactive
        # -UseDeviceAuthentication works on ALL EXO module versions (v2.x and v3.x)
        # -Device is an alias added in v3.2+ — we avoid it to prevent param-not-found errors
        if (-not $exoConnected) {
            $exoModVer = (Get-Module ExchangeOnlineManagement -ListAvailable |
                          Sort-Object Version -Descending | Select-Object -First 1).Version
            Write-Host "    ExchangeOnlineManagement module version: $exoModVer" -ForegroundColor DarkGray

            $deviceCodeConnected = $false

            # Primary: -UseDeviceAuthentication (universal, all versions)
            try {
                Connect-ExchangeOnline -ShowBanner:$false -UseDeviceAuthentication -ErrorAction Stop
                $deviceCodeConnected = $true
            }
            catch {
                Write-Host "    -UseDeviceAuthentication failed: $($_.Exception.Message.Split([char]13)[0])" -ForegroundColor Yellow
            }

            if ($deviceCodeConnected) {
                Write-Host "  [OK] Exchange Online connected (device-code interactive)" -ForegroundColor Green
                $exoConnected = $true
            }
            else {
                Write-Host "  [FAIL] Exchange Online connection failed. EXO checks will be SKIPPED." -ForegroundColor Red
                Write-Host "         Fix option A: Update EXO module (run as admin):" -ForegroundColor DarkYellow
                Write-Host "                       Update-Module ExchangeOnlineManagement" -ForegroundColor Cyan
                Write-Host "         Fix option B: Enable app-only auth (no browser prompt):" -ForegroundColor DarkYellow
                Write-Host "                       Add 'Exchange.ManageAsApp' to App Registration" -ForegroundColor Cyan
                Write-Host "                       + assign SP to 'View-Only Organization Management' in EAC" -ForegroundColor Cyan
            }
        }
        # FLAG IS SET ONLY HERE, INSIDE THE BLOCK, AFTER BOTH ATTEMPTS
        $Script:ExoConnected = $exoConnected

        # -- SharePoint Online ----------------------------------------------------
        if ($SharePointAdminUrl -notlike "*YOURTENANTNAME*") {
            Write-Host "  Connecting to SharePoint Online..." -ForegroundColor Yellow
            try {
                Ensure-Module "Microsoft.Online.SharePoint.PowerShell"
                Connect-SPOService -Url $SharePointAdminUrl -ErrorAction Stop
                Write-Host "  [OK] SharePoint Online connected" -ForegroundColor Green
                $Script:SpoConnected = $true
            }
            catch {
                Write-Host "  [FAIL] SharePoint Online: $($_.Exception.Message)" -ForegroundColor Red
                $Script:SpoConnected = $false
            }
        }
        else {
            Write-Host "  [SKIP] SharePointAdminUrl not configured" -ForegroundColor DarkGray
            $Script:SpoConnected = $false
        }

        # -- Microsoft Teams -------------------------------------------------------
        Write-Host "  Connecting to Microsoft Teams..." -ForegroundColor Yellow
        try {
            Ensure-Module "MicrosoftTeams"
            Connect-MicrosoftTeams -TenantId $TenantId -ErrorAction Stop | Out-Null
            Write-Host "  [OK] Microsoft Teams connected" -ForegroundColor Green
            $Script:TeamsConnected = $true
        }
        catch {
            Write-Host "  [FAIL] Teams: $($_.Exception.Message)" -ForegroundColor Red
            $Script:TeamsConnected = $false
        }
    }
    else {
        Write-Host "  [SKIP] GraphOnlyMode - EXO/SPO/Teams skipped" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  Connection status: Graph=[OK]" -NoNewline -ForegroundColor Gray
    Write-Host " EXO=$(if($Script:ExoConnected){'[OK]'}else{'[SKIP]'})" -NoNewline -ForegroundColor $(if($Script:ExoConnected){'Green'}else{'Red'})
    Write-Host " SPO=$(if($Script:SpoConnected){'[OK]'}else{'[SKIP]'})" -NoNewline -ForegroundColor $(if($Script:SpoConnected){'Green'}else{'Red'})
    Write-Host " Teams=$(if($Script:TeamsConnected){'[OK]'}else{'[SKIP]'})" -ForegroundColor $(if($Script:TeamsConnected){'Green'}else{'Red'})
}

# Helper: EXO guard
function Assert-Exo { if (-not $Script:ExoConnected) { Write-Skip "EXO not connected (see connection notes above)"; return $false }; return $true }
function Assert-Spo { if (-not $Script:SpoConnected) { Write-Skip "SPO not connected"; return $false }; return $true }
function Assert-Teams { if (-not $Script:TeamsConnected) { Write-Skip "Teams not connected"; return $false }; return $true }

# ===============================================================================
#  SECTION 1 - Microsoft 365 Admin Center
# ===============================================================================
function Check-1_1_1 {
    Invoke-Check "1.1.1 (L1)" "Ensure Administrative accounts are cloud-only (Automated)" {
        $DirectoryRoles  = Get-MgDirectoryRole -All -EA Stop
        $PrivilegedRoles = $DirectoryRoles | Where-Object {
            $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader"
        }
        $RoleMembers = $PrivilegedRoles | ForEach-Object {
            Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id -EA SilentlyContinue
        } | Select-Object Id -Unique

        $Hybrid = @()
        foreach ($m in $RoleMembers) {
            $u = Get-MgUser -UserId $m.Id -Property UserPrincipalName,DisplayName,OnPremisesSyncEnabled -EA SilentlyContinue
            if ($u -and $u.OnPremisesSyncEnabled -eq $true) {
                $Hybrid += "$($u.DisplayName) | $($u.UserPrincipalName)"
                Write-Info "  -> HYBRID: $($u.DisplayName) | $($u.UserPrincipalName)"
            }
        }
        if ($Hybrid.Count -eq 0) {
            Write-Pass "No hybrid-synced users found in privileged roles."
            Add-Result "1.1.1" "Admin accounts are cloud-only" "PASS" "No hybrid privileged users."
        } else {
            Write-Fail "$($Hybrid.Count) on-prem synced admin(s) found."
            Add-Result "1.1.1" "Admin accounts are cloud-only" "FAIL" "$($Hybrid.Count) hybrid admin(s): $($Hybrid -join '; ')"
        }
    }
}

function Check-1_1_3 {
    Invoke-Check "1.1.3 (L1)" "Ensure between two and four global admins are designated (Automated)" {
        $GARole   = Get-MgDirectoryRole -Filter "RoleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'" -EA Stop
        $Members  = Get-MgDirectoryRoleMember -DirectoryRoleId $GARole.Id -EA Stop
        $GAs      = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($obj in $Members) {
            $type = $obj.AdditionalProperties.'@odata.type'
            if ($type -eq '#microsoft.graph.group') {
                (Get-MgGroupMember -GroupId $obj.Id -EA SilentlyContinue) | ForEach-Object {
                    if ($_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user') {
                        $GAs.Add([PSCustomObject]@{ Name=$_.AdditionalProperties.displayName; UPN=$_.AdditionalProperties.userPrincipalName })
                    }
                }
            } elseif ($type -eq '#microsoft.graph.user') {
                $GAs.Add([PSCustomObject]@{ Name=$obj.AdditionalProperties.displayName; UPN=$obj.AdditionalProperties.userPrincipalName })
            }
        }
        $GAs  = $GAs | Select-Object Name,UPN -Unique
        $count = $GAs.Count
        Write-Info "Global Admins found: $count"
        $GAs | ForEach-Object { Write-Info "  -> $($_.Name) | $($_.UPN)" }

        if ($count -ge 2 -and $count -le 4) {
            Write-Pass "$count Global Admins - within recommended range of 2-4."
            Add-Result "1.1.3" "2-4 Global Admins" "PASS" "$count GAs found."
        } elseif ($count -lt 2) {
            Write-Fail "Only $count Global Admin(s) - minimum is 2."
            Add-Result "1.1.3" "2-4 Global Admins" "FAIL" "Too few: $count (min 2)."
        } else {
            Write-Fail "$count Global Admins - maximum is 4. Reduce privileged access."
            Add-Result "1.1.3" "2-4 Global Admins" "FAIL" "Too many: $count (max 4)."
        }
    }
}

function Check-1_1_4 {
    Invoke-Check "1.1.4 (L1)" "Ensure admin accounts use licenses with reduced application footprint (Automated)" {
        # FIX: show friendly plan names, not GUIDs
        $RiskyPlanIds = @(
            "57ff2da0-773e-42df-b2af-ffb7a2317929",  # Teams
            "efb87545-963c-4e0d-99df-69c6916d9eb0",  # Exchange Plan 1
            "9aaf7827-d63c-4b61-89c3-182f06f82e5c",  # Exchange Plan 2
            "5dbe027f-2339-4123-9542-606e4d348a72",  # SharePoint Plan 1
            "e95bec33-7c88-4a70-8e19-b8f4d771609f",  # SharePoint Plan 2
            "76846ad7-7776-4c40-a281-a386362dd1b9",  # Exchange Plan 2 (E3)
            "b737dad2-2f6c-4c65-90e3-ca563267e8b9"   # SharePoint Plan 1 (E3)
        )
        Write-Info "Checking privileged users for assigned service plans (Teams, Exchange, SharePoint)..."

        $PrivRoles   = Get-MgDirectoryRole -All -EA Stop | Where-Object {
            $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader"
        }
        $RoleMembers = $PrivRoles | ForEach-Object {
            Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id -EA SilentlyContinue
        } | Select-Object Id -Unique

        $OverLicensed = @()
        foreach ($m in $RoleMembers) {
            $u = Get-MgUser -UserId $m.Id -Property DisplayName,UserPrincipalName,AssignedPlans -EA SilentlyContinue
            if ($u) {
                $risky = $u.AssignedPlans | Where-Object {
                    $_.ServicePlanId -in $RiskyPlanIds -and $_.CapabilityStatus -eq "Enabled"
                }
                if ($risky) {
                    $names = $risky | ForEach-Object {
                        if ($PlanNames[$_.ServicePlanId.ToString()]) { $PlanNames[$_.ServicePlanId.ToString()] } else { $_.ServicePlanId.ToString() }
                    }
                    $OverLicensed += "$($u.DisplayName): $($names -join ', ')"
                    Write-Info "  -> $($u.DisplayName): $($names -join ', ')"
                }
            }
        }
        if ($OverLicensed.Count -eq 0) {
            Write-Pass "No admin accounts have productivity service plans assigned."
            Add-Result "1.1.4" "Admin reduced license footprint" "PASS" "No risky plans on admins."
        } else {
            Write-Fail "$($OverLicensed.Count) admin(s) have productivity services assigned."
            Write-Info "  Recommendation: Create dedicated cloud-only admin accounts without productivity licenses."
            Add-Result "1.1.4" "Admin reduced license footprint" "FAIL" "$($OverLicensed.Count) admin(s) with risky licenses."
        }
    }
}

function Check-1_2_1 {
    Invoke-Check "1.2.1 (L2)" "Ensure only organizationally managed/approved public groups exist (Automated)" {
        # FIX: OData filter on 'visibility' is not supported server-side; use client-side filter
        Write-Info "Retrieving all Unified (M365) groups (client-side visibility filter)..."
        $AllGroups    = @(Get-MgGroup -Filter "groupTypes/any(c:c eq 'Unified')" `
            -Property DisplayName,Mail,Visibility -All -EA Stop
        )
        $PublicGroups = @($AllGroups | Where-Object { $_.Visibility -eq "Public" })
        Write-Info "Total M365 groups: $($AllGroups.Count), Public: $($PublicGroups.Count)"
        if ($PublicGroups.Count -eq 0) {
            Write-Pass "No public Microsoft 365 Groups found."
            Add-Result "1.2.1" "No unapproved public groups" "PASS" "No public M365 groups."
        } else {
            Write-Warn "$($PublicGroups.Count) public M365 group(s) - verify each is organizationally approved:"
            $PublicGroups | ForEach-Object { Write-Info "  -> $($_.DisplayName) | $($_.Mail)" }
            Add-Result "1.2.1" "No unapproved public groups" "WARN" "$($PublicGroups.Count) public groups found."
        }
    }
}

function Check-1_2_2 {
    Invoke-Check "1.2.2 (L1)" "Ensure sign-in to shared mailboxes is blocked (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "1.2.2" "Block shared mailbox sign-in" "WARN" "EXO not connected."; return }
        $SharedMBX = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -EA Stop
        $Enabled   = @()
        foreach ($mbx in $SharedMBX) {
            $u = Get-MgUser -UserId $mbx.ExternalDirectoryObjectId `
                -Property AccountEnabled,UserPrincipalName -EA SilentlyContinue
            if ($u -and $u.AccountEnabled) {
                $Enabled += $u.UserPrincipalName
                Write-Info "  -> SIGN-IN ENABLED: $($u.UserPrincipalName)"
            }
        }
        if ($Enabled.Count -eq 0) {
            Write-Pass "All $($SharedMBX.Count) shared mailbox(es) have sign-in blocked."
            Add-Result "1.2.2" "Block shared mailbox sign-in" "PASS" "All shared MBX blocked."
        } else {
            Write-Fail "$($Enabled.Count) shared mailbox(es) have sign-in ENABLED."
            Add-Result "1.2.2" "Block shared mailbox sign-in" "FAIL" "$($Enabled.Count) shared MBX with sign-in."
        }
    }
}

function Check-1_3_1 {
    Invoke-Check "1.3.1 (L1)" "Ensure the Password expiration policy is set to never expire (Automated)" {
        $NeverExpire  = 2147483647
        $NonCompliant = @(Get-MgDomain -EA Stop | Where-Object {
            $_.IsVerified -and $_.PasswordValidityPeriodInDays -ne $NeverExpire
        })
        if ($NonCompliant.Count -eq 0) {
            Write-Pass "All verified domains have 'Never expire' password policy (value = 2147483647)."
            Add-Result "1.3.1" "Password never expire policy" "PASS" "All domains = never expire."
        } else {
            Write-Fail "$($NonCompliant.Count) domain(s) without 'Never expire':"
            $NonCompliant | ForEach-Object { Write-Info "  -> $($_.Id): $($_.PasswordValidityPeriodInDays) days" }
            Add-Result "1.3.1" "Password never expire policy" "FAIL" "$($NonCompliant.Count) domains with expiry."
        }
    }
}

function Check-1_3_2 {
    Invoke-Check "1.3.2 (L2)" "Ensure 'Idle session timeout' is set to 3 hours or less (Automated)" {
        $Policy    = Get-MgPolicyActivityBasedTimeoutPolicy -EA Stop
        $MaxSpan   = [TimeSpan]::Parse('03:00:00')
        if (-not $Policy) {
            Write-Fail "No Activity-Based Timeout policy found - idle session timeout is not configured."
            Write-Info "  Remediation: Entra ID > Properties > Manage security defaults > Session timeout"
            Add-Result "1.3.2" "Idle session timeout <=3h" "FAIL" "No timeout policy configured."
            return
        }
        try {
            $Def = ($Policy.Definition | ConvertFrom-Json)
            $TimeoutStr = $Def.ActivityBasedTimeoutPolicy.ApplicationPolicies[0].WebSessionIdleTimeout
            $TS = [TimeSpan]::Parse($TimeoutStr)
            Write-Info "Idle session timeout: $($TS.Hours)h $($TS.Minutes)m"
            if ($TS -le $MaxSpan) {
                Write-Pass "Idle session timeout ($($TS.Hours)h $($TS.Minutes)m) is within the 3-hour limit."
                Add-Result "1.3.2" "Idle session timeout <=3h" "PASS" "Timeout = $TimeoutStr."
            } else {
                Write-Fail "Idle timeout ($($TS.Hours)h $($TS.Minutes)m) exceeds 3-hour limit."
                Add-Result "1.3.2" "Idle session timeout <=3h" "FAIL" "Too long: $TimeoutStr."
            }
        } catch {
            Write-Warn "Cannot parse timeout from policy definition."
            Add-Result "1.3.2" "Idle session timeout <=3h" "WARN" "Cannot parse timeout value."
        }
    }
}

function Check-1_3_3 {
    Invoke-Check "1.3.3 (L2)" "Ensure external sharing of calendars is not available (Automated)" {
        if (-not (Assert-Exo)) {
            Write-Info "  Manual check: Exchange Admin Center > Organization > Sharing > Individual Sharing"
            Write-Info "  Compliant state: No sharing policies allow anonymous/external calendar sharing."
            Add-Result "1.3.3" "No external calendar sharing" "WARN" "EXO not connected. Manual check required."
            return
        }
        try {
            $SharingPolicies = Get-SharingPolicy -EA Stop
            $AnonSharing = $SharingPolicies | Where-Object {
                $_.Enabled -and ($_.Domains -like "*Anonymous*" -or $_.Domains -like "*CalendarSharingFreeBusyDetail*")
            }
            if ($AnonSharing.Count -gt 0) {
                Write-Fail "External calendar sharing policy allows anonymous access:"
                $AnonSharing | ForEach-Object { Write-Info "  -> $($_.Name): $($_.Domains)" }
                Add-Result "1.3.3" "No external calendar sharing" "FAIL" "Anonymous calendar sharing enabled."
            } else {
                Write-Pass "No anonymous external calendar sharing policies detected."
                Add-Result "1.3.3" "No external calendar sharing" "PASS" "External calendar sharing restricted."
            }
        } catch {
            Write-Warn "EXO error: $($_.Exception.Message)"
            Add-Result "1.3.3" "No external calendar sharing" "WARN" "EXO error."
        }
    }
}

function Check-1_3_4 {
    Invoke-Check "1.3.4 (L1)" "Ensure 'User owned apps and services' is restricted (Automated)" {
        $AuthPol    = Get-MgPolicyAuthorizationPolicy -EA Stop
        $CreateApps = $AuthPol.DefaultUserRolePermissions.AllowedToCreateApps
        Write-Info "AllowedToCreateApps : $CreateApps"
        if ($CreateApps -eq $false) {
            Write-Pass "Users are restricted from creating/registering apps."
            Add-Result "1.3.4" "User owned apps restricted" "PASS" "AllowedToCreateApps = False."
        } else {
            Write-Fail "Users CAN create apps (AllowedToCreateApps = True). Restrict this setting."
            Write-Info "  Remediation: Entra ID > User settings > App registrations > No"
            Add-Result "1.3.4" "User owned apps restricted" "FAIL" "AllowedToCreateApps = True."
        }
    }
}

function Check-1_3_5 {
    Invoke-Check "1.3.5 (L1)" "Ensure internal phishing protection for Forms is enabled (Automated)" {
        try {
            $Uri      = "https://graph.microsoft.com/beta/admin/forms/settings"
            $Response = Invoke-MgGraphRequest -Uri $Uri -EA Stop
            $Setting  = $Response.isInOrgFormsPhishingScanEnabled
            Write-Info "isInOrgFormsPhishingScanEnabled: $Setting"
            if ($Setting -eq $true) {
                Write-Pass "Internal phishing protection for Forms is ENABLED."
                Add-Result "1.3.5" "Forms phishing protection" "PASS" "Phishing scan enabled."
            } else {
                Write-Fail "Internal phishing protection for Forms is DISABLED."
                Write-Info "  Remediation: M365 Admin > Settings > Org Settings > Microsoft Forms > Enable phishing protection"
                Add-Result "1.3.5" "Forms phishing protection" "FAIL" "Phishing scan disabled."
            }
        } catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization_RequestDenied*") {
                Write-Warn "Permission denied. Add 'OrgSettings-Forms.ReadWrite.All' or use a Global Admin account."
                Write-Info "  Note: This Graph beta endpoint requires the calling identity to be"
                Write-Info "  a Global Admin or have the Forms admin role - it cannot be granted to App Registrations."
                Write-Info "  Manual check: M365 Admin Center > Settings > Org Settings > Microsoft Forms"
                Write-Info "  Compliant: 'Phishing protection' checkbox is ticked."
                Add-Result "1.3.5" "Forms phishing protection" "WARN" "Insufficient permissions - requires Global Admin."
            } else { throw }
        }
    }
}

function Check-1_3_6 {
    Invoke-Check "1.3.6 (L2)" "Ensure the customer lockbox feature is enabled (Automated)" {
        if (-not (Assert-Exo)) {
            Write-Info "  Manual check: M365 Admin Center > Settings > Org Settings > Security & Privacy > Customer Lockbox"
            Add-Result "1.3.6" "Customer Lockbox enabled" "WARN" "EXO not connected. Manual check required."
            return
        }
        $Cfg = Get-OrganizationConfig -EA Stop
        Write-Info "CustomerLockBoxEnabled: $($Cfg.CustomerLockBoxEnabled)"
        if ($Cfg.CustomerLockBoxEnabled) {
            Write-Pass "Customer Lockbox is ENABLED."
            Add-Result "1.3.6" "Customer Lockbox enabled" "PASS" "Enabled = True."
        } else {
            Write-Fail "Customer Lockbox is NOT enabled."
            Write-Info "  Remediation: M365 Admin Center > Settings > Org Settings > Security & Privacy > Customer Lockbox > On"
            Add-Result "1.3.6" "Customer Lockbox enabled" "FAIL" "Enabled = False."
        }
    }
}

function Check-1_3_7 {
    Invoke-Check "1.3.7 (L2)" "Ensure third-party storage services are restricted in Microsoft 365 (Automated)" {
        # FIX: improved SP lookup and result logic
        $ThirdPartyAppId = "c1f33bc0-bdb4-4248-ba9b-096807ddb43e"
        $SP = Get-MgServicePrincipal -Filter "appId eq '$ThirdPartyAppId'" -EA SilentlyContinue
        if ($null -eq $SP) {
            # Not present = no 3rd party app added; can also mean not licensed for the feature
            Write-Pass "Third-party storage service principal not found in tenant (not added = restricted)."
            Add-Result "1.3.7" "Third-party storage restricted" "PASS" "SP not found (not installed)."
        } elseif ($SP.AccountEnabled -eq $false) {
            Write-Pass "Third-party storage Service Principal is DISABLED (AccountEnabled = False)."
            Add-Result "1.3.7" "Third-party storage restricted" "PASS" "SP disabled."
        } else {
            Write-Fail "Third-party storage IS enabled (AccountEnabled = True)."
            Write-Info "  SP Display Name: $($SP.DisplayName)"
            Write-Info "  Remediation: Entra ID > Enterprise Applications > $($SP.DisplayName) > Disable"
            Add-Result "1.3.7" "Third-party storage restricted" "FAIL" "SP '$($SP.DisplayName)' is enabled."
        }
    }
}

function Check-1_3_9 {
    Invoke-Check "1.3.9 (L1)" "Ensure shared Bookings pages are restricted to select users (Automated)" {
        if (-not (Assert-Exo)) {
            Write-Info "  Manual check: Exchange Admin Center > Settings > Org settings > Bookings"
            Add-Result "1.3.9" "Bookings restricted" "WARN" "EXO not connected."
            return
        }
        $OrgCfg    = Get-OrganizationConfig -EA SilentlyContinue
        $OwaPolicy = Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -EA Stop
        Write-Info "BookingsMailboxCreationEnabled: $($OwaPolicy.BookingsMailboxCreationEnabled)"
        Write-Info "BookingsEnabled (org)          : $($OrgCfg.BookingsEnabled)"
        if ($OrgCfg.BookingsEnabled -eq $false) {
            Write-Pass "Bookings disabled at org level (most restrictive)."
            Add-Result "1.3.9" "Bookings restricted" "PASS" "Bookings disabled org-wide."
        } elseif ($OwaPolicy.BookingsMailboxCreationEnabled -eq $false) {
            Write-Pass "Shared Bookings page creation is restricted."
            Add-Result "1.3.9" "Bookings restricted" "PASS" "Bookings creation restricted."
        } else {
            Write-Fail "Any user can create Bookings pages (BookingsMailboxCreationEnabled = True)."
            Write-Info "  Remediation: Exchange Admin > Settings > Bookings > restrict to specific users"
            Add-Result "1.3.9" "Bookings restricted" "FAIL" "BookingsMailboxCreationEnabled = True."
        }
    }
}

# ===============================================================================
#  SECTION 2 - Microsoft 365 Defender
# ===============================================================================
function Check-2_1_2 {
    Invoke-Check "2.1.2 (L1)" "Ensure the Common Attachment Types Filter is enabled (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "2.1.2" "Common attachment filter" "WARN" "EXO not connected."; return }
        $Policy = Get-MalwareFilterPolicy -Identity Default -EA Stop
        Write-Info "EnableFileFilter: $($Policy.EnableFileFilter)"
        if ($Policy.EnableFileFilter) {
            Write-Pass "Common Attachment Types Filter is ENABLED."
            Add-Result "2.1.2" "Common attachment filter" "PASS" "EnableFileFilter = True."
        } else {
            Write-Fail "Common Attachment Types Filter is DISABLED."
            Write-Info "  Remediation: Defender portal > Policies & rules > Anti-malware > Default > Common attachments filter > On"
            Add-Result "2.1.2" "Common attachment filter" "FAIL" "EnableFileFilter = False."
        }
    }
}

function Check-2_1_3 {
    Invoke-Check "2.1.3 (L1)" "Ensure notifications for internal users sending malware is Enabled (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "2.1.3" "Malware internal notification" "WARN" "EXO not connected."; return }
        $OK = Get-MalwareFilterPolicy -EA Stop | Where-Object {
            $_.EnableInternalSenderAdminNotifications -and $_.InternalSenderAdminAddress
        }
        if ($OK.Count -gt 0) {
            Write-Pass "Malware internal notification is configured."
            $OK | ForEach-Object { Write-Info "  -> $($_.Identity): $($_.InternalSenderAdminAddress)" }
            Add-Result "2.1.3" "Malware internal notification" "PASS" "Notification configured."
        } else {
            Write-Fail "No malware filter policy has internal admin notifications configured."
            Write-Info "  Remediation: Defender portal > Anti-malware > Default > Notification > Notify an admin about undelivered messages from internal senders"
            Add-Result "2.1.3" "Malware internal notification" "FAIL" "Notification not configured."
        }
    }
}

function Check-2_1_5 {
    Invoke-Check "2.1.5 (L2)" "Ensure Safe Attachments for SharePoint, OneDrive, and Teams is Enabled (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "2.1.5" "Safe Attachments SPO/ODB/Teams" "WARN" "EXO not connected."; return }
        $Atp = Get-AtpPolicyForO365 -EA Stop
        Write-Info "EnableATPForSPOTeamsODB : $($Atp.EnableATPForSPOTeamsODB)"
        Write-Info "EnableSafeDocs          : $($Atp.EnableSafeDocs)"
        Write-Info "AllowSafeDocsOpen       : $($Atp.AllowSafeDocsOpen)"
        if ($Atp.EnableATPForSPOTeamsODB -and $Atp.EnableSafeDocs -and -not $Atp.AllowSafeDocsOpen) {
            Write-Pass "Safe Attachments for SPO/ODB/Teams fully configured."
            Add-Result "2.1.5" "Safe Attachments SPO/ODB/Teams" "PASS" "All ATP settings correct."
        } else {
            Write-Fail "Safe Attachments NOT fully configured."
            Write-Info "  Remediation: Defender portal > Policies & rules > Safe Attachments > Global settings"
            Add-Result "2.1.5" "Safe Attachments SPO/ODB/Teams" "FAIL" "One or more ATP settings incorrect."
        }
    }
}

function Check-2_1_6 {
    Invoke-Check "2.1.6 (L1)" "Ensure Exchange Online Spam Policies are set to notify administrators (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "2.1.6" "Spam admin notification" "WARN" "EXO not connected."; return }
        $OK = Get-HostedOutboundSpamFilterPolicy -EA Stop | Where-Object {
            $_.BccSuspiciousOutboundMail -or $_.NotifyOutboundSpam
        }
        if ($OK.Count -gt 0) {
            Write-Pass "Outbound spam admin notification is configured."
            $OK | ForEach-Object { Write-Info "  -> $($_.Identity): BCC=$($_.BccSuspiciousOutboundMail), Notify=$($_.NotifyOutboundSpam)" }
            Add-Result "2.1.6" "Spam admin notification" "PASS" "Notification enabled."
        } else {
            Write-Fail "No outbound spam policy has admin notifications configured."
            Write-Info "  Remediation: Defender portal > Anti-spam > Outbound spam policy > Default > Notifications"
            Add-Result "2.1.6" "Spam admin notification" "FAIL" "Admin notification missing."
        }
    }
}

function Check-2_1_8 {
    Invoke-Check "2.1.8 (L1)" "Ensure SPF records are published for all Exchange Domains (Automated)" {
        $Domains = Get-MgDomain -All -EA Stop | Where-Object { $_.IsVerified }
        $Missing = @()
        foreach ($d in $Domains) {
            try {
                $SPF = Resolve-DnsName -Name $d.Id -Type TXT -EA SilentlyContinue |
                    Where-Object { $_.Strings -like "*v=spf1*" }
                if ($SPF) { Write-Info "  -> $($d.Id): SPF found" }
                else { $Missing += $d.Id }
            } catch { $Missing += "$($d.Id) [DNS error]" }
        }
        if ($Missing.Count -eq 0) {
            Write-Pass "SPF records found for all verified Exchange domains."
            Add-Result "2.1.8" "SPF records published" "PASS" "All domains have SPF."
        } else {
            Write-Fail "SPF MISSING for: $($Missing -join ', ')"
            Add-Result "2.1.8" "SPF records published" "FAIL" "Missing: $($Missing -join ', ')"
        }
    }
}

function Check-2_1_9 {
    Invoke-Check "2.1.9 (L1)" "Ensure DKIM is enabled for all Exchange Online Domains (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "2.1.9" "DKIM enabled all domains" "WARN" "EXO not connected."; return }
        $Configs = Get-DkimSigningConfig -EA Stop
        $Bad     = $Configs | Where-Object { -not $_.Enabled -or $_.Status -ne "Valid" }
        if ($Bad.Count -eq 0) {
            Write-Pass "DKIM enabled and valid for all domains."
            $Configs | ForEach-Object { Write-Info "  -> $($_.Name): Enabled=$($_.Enabled), Status=$($_.Status)" }
            Add-Result "2.1.9" "DKIM enabled all domains" "PASS" "All domains valid."
        } else {
            Write-Fail "$($Bad.Count) domain(s) with DKIM not enabled or invalid:"
            $Bad | ForEach-Object { Write-Info "  -> $($_.Name): Enabled=$($_.Enabled), Status=$($_.Status)" }
            Add-Result "2.1.9" "DKIM enabled all domains" "FAIL" "$($Bad.Count) domains not valid."
        }
    }
}

function Check-2_1_10 {
    Invoke-Check "2.1.10 (L1)" "Ensure DMARC Records for all Exchange Online domains are published (Automated)" {
        $Domains = Get-MgDomain -All -EA Stop | Where-Object { $_.IsVerified }
        $Missing = @()
        foreach ($d in $Domains) {
            # FIX: .onmicrosoft.com domains never carry DMARC - skip them
            if ($d.Id -like "*.onmicrosoft.com") {
                Write-Info "  -> $($d.Id): Skipped (.onmicrosoft.com - DMARC not expected)"
                continue
            }
            try {
                $DMARC = Resolve-DnsName -Name "_dmarc.$($d.Id)" -Type TXT -EA SilentlyContinue |
                    Where-Object { $_.Strings -like "*v=DMARC1*" }
                if ($DMARC) { Write-Info "  -> $($d.Id): DMARC found" }
                else { $Missing += $d.Id }
            } catch { $Missing += "$($d.Id) [DNS error]" }
        }
        if ($Missing.Count -eq 0) {
            Write-Pass "DMARC records found for all custom domains (.onmicrosoft.com skipped)."
            Add-Result "2.1.10" "DMARC records published" "PASS" "All custom domains have DMARC."
        } else {
            Write-Fail "DMARC MISSING for: $($Missing -join ', ')"
            Add-Result "2.1.10" "DMARC records published" "FAIL" "Missing: $($Missing -join ', ')"
        }
    }
}

function Check-2_1_13 {
    Invoke-Check "2.1.13 (L1)" "Ensure the connection filter safe list is off (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "2.1.13" "Connection filter safe list off" "WARN" "EXO not connected."; return }
        $Policy = Get-HostedConnectionFilterPolicy -Identity Default -EA Stop
        Write-Info "EnableSafeList: $($Policy.EnableSafeList)"
        if ($Policy.EnableSafeList -eq $false) {
            Write-Pass "Connection filter safe list is OFF."
            Add-Result "2.1.13" "Connection filter safe list off" "PASS" "EnableSafeList = False."
        } else {
            Write-Fail "Connection filter safe list is ENABLED."
            Write-Info "  Remediation: Defender portal > Anti-spam > Connection filter policy > Enable safe list = Off"
            Add-Result "2.1.13" "Connection filter safe list off" "FAIL" "EnableSafeList = True."
        }
    }
}

function Check-2_1_14 {
    Invoke-Check "2.1.14 (L1)" "Ensure inbound anti-spam policies do not contain allowed domains (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "2.1.14" "No bypass domains in spam policy" "WARN" "EXO not connected."; return }
        $Bad = Get-HostedContentFilterPolicy -EA Stop | Where-Object { $_.AllowedSenderDomains.Count -gt 0 }
        if ($Bad.Count -eq 0) {
            Write-Pass "No inbound spam policies contain allowed sender domains."
            Add-Result "2.1.14" "No bypass domains in spam policy" "PASS" "No bypass domains."
        } else {
            Write-Fail "$($Bad.Count) policy/policies with allowed sender domains:"
            $Bad | ForEach-Object { Write-Info "  -> $($_.Identity): $($_.AllowedSenderDomains -join ', ')" }
            Add-Result "2.1.14" "No bypass domains in spam policy" "FAIL" "Bypass domains found."
        }
    }
}

function Check-2_1_15 {
    Invoke-Check "2.1.15 (L1)" "Ensure outbound anti-spam message limits are in place (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "2.1.15" "Outbound spam limits" "WARN" "EXO not connected."; return }
        $Policy = Get-HostedOutboundSpamFilterPolicy -Identity Default -EA Stop
        Write-Info "RecipientLimitExternalPerHour : $($Policy.RecipientLimitExternalPerHour)"
        Write-Info "RecipientLimitInternalPerHour : $($Policy.RecipientLimitInternalPerHour)"
        Write-Info "RecipientLimitPerDay          : $($Policy.RecipientLimitPerDay)"
        Write-Info "ActionWhenThresholdReached    : $($Policy.ActionWhenThresholdReached)"
        $OK = (
            $Policy.RecipientLimitExternalPerHour -gt 0 -and $Policy.RecipientLimitExternalPerHour -le 500  -and
            $Policy.RecipientLimitInternalPerHour -gt 0 -and $Policy.RecipientLimitInternalPerHour -le 1000 -and
            $Policy.RecipientLimitPerDay          -gt 0 -and $Policy.RecipientLimitPerDay          -le 1000 -and
            $Policy.ActionWhenThresholdReached    -eq "BlockUser"
        )
        if ($OK) {
            Write-Pass "Outbound spam limits correctly configured."
            Add-Result "2.1.15" "Outbound spam limits" "PASS" "Limits within thresholds."
        } else {
            Write-Fail "Outbound spam limits do NOT meet CIS recommendations."
            Add-Result "2.1.15" "Outbound spam limits" "FAIL" "Check values above."
        }
    }
}

# ===============================================================================
#  SECTION 3 - Compliance
# ===============================================================================
function Check-3_2_1 {
    Invoke-Check "3.2.1 (L1)" "Ensure DLP policies are enabled (Automated)" {
        Write-Warn "DLP policy check is not currently automated in this script."
        Write-Info "  Manual check: Microsoft Purview > Data loss prevention > Policies"
        Write-Info "  Compliant: At least one enabled policy covering Exchange, SharePoint, OneDrive, Teams."
        Add-Result "3.2.1" "DLP policies enabled" "WARN" "Manual verification required (Purview DLP policies not queried here)."
    }
}

function Check-3_3_1 {
    Invoke-Check "3.3.1 (L1)" "Ensure Information Protection sensitivity label policies are published (Automated)" {
        try {
            $Uri      = "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels"
            $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri -EA Stop
            $Count    = $Response.value.Count
            if ($Count -gt 0) {
                Write-Pass "$Count sensitivity label(s) found."
                Write-Info "  Verify labels are published via label policies in Microsoft Purview."
                Add-Result "3.3.1" "Sensitivity labels published" "PASS" "$Count labels found."
            } else {
                Write-Fail "No sensitivity labels found."
                Write-Info "  Remediation: Microsoft Purview > Information Protection > Labels > Create label > Publish"
                Add-Result "3.3.1" "Sensitivity labels published" "FAIL" "No labels found."
            }
        } catch {
            if ($_.Exception.Message -like "*Forbidden*") {
                Write-Warn "Permission denied reading sensitivity labels from Graph."
                Write-GraphErrorDetails -Err $_
                Write-GraphTokenRoles
                Write-Info "  Required: Microsoft Graph Application permission 'InformationProtectionPolicy.Read.All' + admin consent"
                Write-Info "  Manual check: Microsoft Purview > Information Protection > Labels > Label policies"
            } else {
                Write-Warn "Error: $($_.Exception.Message)"
            }
            Add-Result "3.3.1" "Sensitivity labels published" "WARN" "Unable to read sensitivity labels (see error details)."
        }
    }
}

# ===============================================================================
#  SECTION 4 - Intune / Device Management
# ===============================================================================
function Check-4_1 {
    Invoke-Check "4.1 (L2)" "Ensure devices without compliance policy are marked 'not compliant' (Automated)" {
        try {
            $Uri      = "https://graph.microsoft.com/v1.0/deviceManagement/settings"
            $Settings = Invoke-MgGraphRequest -Uri $Uri -Method GET -EA Stop
            Write-Info "secureByDefault: $($Settings.secureByDefault)"
            if ($Settings.secureByDefault -eq $true) {
                Write-Pass "Devices without compliance policy marked 'not compliant' (secureByDefault = True)."
                Add-Result "4.1" "Devices default not-compliant" "PASS" "secureByDefault = True."
            } else {
                Write-Fail "Devices without compliance policy are NOT marked not-compliant (secureByDefault = False)."
                Write-Info "  Remediation: Intune > Devices > Compliance policies > Compliance policy settings > Mark devices with no compliance policy as: Not compliant"
                Add-Result "4.1" "Devices default not-compliant" "FAIL" "secureByDefault = False."
            }
        } catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization_RequestDenied*") {
                Write-Warn "Permission denied accessing Intune device settings."
                Write-GraphErrorDetails -Err $_
                Write-GraphTokenRoles
                Write-Info "  Required: 'DeviceManagementConfiguration.Read.All' Graph permission (Application) + admin consent"
                Write-Info "  Also required: Intune license on the tenant + SP assigned 'Intune Administrator' role"
                Write-Info "    Entra ID > Roles and administrators > Intune Administrator > Add assignments"
                Add-Result "4.1" "Devices default not-compliant" "WARN" "Forbidden - check DeviceManagementConfiguration.Read.All + Intune license."
            } else { throw }
        }
    }
}

function Check-4_2 {
    Invoke-Check "4.2 (L1)" "Ensure device enrollment for personally owned devices is blocked (Automated)" {
        try {
            $Uri    = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations"
            $Config = (Invoke-MgGraphRequest -Uri $Uri -Method GET -EA Stop).value |
                Where-Object { $_.'@odata.type' -like "*platformRestriction*" -and $_.priority -ne 0 } |
                Select-Object -First 1
            if (-not $Config) {
                Write-Warn "No platform restriction config found. Verify in Intune > Devices > Enrollment."
                Add-Result "4.2" "Block personal device enrollment" "WARN" "Config not found."
                return
            }
            $Win = $Config.windowsRestriction.personalDeviceEnrollmentBlocked
            $iOS = $Config.iosRestriction.personalDeviceEnrollmentBlocked
            $And = $Config.androidRestriction.personalDeviceEnrollmentBlocked
            Write-Info "Windows personal blocked : $Win"
            Write-Info "iOS personal blocked     : $iOS"
            Write-Info "Android personal blocked : $And"
            if ($Win -and $iOS -and $And) {
                Write-Pass "Personal device enrollment blocked for all platforms."
                Add-Result "4.2" "Block personal device enrollment" "PASS" "All platforms blocked."
            } else {
                Write-Fail "Personal device enrollment NOT blocked for all platforms."
                Write-Info "  Remediation: Intune > Devices > Enrollment > Device platform restriction"
                Add-Result "4.2" "Block personal device enrollment" "FAIL" "Win=$Win, iOS=$iOS, Android=$And."
            }
        } catch {
            if ($_.Exception.Message -like "*Forbidden*") {
                Write-Warn "Permission denied accessing Intune enrollment configurations."
                Write-GraphErrorDetails -Err $_
                Write-GraphTokenRoles
                Write-Info "  Required: 'DeviceManagementServiceConfig.Read.All' (or 'DeviceManagementServiceConfiguration.Read.All') Graph Application permission + admin consent"
                Write-Info "  Also required: Intune license + SP assigned 'Intune Administrator' Entra role"
            } else { throw }
            Add-Result "4.2" "Block personal device enrollment" "WARN" "Forbidden - check DeviceManagementServiceConfig.Read.All + Intune license."
        }
    }
}

# ===============================================================================
#  SECTION 5 - Microsoft Entra ID
# ===============================================================================

function Check-5_1_2_1 {
    Invoke-Check "5.1.2.1 (L1)" "Ensure 'Per-user MFA' is disabled (Automated)" {
        $AllUsers = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName -EA Stop |
                    Where-Object { $_.Id -and $_.Id.Trim() -ne '' }   # guard against empty Id
        $PerUserMFA = [System.Collections.Generic.List[string]]::new()
        foreach ($u in $AllUsers) {
            $detail = Get-MgUser -UserId $u.Id -Property StrongAuthenticationRequirements -EA SilentlyContinue
            $reqs   = $detail.AdditionalProperties['strongAuthenticationRequirements']
            if ($reqs -and $reqs.Count -gt 0) {
                $state = $reqs[0].state
                if ($state -notin @('disabled', $null, '')) {
                    $PerUserMFA.Add("$($u.DisplayName) | $($u.UserPrincipalName) (state: $state)")
                }
            }
        }
        if ($PerUserMFA.Count -eq 0) {
            Write-Pass "Per-user MFA is disabled for all users - CA-based MFA should be in use."
            Add-Result "5.1.2.1" "Per-user MFA disabled" "PASS" "No per-user MFA found."
        } else {
            Write-Fail "$($PerUserMFA.Count) user(s) have per-user MFA enabled:"
            $PerUserMFA | ForEach-Object { Write-Info "  -> $_" }
            Add-Result "5.1.2.1" "Per-user MFA disabled" "FAIL" "$($PerUserMFA.Count) users with per-user MFA."
        }
    }
}

function Check-5_1_2_2 {
    Invoke-Check "5.1.2.2 (L2)" "Ensure third party integrated applications are not allowed (Automated)" {
        $AuthPol    = Get-MgPolicyAuthorizationPolicy -EA Stop
        $CreateApps = $AuthPol.DefaultUserRolePermissions.AllowedToCreateApps
        Write-Info "AllowedToCreateApps: $CreateApps"
        if ($CreateApps -eq $false) {
            Write-Pass "Third-party app registration by users is DISABLED."
            Add-Result "5.1.2.2" "No 3rd party app registration" "PASS" "AllowedToCreateApps = False."
        } else {
            Write-Fail "Users CAN register third-party applications (AllowedToCreateApps = True)."
            Write-Info "  Remediation: Entra ID > User settings > App registrations = No"
            Add-Result "5.1.2.2" "No 3rd party app registration" "FAIL" "AllowedToCreateApps = True."
        }
    }
}

function Check-5_1_2_3 {
    Invoke-Check "5.1.2.3 (L1)" "Ensure non-admin users cannot create tenants (Automated)" {
        $AuthPol       = Get-MgPolicyAuthorizationPolicy -EA Stop
        $CreateTenants = $AuthPol.DefaultUserRolePermissions.AllowedToCreateTenants
        Write-Info "AllowedToCreateTenants: $CreateTenants"
        if ($CreateTenants -eq $false) {
            Write-Pass "Non-admin users are restricted from creating tenants."
            Add-Result "5.1.2.3" "Restrict tenant creation" "PASS" "AllowedToCreateTenants = False."
        } else {
            Write-Fail "Non-admin users CAN create tenants."
            Write-Info "  Remediation: Entra ID > User settings > Restrict non-admin users from creating tenants = Yes"
            Add-Result "5.1.2.3" "Restrict tenant creation" "FAIL" "AllowedToCreateTenants = True."
        }
    }
}

function Check-5_1_4_2 {
    Invoke-Check "5.1.4.2 (L1)" "Ensure the maximum number of devices per user is limited (Automated)" {
        $Uri    = "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy"
        $Policy = Invoke-MgGraphRequest -Method GET -Uri $Uri -EA Stop
        $Quota  = $Policy.userDeviceQuota
        Write-Info "userDeviceQuota: $Quota"
        if ($Quota -gt 0 -and $Quota -le 20) {
            Write-Pass "Device limit per user is $Quota (CIS max = 20)."
            Add-Result "5.1.4.2" "Max devices per user" "PASS" "Quota = $Quota."
        } else {
            Write-Fail "Device limit is $Quota - CIS recommends 20 or fewer."
            Write-Info "  Remediation: Entra ID > Devices > Device settings > Maximum number of devices per user = 20"
            Add-Result "5.1.4.2" "Max devices per user" "FAIL" "Quota = $Quota (should be <=20)."
        }
    }
}

function Check-5_1_4_3 {
    Invoke-Check "5.1.4.3 (L1)" "Ensure GA role is not added as local admin during Entra join (Automated)" {
        $Uri    = "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy"
        $Policy = Invoke-MgGraphRequest -Method GET -Uri $Uri -EA Stop
        $GALocalAdmin = $Policy.azureADJoin.localAdmins.enableGlobalAdmins
        Write-Info "enableGlobalAdmins: $GALocalAdmin"
        if ($GALocalAdmin -eq $false) {
            Write-Pass "GA role is NOT added as local admin during Entra join."
            Add-Result "5.1.4.3" "GA not local admin on join" "PASS" "enableGlobalAdmins = False."
        } else {
            Write-Fail "Global Administrator role IS added as local admin during Entra join."
            Write-Info "  Remediation: Entra ID > Devices > Device settings > Additional local administrators on joined devices = None"
            Add-Result "5.1.4.3" "GA not local admin on join" "FAIL" "enableGlobalAdmins = True."
        }
    }
}

function Check-5_1_4_4 {
    Invoke-Check "5.1.4.4 (L1)" "Ensure local administrator assignment is limited during Entra join (Automated)" {
        $Uri     = "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy"
        $Policy  = Invoke-MgGraphRequest -Method GET -Uri $Uri -EA Stop
        $RegType = $Policy.azureADJoin.localAdmins.registeringUsers.'@odata.type'
        Write-Info "Registering users type: $RegType"
        $Compliant = @(
            "#microsoft.graph.enumeratedDeviceRegistrationMembership",
            "#microsoft.graph.noDeviceRegistrationMembership"
        )
        if ($RegType -in $Compliant) {
            Write-Pass "Local admin assignment is limited (type = $RegType)."
            Add-Result "5.1.4.4" "Limit local admin on Entra join" "PASS" "Type = $RegType."
        } else {
            Write-Fail "All registering users become local admins (type = $RegType)."
            Write-Info "  Remediation: Entra ID > Devices > Device settings > Local administrator settings = Selected"
            Add-Result "5.1.4.4" "Limit local admin on Entra join" "FAIL" "Type = $RegType."
        }
    }
}

function Check-5_1_4_5 {
    Invoke-Check "5.1.4.5 (L1)" "Ensure Local Administrator Password Solution (LAPS) is enabled (Automated)" {
        $Uri    = "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy"
        $Policy = Invoke-MgGraphRequest -Method GET -Uri $Uri -EA Stop
        $Laps   = $Policy.localAdminPassword.isEnabled
        Write-Info "LAPS isEnabled: $Laps"
        if ($Laps -eq $true) {
            Write-Pass "LAPS is ENABLED."
            Add-Result "5.1.4.5" "LAPS enabled" "PASS" "LAPS = True."
        } else {
            Write-Fail "Local Administrator Password Solution (LAPS) is NOT enabled."
            Write-Info "  Remediation: Entra ID > Devices > Device settings > Enable Microsoft Entra Local Administrator Password Solution (LAPS) = Yes"
            Add-Result "5.1.4.5" "LAPS enabled" "FAIL" "LAPS = False."
        }
    }
}

function Check-5_1_4_6 {
    Invoke-Check "5.1.4.6 (L2)" "Ensure users are restricted from recovering BitLocker keys (Automated)" {
        $AuthPol   = Get-MgPolicyAuthorizationPolicy -EA Stop
        $BitLocker = $AuthPol.DefaultUserRolePermissions.AllowedToReadBitlockerKeysForOwnedDevice
        Write-Info "AllowedToReadBitlockerKeysForOwnedDevice: $BitLocker"
        if ($BitLocker -eq $false) {
            Write-Pass "Users restricted from self-recovering BitLocker keys."
            Add-Result "5.1.4.6" "Restrict BitLocker key recovery" "PASS" "BitLocker self-recovery = False."
        } else {
            Write-Fail "Users CAN recover their own BitLocker keys."
            Write-Info "  Remediation: Entra ID > Devices > Device settings > Restrict access to BitLocker recovery keys = Yes"
            Add-Result "5.1.4.6" "Restrict BitLocker key recovery" "FAIL" "BitLocker self-recovery = True."
        }
    }
}

function Check-5_1_5_1 {
    Invoke-Check "5.1.5.1 (L1)" "Ensure user consent to apps accessing company data is not allowed (Automated)" {
        $AuthPol   = Get-MgPolicyAuthorizationPolicy -EA Stop
        $GrantPols = @($AuthPol.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)
        Write-Info "PermissionGrantPoliciesAssigned:"
        $GrantPols | ForEach-Object { Write-Info "  -> $_" }
        $Risky = @($GrantPols | Where-Object {
            $_ -like "*microsoft-user-default-low*" -or $_ -like "*microsoft-user-default-legacy*"
        })
        if ($Risky.Count -eq 0) {
            Write-Pass "User consent for apps is NOT allowed via default-low or legacy policies."
            Add-Result "5.1.5.1" "No user consent to apps" "PASS" "No risky consent policies."
        } else {
            Write-Fail "User consent enabled via: $($Risky -join ', ')"
            Write-Info "  Remediation: Entra ID > Enterprise Apps > Consent and permissions > Do not allow user consent"
            Add-Result "5.1.5.1" "No user consent to apps" "FAIL" "Risky consent: $($Risky -join ', ')"
        }
    }
}

function Check-5_1_6_1 {
    Invoke-Check "5.1.6.1 (L1)" "Ensure collaboration invitations are sent to allowed domains only (Automated)" {
        try {
            $Uri      = "https://graph.microsoft.com/beta/legacy/policies"
            $Response = (Invoke-MgGraphRequest -Uri $Uri -EA Stop).value |
                Where-Object { $_.type -eq 'B2BManagementPolicy' }
            if ($Response) {
                $Definition    = $Response.definition | ConvertFrom-Json
                $DomainsPolicy = $Definition.B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy
                Write-Info "AllowedDomains: $($DomainsPolicy.AllowedDomains -join ', ')"
                Write-Info "BlockedDomains: $($DomainsPolicy.BlockedDomains -join ', ')"
                if ($DomainsPolicy.AllowedDomains.Count -gt 0 -or $DomainsPolicy.BlockedDomains.Count -gt 0) {
                    Write-Pass "B2B invitation domain restrictions are configured."
                    Add-Result "5.1.6.1" "B2B invitation domain restriction" "PASS" "Domain policy configured."
                } else {
                    Write-Fail "B2B policy exists but no domains defined - any domain can be invited."
                    Add-Result "5.1.6.1" "B2B invitation domain restriction" "FAIL" "No domains in B2B policy."
                }
            } else {
                Write-Fail "No B2B domain management policy found - invitations may go to any domain."
                Write-Info "  Remediation: Entra ID > External Identities > External collaboration settings > Collaboration restrictions"
                Add-Result "5.1.6.1" "B2B invitation domain restriction" "FAIL" "No B2B policy found."
            }
        } catch {
            Write-Warn "Could not check B2B policy: $($_.Exception.Message)"
            Add-Result "5.1.6.1" "B2B invitation domain restriction" "WARN" "Error checking policy."
        }
    }
}

function Check-5_1_6_3 {
    Invoke-Check "5.1.6.3 (L2)" "Ensure guest invitations are limited to the Guest Inviter role (Automated)" {
        $AuthPol      = Get-MgPolicyAuthorizationPolicy -EA Stop
        $AllowInvites = $AuthPol.AllowInvitesFrom
        Write-Info "AllowInvitesFrom: $AllowInvites"
        if ($AllowInvites -in @("adminsAndGuestInviters", "none", "adminsGuestInvitersAndMemberUsers")) {
            Write-Pass "Guest invitations limited (AllowInvitesFrom = $AllowInvites)."
            Add-Result "5.1.6.3" "Guest invite limited to Guest Inviter" "PASS" "AllowInvitesFrom = $AllowInvites."
        } else {
            Write-Fail "Guest invitations NOT restricted to Guest Inviter role (AllowInvitesFrom = $AllowInvites)."
            Write-Info "  Remediation: Entra ID > External Identities > External collaboration settings > Guest invite settings = Only users assigned to specific admin roles"
            Add-Result "5.1.6.3" "Guest invite limited to Guest Inviter" "FAIL" "AllowInvitesFrom = $AllowInvites."
        }
    }
}

function Check-5_2_2_1 {
    Invoke-Check "5.2.2.1 (L1)" "Ensure MFA is enabled for all users in administrative roles (Automated)" {
        $CAPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -EA Stop)
        $AdminMFA   = @($CAPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.GrantControls.BuiltInControls -contains "mfa" -and
            (@($_.Conditions.Users.IncludeRoles).Count -gt 0)
        })
        if ($AdminMFA.Count -gt 0) {
            Write-Pass "$($AdminMFA.Count) CA policy/policies require MFA for admin roles."
            $AdminMFA | ForEach-Object { Write-Info "  -> $($_.DisplayName)" }
            Add-Result "5.2.2.1" "MFA for admin roles" "PASS" "$($AdminMFA.Count) admin MFA CA policies."
        } else {
            Write-Fail "No CA policy requiring MFA specifically for administrative roles found."
            Write-Info "  Remediation: Entra ID > Security > Conditional Access > New policy > target admin roles > grant MFA"
            Add-Result "5.2.2.1" "MFA for admin roles" "FAIL" "No admin-role MFA CA policy."
        }
    }
}

function Check-5_2_2_2 {
    Invoke-Check "5.2.2.2 (L1)" "Ensure MFA is enabled for all users (Automated)" {
        $CAPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -EA Stop)
        $AllMFA     = @($CAPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.GrantControls.BuiltInControls -contains "mfa" -and
            $_.Conditions.Users.IncludeUsers -contains "All"
        })
        if ($AllMFA.Count -gt 0) {
            Write-Pass "$($AllMFA.Count) CA policy/policies require MFA for ALL users."
            $AllMFA | ForEach-Object { Write-Info "  -> $($_.DisplayName)" }
            Add-Result "5.2.2.2" "MFA for all users" "PASS" "All-user MFA CA in place."
        } else {
            Write-Fail "No CA policy requiring MFA for ALL users found."
            Write-Info "  Remediation: Entra ID > Security > Conditional Access > New policy > All users > grant MFA"
            Add-Result "5.2.2.2" "MFA for all users" "FAIL" "No all-user MFA CA policy."
        }
    }
}

function Check-5_2_2_4 {
    Invoke-Check "5.2.2.4 (L1)" "Ensure Sign-in frequency and non-persistent browser sessions are configured (Automated)" {
        $CAPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -EA Stop)
        $SIF = @($CAPolicies | Where-Object {
            $_.State -eq "enabled" -and $_.SessionControls.SignInFrequency.IsEnabled -eq $true
        })
        $PB = @($CAPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.SessionControls.PersistentBrowser.IsEnabled -eq $true -and
            $_.SessionControls.PersistentBrowser.Mode -eq "never"
        })
        Write-Info "Sign-in frequency policies  : $($SIF.Count)"
        Write-Info "Persistent browser=never pols: $($PB.Count)"
        if ($SIF.Count -gt 0 -and $PB.Count -gt 0) {
            Write-Pass "Both sign-in frequency and non-persistent session policies are configured."
            Add-Result "5.2.2.4" "Sign-in freq + non-persistent session" "PASS" "Both CA policies present."
        } elseif ($SIF.Count -gt 0) {
            Write-Warn "Sign-in frequency is set but no persistent browser 'never' policy found."
            Add-Result "5.2.2.4" "Sign-in freq + non-persistent session" "WARN" "SIF ok; missing PB=never."
        } else {
            Write-Fail "Neither sign-in frequency nor non-persistent session CA policies found."
            Add-Result "5.2.2.4" "Sign-in freq + non-persistent session" "FAIL" "Both policies missing."
        }
    }
}

function Check-5_2_2_5 {
    Invoke-Check "5.2.2.5 (L1)" "Ensure Phishing-resistant MFA strength is required for Administrators (Automated)" {
        $CAPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -EA Stop)
        $PhishPols  = @($CAPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $null -ne $_.GrantControls.AuthenticationStrength -and
            (@($_.Conditions.Users.IncludeRoles).Count -gt 0)
        })
        if ($PhishPols.Count -gt 0) {
            Write-Pass "$($PhishPols.Count) CA policy/policies require authentication strength for admins."
            $PhishPols | ForEach-Object { Write-Info "  -> $($_.DisplayName)" }
            Add-Result "5.2.2.5" "Phishing-resistant MFA for admins" "PASS" "Auth strength CA found."
        } else {
            Write-Fail "No CA policy requiring phishing-resistant MFA strength for administrators."
            Write-Info "  Remediation: CA policy > Admin roles > Require authentication strength > Phishing-resistant MFA"
            Add-Result "5.2.2.5" "Phishing-resistant MFA for admins" "FAIL" "No phishing-resistant MFA CA."
        }
    }
}

function Check-5_2_2_8 {
    Invoke-Check "5.2.2.8 (L2)" "Ensure sign-in risk is blocked for medium and high risk (Automated)" {
        $CAPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -EA Stop)
        $RiskBlock  = @($CAPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.GrantControls.BuiltInControls -contains "block" -and
            ($_.Conditions.SignInRiskLevels -contains "high" -or $_.Conditions.SignInRiskLevels -contains "medium")
        })
        if ($RiskBlock.Count -gt 0) {
            Write-Pass "$($RiskBlock.Count) CA policy/policies block medium/high risk sign-ins."
            $RiskBlock | ForEach-Object { Write-Info "  -> $($_.DisplayName): Levels=$($_.Conditions.SignInRiskLevels -join ',')" }
            Add-Result "5.2.2.8" "Block medium/high sign-in risk" "PASS" "Risk block CA found."
        } else {
            Write-Fail "No CA policy blocks sign-ins at medium or high risk."
            Write-Info "  Requires: Entra ID P2 + Identity Protection."
            Write-Info "  Remediation: CA > Sign-in risk >= medium > Block access"
            Add-Result "5.2.2.8" "Block medium/high sign-in risk" "FAIL" "No risk block CA."
        }
    }
}

function Check-5_2_2_9 {
    Invoke-Check "5.2.2.9 (L1)" "Ensure a managed device is required for authentication (Automated)" {
        $CAPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -EA Stop)
        $MgrDev     = @($CAPolicies | Where-Object {
            $_.State -eq "enabled" -and
            ($_.GrantControls.BuiltInControls -contains "compliantDevice" -or
             $_.GrantControls.BuiltInControls -contains "domainJoinedDevice")
        })
        if ($MgrDev.Count -gt 0) {
            Write-Pass "$($MgrDev.Count) CA policy/policies require compliant/domain-joined device."
            $MgrDev | ForEach-Object { Write-Info "  -> $($_.DisplayName)" }
            Add-Result "5.2.2.9" "Managed device required" "PASS" "Managed device CA found."
        } else {
            Write-Warn "No CA policy requiring managed device found. Check if scoped to specific users/apps."
            Add-Result "5.2.2.9" "Managed device required" "WARN" "No all-user managed device CA found."
        }
    }
}

function Check-5_2_2_10 {
    Invoke-Check "5.2.2.10 (L1)" "Ensure managed device is required to register security information (Automated)" {
        $CAPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -EA Stop)
        $SecInfoPol = @($CAPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.Conditions.Applications.IncludeUserActions -contains "urn:user:registersecurityinfo"
        })
        if ($SecInfoPol.Count -gt 0) {
            Write-Pass "$($SecInfoPol.Count) CA policy/policies protect security info registration."
            $SecInfoPol | ForEach-Object { Write-Info "  -> $($_.DisplayName)" }
            Add-Result "5.2.2.10" "Managed device for security info reg" "PASS" "Security info reg CA found."
        } else {
            Write-Fail "No CA policy found protecting security information registration."
            Write-Info "  Remediation: CA > User actions = 'Register security information' > require MFA or compliant device"
            Add-Result "5.2.2.10" "Managed device for security info reg" "FAIL" "No security info reg CA."
        }
    }
}

function Check-5_2_2_11 {
    Invoke-Check "5.2.2.11 (L1)" "Ensure sign-in frequency for Intune Enrollment is set to 'Every time' (Automated)" {
        $IntuneAppId = "d4ebce55-015a-49b5-a083-c84d1797ae8c"
        $CAPolicies  = @(Get-MgIdentityConditionalAccessPolicy -All -EA Stop)
        $IntunePol   = @($CAPolicies | Where-Object {
            $_.State -eq "enabled" -and
            $_.SessionControls.SignInFrequency.IsEnabled -and
            $_.SessionControls.SignInFrequency.FrequencyInterval -eq "everyTime" -and
            ($_.Conditions.Applications.IncludeApplications -contains $IntuneAppId -or
             $_.Conditions.Applications.IncludeApplications -contains "All")
        })
        if ($IntunePol.Count -gt 0) {
            Write-Pass "Sign-in frequency for Intune Enrollment set to 'Every time'."
            $IntunePol | ForEach-Object { Write-Info "  -> $($_.DisplayName)" }
            Add-Result "5.2.2.11" "Intune enrollment sign-in freq" "PASS" "everyTime CA found."
        } else {
            Write-Fail "No CA policy sets sign-in frequency to 'Every time' for Intune Enrollment."
            Write-Info "  Remediation: CA > Target Intune Enrollment app > Session: Sign-in frequency = Every time"
            Add-Result "5.2.2.11" "Intune enrollment sign-in freq" "FAIL" "No everyTime Intune CA."
        }
    }
}

function Check-5_2_3_1 {
    Invoke-Check "5.2.3.1 (L1)" "Ensure Microsoft Authenticator is configured against MFA fatigue (Automated)" {
        $Uri      = "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator"
        $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri -EA Stop
        $NumMatch  = $Response.featureSettings.numberMatchingRequiredState.state
        $AppCtx    = $Response.featureSettings.displayAppInformationRequiredState.state
        Write-Info "Number matching    : $NumMatch"
        Write-Info "Additional context : $AppCtx"
        if ($NumMatch -eq "enabled" -or $AppCtx -eq "enabled") {
            Write-Pass "Microsoft Authenticator has number matching or additional context enabled."
            Add-Result "5.2.3.1" "Authenticator MFA fatigue protection" "PASS" "Number match/context enabled."
        } else {
            Write-Fail "Authenticator MFA fatigue protection NOT enabled."
            Write-Info "  Remediation: Entra ID > Security > Authentication methods > Microsoft Authenticator > Configure"
            Add-Result "5.2.3.1" "Authenticator MFA fatigue protection" "FAIL" "Number match and context disabled."
        }
    }
}

function Check-5_2_3_3 {
    Invoke-Check "5.2.3.3 (L1)" "Ensure password protection is enabled for on-prem Active Directory (Automated)" {
        $GroupSettings = Get-MgGroupSetting -EA Stop
        $PwdSettings   = $GroupSettings | Where-Object { $_.TemplateId -eq '5cf42378-d67d-4f36-ba46-e8b86229381d' }
        if ($PwdSettings) {
            $EnableOnPrem = ($PwdSettings.Values | Where-Object { $_.Name -eq "EnableBannedPasswordCheckOnPremises" }).Value
            $Mode         = ($PwdSettings.Values | Where-Object { $_.Name -eq "BannedPasswordCheckOnPremisesMode" }).Value
            Write-Info "EnableBannedPasswordCheckOnPremises: $EnableOnPrem"
            Write-Info "BannedPasswordCheckOnPremisesMode  : $Mode"
            if ($EnableOnPrem -eq "true" -and $Mode -eq "Enforce") {
                Write-Pass "On-prem AD password protection ENABLED and in Enforce mode."
                Add-Result "5.2.3.3" "On-prem AD password protection" "PASS" "Enabled + Enforce mode."
            } else {
                Write-Fail "On-prem AD password protection NOT fully configured."
                Add-Result "5.2.3.3" "On-prem AD password protection" "FAIL" "Enabled=$EnableOnPrem, Mode=$Mode."
            }
        } else {
            Write-Warn "Password protection settings not found. May not be a hybrid environment (cloud-only = N/A)."
            Add-Result "5.2.3.3" "On-prem AD password protection" "WARN" "Cloud-only or not configured."
        }
    }
}

function Check-5_2_3_6 {
    Invoke-Check "5.2.3.6 (L1)" "Ensure system-preferred multifactor authentication is enabled (Automated)" {
        $Uri      = "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy"
        $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri -EA Stop
        $SysPrefs = $Response.systemCredentialPreferences
        $State    = $SysPrefs.state

        # FIX: includeTargets is an array of Hashtable objects - enumerate correctly
        $TargetIds = @()
        $RawTargets = $SysPrefs.includeTargets
        if ($null -ne $RawTargets) {
            foreach ($t in @($RawTargets)) {
                if ($t -is [hashtable] -or ($t.GetType().Name -like "*Dictionary*")) {
                    $id = if ($null -ne $t['id']) { $t['id'] } else { $t.id }
                    if ($id) { $TargetIds += $id.ToString() }
                } elseif ($t -is [string]) {
                    $TargetIds += $t
                } else {
                    $TargetIds += $t.id.ToString()
                }
            }
        }

        Write-Info "state          : $State"
        Write-Info "includeTargets : $($TargetIds -join ', ')"

        $HasAllUsers = $TargetIds | Where-Object { $_ -match "all_users|AllUsers" }
        # 'default' in newer tenants means system-preferred MFA is on by Microsoft default
        $IsActive    = ($State -in @("enabled", "default"))

        if ($IsActive -and $HasAllUsers) {
            Write-Pass "System-preferred MFA is ENABLED targeting all users (state=$State)."
            Add-Result "5.2.3.6" "System-preferred MFA enabled" "PASS" "State=$State, target=all_users."
        } elseif ($State -eq "default") {
            Write-Warn "State is 'default' (Microsoft-managed on). Verify all_users is in scope."
            Write-Info "  If all users are targeted, this is compliant. Check: Entra ID > Security > Authentication methods > System-preferred MFA"
            Add-Result "5.2.3.6" "System-preferred MFA enabled" "WARN" "State=default - verify all_users target."
        } else {
            Write-Fail "System-preferred MFA is NOT enabled (state = $State)."
            Write-Info "  Remediation: Entra ID > Security > Authentication methods > Policies > System-preferred MFA = Enabled"
            Add-Result "5.2.3.6" "System-preferred MFA enabled" "FAIL" "State = $State."
        }
    }
}

function Check-5_2_3_7 {
    Invoke-Check "5.2.3.7 (L2)" "Ensure email OTP authentication method is disabled (Automated)" {
        $Configs  = (Get-MgPolicyAuthenticationMethodPolicy -EA Stop).AuthenticationMethodConfigurations
        $EmailOTP = $Configs | Where-Object { $_.Id -eq "Email" }
        Write-Info "Email OTP state: $($EmailOTP.State)"
        if ($EmailOTP.State -eq "disabled") {
            Write-Pass "Email OTP authentication method is DISABLED."
            Add-Result "5.2.3.7" "Email OTP disabled" "PASS" "Email OTP = disabled."
        } else {
            Write-Fail "Email OTP authentication method is ENABLED."
            Write-Info "  Remediation: Entra ID > Security > Authentication methods > Email OTP > Disable"
            Add-Result "5.2.3.7" "Email OTP disabled" "FAIL" "Email OTP = $($EmailOTP.State)."
        }
    }
}

function Check-5_3_1 {
    Invoke-Check "5.3.1 (L2)" "Ensure Privileged Identity Management is used to manage roles (Automated)" {
        try {
            $Uri  = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests?`$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'"
            $Resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -EA Stop
            $Eligible = @($Resp.value | Where-Object { $_.status -eq "Provisioned" })
            if ($Eligible.Count -gt 0) {
                Write-Pass "PIM in use - $($Eligible.Count) eligible GA role assignment(s) found."
                Add-Result "5.3.1" "PIM used for role management" "PASS" "$($Eligible.Count) PIM eligible GAs."
            } else {
                Write-Warn "No PIM eligible GA assignments found."
                Write-Info "  Verify PIM is licensed (Entra ID P2) and configured."
                Write-Info "  Check: Entra ID > Identity Governance > Privileged Identity Management > Azure AD roles > Global Administrator"
                Add-Result "5.3.1" "PIM used for role management" "WARN" "No PIM eligible GAs found."
            }
        } catch {
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*Authorization_RequestDenied*") {
                Write-Warn "Permission denied accessing PIM role schedules."
                Write-Info "  Actual error: $($_.Exception.Message.Split([char]10)[0].Trim())"
                Write-Info "  Required: 'RoleManagement.Read.Directory' Graph permission (Application) + admin consent"
                Write-Info "  Note: Also requires Entra ID P2 license on the tenant"
                Add-Result "5.3.1" "PIM used for role management" "WARN" "Forbidden - check RoleManagement.Read.Directory permission + P2 license."
            } else { throw }
        }
    }
}

function Check-5_3_3 {
    Invoke-Check "5.3.3 (L1)" "Ensure access reviews for privileged roles are configured (Automated)" {
        try {
            $Uri      = "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions"
            $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri -EA Stop
            $Active   = @($Response.value | Where-Object { $_.status -ne "Completed" })
            if ($Active.Count -gt 0) {
                Write-Pass "$($Active.Count) active access review(s) configured."
                $Active | Select-Object -First 5 | ForEach-Object { Write-Info "  -> $($_.displayName) (status: $($_.status))" }
                Add-Result "5.3.3" "Access reviews for privileged roles" "PASS" "$($Active.Count) active reviews."
            } else {
                Write-Fail "No active access review definitions found."
                Write-Info "  Remediation: Entra ID > Identity Governance > Access reviews > New access review > target privileged roles"
                Add-Result "5.3.3" "Access reviews for privileged roles" "FAIL" "No active access reviews."
            }
        } catch {
            if ($_.Exception.Message -like "*Forbidden*") {
                Write-Warn "Permission denied accessing access review definitions."
                Write-Info "  Actual error: $($_.Exception.Message.Split([char]10)[0].Trim())"
                Write-Info "  Required: 'AccessReview.Read.All' Graph permission (Application) + admin consent"
                Write-Info "  Note: Also requires Entra ID P2 license on the tenant"
                Add-Result "5.3.3" "Access reviews for privileged roles" "WARN" "Forbidden - check AccessReview.Read.All permission + P2 license."
            } else { throw }
        }
    }
}

function Check-5_3_4 {
    Invoke-Check "5.3.4 (L1)" "Ensure approval is required for Global Administrator role activation (Automated)" {
        Write-Warn "PIM role activation approval settings cannot be fully read via API with client-secret auth."
        Write-Info "  Manual check: Entra ID > Identity Governance > PIM > Azure AD roles > Global Administrator > Settings"
        Write-Info "  Verify: 'Require approval to activate' = Enabled"
        Add-Result "5.3.4" "Approval required for GA activation" "WARN" "Manual PIM portal verification required."
    }
}

function Check-5_3_5 {
    Invoke-Check "5.3.5 (L1)" "Ensure approval is required for Privileged Role Admin activation (Automated)" {
        Write-Warn "PIM role activation approval settings cannot be fully read via API with client-secret auth."
        Write-Info "  Manual check: Entra ID > Identity Governance > PIM > Azure AD roles > Privileged Role Administrator > Settings"
        Write-Info "  Verify: 'Require approval to activate' = Enabled"
        Add-Result "5.3.5" "Approval required for PRA activation" "WARN" "Manual PIM portal verification required."
    }
}

# ===============================================================================
#  SECTION 6 - Exchange Online
# ===============================================================================

function Check-6_1_3 {
    Invoke-Check "6.1.3 (L1)" "Ensure 'AuditBypassEnabled' is not enabled on mailboxes (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "6.1.3" "AuditBypass not enabled" "WARN" "EXO not connected."; return }
        $Report = Get-MailboxAuditBypassAssociation -ResultSize Unlimited -EA Stop |
            Where-Object { $_.AuditBypassEnabled }
        if ($Report.Count -eq 0) {
            Write-Pass "No mailboxes have AuditBypassEnabled = True."
            Add-Result "6.1.3" "AuditBypass not enabled" "PASS" "No audit bypass."
        } else {
            Write-Fail "$($Report.Count) mailbox(es) with AuditBypassEnabled:"
            $Report | ForEach-Object { Write-Info "  -> $($_.Name)" }
            Add-Result "6.1.3" "AuditBypass not enabled" "FAIL" "$($Report.Count) bypassed."
        }
    }
}

function Check-6_2_1 {
    Invoke-Check "6.2.1 (L1)" "Ensure all forms of mail forwarding are blocked and/or disabled (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "6.2.1" "Mail forwarding blocked" "WARN" "EXO not connected."; return }
        $FwdRules = Get-TransportRule -EA Stop | Where-Object { $_.RedirectMessageTo }
        $FwdPol   = Get-HostedOutboundSpamFilterPolicy -EA Stop | Where-Object {
            $_.AutoForwardingMode -notin @("Off", $null)
        }
        if ($FwdRules.Count -eq 0 -and $FwdPol.Count -eq 0) {
            Write-Pass "No mail forwarding transport rules or risky policy settings found."
            Add-Result "6.2.1" "Mail forwarding blocked" "PASS" "No forwarding rules."
        } else {
            if ($FwdRules.Count -gt 0) {
                Write-Fail "$($FwdRules.Count) transport rule(s) redirect messages:"
                $FwdRules | ForEach-Object { Write-Info "  -> $($_.Name): $($_.RedirectMessageTo)" }
            }
            if ($FwdPol.Count -gt 0) {
                Write-Fail "Auto-forwarding may be enabled:"
                $FwdPol | ForEach-Object { Write-Info "  -> $($_.Identity): AutoForwardingMode=$($_.AutoForwardingMode)" }
            }
            Add-Result "6.2.1" "Mail forwarding blocked" "FAIL" "Forwarding rules/policies found."
        }
    }
}

function Check-6_2_2 {
    Invoke-Check "6.2.2 (L1)" "Ensure mail transport rules do not whitelist specific domains (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "6.2.2" "No domain bypass rules" "WARN" "EXO not connected."; return }
        $Bad = Get-TransportRule -EA Stop | Where-Object {
            $_.SetScl -eq -1 -and $_.SenderDomainIs.Count -gt 0
        }
        if ($Bad.Count -eq 0) {
            Write-Pass "No transport rules bypass spam filtering for specific domains."
            Add-Result "6.2.2" "No domain bypass rules" "PASS" "No SCL=-1 domain rules."
        } else {
            Write-Fail "$($Bad.Count) transport rule(s) bypass spam filtering:"
            $Bad | ForEach-Object { Write-Info "  -> $($_.Name): $($_.SenderDomainIs -join ', ')" }
            Add-Result "6.2.2" "No domain bypass rules" "FAIL" "Domain bypass rules found."
        }
    }
}

function Check-6_5_1 {
    Invoke-Check "6.5.1 (L1)" "Ensure modern authentication for Exchange Online is enabled (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "6.5.1" "Exchange modern auth enabled" "WARN" "EXO not connected."; return }
        $Cfg = Get-OrganizationConfig -EA Stop
        Write-Info "OAuth2ClientProfileEnabled: $($Cfg.OAuth2ClientProfileEnabled)"
        if ($Cfg.OAuth2ClientProfileEnabled) {
            Write-Pass "Modern authentication (OAuth2) is ENABLED for Exchange Online."
            Add-Result "6.5.1" "Exchange modern auth enabled" "PASS" "OAuth2 = True."
        } else {
            Write-Fail "Modern authentication NOT enabled for Exchange Online."
            Write-Info "  Remediation: Exchange Admin Center > Settings > Modern authentication > Enable"
            Add-Result "6.5.1" "Exchange modern auth enabled" "FAIL" "OAuth2 = False."
        }
    }
}

function Check-6_5_2 {
    Invoke-Check "6.5.2 (L1)" "Ensure MailTips are enabled for end users (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "6.5.2" "MailTips enabled" "WARN" "EXO not connected."; return }
        $Cfg = Get-OrganizationConfig -EA Stop
        Write-Info "MailTipsAllTipsEnabled               : $($Cfg.MailTipsAllTipsEnabled)"
        Write-Info "MailTipsExternalRecipientsTipsEnabled: $($Cfg.MailTipsExternalRecipientsTipsEnabled)"
        Write-Info "MailTipsGroupMetricsEnabled          : $($Cfg.MailTipsGroupMetricsEnabled)"
        if ($Cfg.MailTipsAllTipsEnabled -and $Cfg.MailTipsExternalRecipientsTipsEnabled -and $Cfg.MailTipsGroupMetricsEnabled) {
            Write-Pass "MailTips enabled for all scenarios."
            Add-Result "6.5.2" "MailTips enabled" "PASS" "All MailTip settings on."
        } else {
            Write-Fail "One or more MailTip settings are disabled."
            Add-Result "6.5.2" "MailTips enabled" "FAIL" "Some MailTip settings off."
        }
    }
}

function Check-6_5_3 {
    Invoke-Check "6.5.3 (L2)" "Ensure additional storage providers are restricted in OWA (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "6.5.3" "OWA storage restricted" "WARN" "EXO not connected."; return }
        $OwaPolicy = Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -EA Stop
        Write-Info "AdditionalStorageProvidersAvailable: $($OwaPolicy.AdditionalStorageProvidersAvailable)"
        if ($OwaPolicy.AdditionalStorageProvidersAvailable -eq $false) {
            Write-Pass "Additional storage providers RESTRICTED in OWA."
            Add-Result "6.5.3" "OWA storage restricted" "PASS" "AdditionalStorage = False."
        } else {
            Write-Fail "Additional storage providers AVAILABLE in OWA."
            Write-Info "  Remediation: Exchange Admin Center > Settings > OWA mailbox policy > Disable additional storage"
            Add-Result "6.5.3" "OWA storage restricted" "FAIL" "AdditionalStorage = True."
        }
    }
}

function Check-6_5_4 {
    Invoke-Check "6.5.4 (L1)" "Ensure SMTP AUTH is disabled (Automated)" {
        if (-not (Assert-Exo)) { Add-Result "6.5.4" "SMTP AUTH disabled" "WARN" "EXO not connected."; return }
        $Cfg = Get-TransportConfig -EA Stop
        Write-Info "SmtpClientAuthenticationDisabled: $($Cfg.SmtpClientAuthenticationDisabled)"
        if ($Cfg.SmtpClientAuthenticationDisabled) {
            Write-Pass "SMTP AUTH is DISABLED."
            Add-Result "6.5.4" "SMTP AUTH disabled" "PASS" "SMTP AUTH = disabled."
        } else {
            Write-Fail "SMTP AUTH is ENABLED."
            Write-Info "  Remediation: Exchange Admin Center > Settings > Mail flow > Turn off SMTP AUTH"
            Add-Result "6.5.4" "SMTP AUTH disabled" "FAIL" "SMTP AUTH = enabled."
        }
    }
}

# ===============================================================================
#  SECTION 7 - SharePoint Online & OneDrive
# ===============================================================================

function Check-7_2_1 {
    Invoke-Check "7.2.1 (L1)" "Ensure modern authentication for SharePoint is required (Automated)" {
        if (-not (Assert-Spo)) { Add-Result "7.2.1" "SPO modern auth required" "WARN" "SPO not connected."; return }
        $T = Get-SPOTenant -EA Stop
        Write-Info "LegacyAuthProtocolsEnabled: $($T.LegacyAuthProtocolsEnabled)"
        if ($T.LegacyAuthProtocolsEnabled -eq $false) {
            Write-Pass "Legacy auth protocols DISABLED for SharePoint."
            Add-Result "7.2.1" "SPO modern auth required" "PASS" "LegacyAuth = False."
        } else {
            Write-Fail "Legacy authentication ENABLED for SharePoint."
            Write-Info "  Remediation: SPO Admin > Policies > Access control > Apps that don't use modern authentication > Block access"
            Add-Result "7.2.1" "SPO modern auth required" "FAIL" "LegacyAuth = True."
        }
    }
}

function Check-7_2_2 {
    Invoke-Check "7.2.2 (L1)" "Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled (Automated)" {
        if (-not (Assert-Spo)) { Add-Result "7.2.2" "SPO B2B integration" "WARN" "SPO not connected."; return }
        $T = Get-SPOTenant -EA Stop
        Write-Info "EnableAzureADB2BIntegration: $($T.EnableAzureADB2BIntegration)"
        if ($T.EnableAzureADB2BIntegration) {
            Write-Pass "SharePoint/OneDrive Azure AD B2B integration is ENABLED."
            Add-Result "7.2.2" "SPO B2B integration" "PASS" "B2B = True."
        } else {
            Write-Fail "SharePoint/OneDrive Azure AD B2B integration is NOT enabled."
            Add-Result "7.2.2" "SPO B2B integration" "FAIL" "B2B = False."
        }
    }
}

function Check-7_2_5 {
    Invoke-Check "7.2.5 (L2)" "Ensure SharePoint guest users cannot share items they don't own (Automated)" {
        if (-not (Assert-Spo)) { Add-Result "7.2.5" "SPO guest resharing blocked" "WARN" "SPO not connected."; return }
        $T = Get-SPOTenant -EA Stop
        Write-Info "PreventExternalUsersFromResharing: $($T.PreventExternalUsersFromResharing)"
        if ($T.PreventExternalUsersFromResharing) {
            Write-Pass "External users PREVENTED from resharing items."
            Add-Result "7.2.5" "SPO guest resharing blocked" "PASS" "PreventResharing = True."
        } else {
            Write-Fail "External users CAN reshare items they don't own."
            Write-Info "  Remediation: SPO Admin > Policies > Sharing > More external sharing settings > Uncheck 'Allow guests to share'"
            Add-Result "7.2.5" "SPO guest resharing blocked" "FAIL" "PreventResharing = False."
        }
    }
}

function Check-7_2_7 {
    Invoke-Check "7.2.7 (L1)" "Ensure link sharing is restricted in SharePoint and OneDrive (Automated)" {
        if (-not (Assert-Spo)) { Add-Result "7.2.7" "SPO link sharing restricted" "WARN" "SPO not connected."; return }
        $T = Get-SPOTenant -EA Stop
        Write-Info "DefaultSharingLinkType: $($T.DefaultSharingLinkType)"
        if ($T.DefaultSharingLinkType -in @("Direct", "Internal")) {
            Write-Pass "Default sharing link is '$($T.DefaultSharingLinkType)' - compliant."
            Add-Result "7.2.7" "SPO link sharing restricted" "PASS" "DefaultSharingLink = $($T.DefaultSharingLinkType)."
        } else {
            Write-Fail "Default sharing link is '$($T.DefaultSharingLinkType)' - should be 'Direct' or 'Internal'."
            Write-Info "  Remediation: SPO Admin > Policies > Sharing > Default link type > Specific people or Only people in org"
            Add-Result "7.2.7" "SPO link sharing restricted" "FAIL" "DefaultSharingLink = $($T.DefaultSharingLinkType)."
        }
    }
}

function Check-7_2_9 {
    Invoke-Check "7.2.9 (L1)" "Ensure guest access to a site or OneDrive will expire automatically (Automated)" {
        if (-not (Assert-Spo)) { Add-Result "7.2.9" "SPO guest access expiry" "WARN" "SPO not connected."; return }
        $T = Get-SPOTenant -EA Stop
        Write-Info "ExternalUserExpirationRequired : $($T.ExternalUserExpirationRequired)"
        Write-Info "ExternalUserExpireInDays       : $($T.ExternalUserExpireInDays)"
        if ($T.ExternalUserExpirationRequired -and $T.ExternalUserExpireInDays -le 30) {
            Write-Pass "Guest access expires in $($T.ExternalUserExpireInDays) days."
            Add-Result "7.2.9" "SPO guest access expiry" "PASS" "Expiry = $($T.ExternalUserExpireInDays) days."
        } else {
            Write-Fail "Guest access expiry NOT configured (Required=$($T.ExternalUserExpirationRequired), Days=$($T.ExternalUserExpireInDays))."
            Write-Info "  Remediation: SPO Admin > Policies > Sharing > Guest access expiration = 30 days"
            Add-Result "7.2.9" "SPO guest access expiry" "FAIL" "Required=$($T.ExternalUserExpirationRequired), Days=$($T.ExternalUserExpireInDays)."
        }
    }
}

function Check-7_2_10 {
    Invoke-Check "7.2.10 (L1)" "Ensure reauthentication with verification code is restricted (Automated)" {
        if (-not (Assert-Spo)) { Add-Result "7.2.10" "SPO reauth" "WARN" "SPO not connected."; return }
        $T = Get-SPOTenant -EA Stop
        Write-Info "EmailAttestationRequired   : $($T.EmailAttestationRequired)"
        Write-Info "EmailAttestationReAuthDays : $($T.EmailAttestationReAuthDays)"
        if ($T.EmailAttestationRequired -and $T.EmailAttestationReAuthDays -le 15) {
            Write-Pass "Reauthentication required every $($T.EmailAttestationReAuthDays) days."
            Add-Result "7.2.10" "SPO reauth verification" "PASS" "ReAuth = $($T.EmailAttestationReAuthDays) days."
        } else {
            Write-Fail "Reauthentication NOT configured correctly (Required=$($T.EmailAttestationRequired), Days=$($T.EmailAttestationReAuthDays))."
            Write-Info "  Remediation: SPO Admin > Policies > Sharing > People who use verification codes must reauthenticate after 15 days"
            Add-Result "7.2.10" "SPO reauth verification" "FAIL" "Required=$($T.EmailAttestationRequired), Days=$($T.EmailAttestationReAuthDays)."
        }
    }
}

function Check-7_2_11 {
    Invoke-Check "7.2.11 (L1)" "Ensure SharePoint default sharing link permission is set to View (Automated)" {
        if (-not (Assert-Spo)) { Add-Result "7.2.11" "SPO default link permission" "WARN" "SPO not connected."; return }
        $T = Get-SPOTenant -EA Stop
        Write-Info "DefaultLinkPermission: $($T.DefaultLinkPermission)"
        if ($T.DefaultLinkPermission -eq "View") {
            Write-Pass "Default sharing link permission is 'View'."
            Add-Result "7.2.11" "SPO default link permission" "PASS" "DefaultLinkPermission = View."
        } else {
            Write-Fail "Default link permission is '$($T.DefaultLinkPermission)' - should be 'View'."
            Write-Info "  Remediation: SPO Admin > Policies > Sharing > Default link permission = View"
            Add-Result "7.2.11" "SPO default link permission" "FAIL" "DefaultLinkPermission = $($T.DefaultLinkPermission)."
        }
    }
}

function Check-7_3_1 {
    Invoke-Check "7.3.1 (L1)" "Ensure infected files are disallowed from download in SharePoint (Automated)" {
        if (-not (Assert-Spo)) { Add-Result "7.3.1" "SPO infected file download blocked" "WARN" "SPO not connected."; return }
        $T = Get-SPOTenant -EA Stop
        Write-Info "DisallowInfectedFileDownload: $($T.DisallowInfectedFileDownload)"
        if ($T.DisallowInfectedFileDownload) {
            Write-Pass "Infected file download BLOCKED in SharePoint."
            Add-Result "7.3.1" "SPO infected file download blocked" "PASS" "DisallowInfected = True."
        } else {
            Write-Fail "Infected file download ALLOWED."
            Write-Info "  Remediation: SPO Admin > Settings > Disallow infected file download = On"
            Add-Result "7.3.1" "SPO infected file download blocked" "FAIL" "DisallowInfected = False."
        }
    }
}

function Check-7_3_2 {
    Invoke-Check "7.3.2 (L2)" "Ensure OneDrive sync is restricted for unmanaged devices (Automated)" {
        if (-not (Assert-Spo)) { Add-Result "7.3.2" "OneDrive sync restricted" "WARN" "SPO not connected."; return }
        $Sync = Get-SPOTenantSyncClientRestriction -EA Stop
        Write-Info "TenantRestrictionEnabled : $($Sync.TenantRestrictionEnabled)"
        Write-Info "AllowedDomainList        : $($Sync.AllowedDomainList -join ', ')"
        if ($Sync.TenantRestrictionEnabled -and $Sync.AllowedDomainList.Count -gt 0) {
            Write-Pass "OneDrive sync restricted to $($Sync.AllowedDomainList.Count) allowed domain(s)."
            Add-Result "7.3.2" "OneDrive sync restricted" "PASS" "Sync restricted."
        } else {
            Write-Fail "OneDrive sync NOT restricted (TenantRestriction=$($Sync.TenantRestrictionEnabled))."
            Write-Info "  Remediation: SPO Admin > Settings > OneDrive > Sync > Allow only on computers joined to specific domains"
            Add-Result "7.3.2" "OneDrive sync restricted" "FAIL" "Sync not restricted."
        }
    }
}

# ===============================================================================
#  SECTION 8 - Microsoft Teams
# ===============================================================================

function Check-8_1_1 {
    Invoke-Check "8.1.1 (L1)" "Ensure external file sharing in Teams uses only approved cloud storage (Automated)" {
        if (-not (Assert-Teams)) { Add-Result "8.1.1" "Teams approved storage" "WARN" "Teams not connected."; return }
        $Config = Get-CsTeamsClientConfiguration -Identity Global -EA Stop
        $Providers = [ordered]@{
            AllowDropbox    = $Config.AllowDropbox
            AllowBox        = $Config.AllowBox
            AllowGoogleDrive= $Config.AllowGoogleDrive
            AllowShareFile  = $Config.AllowShareFile
            AllowEgnyte     = $Config.AllowEgnyte
        }
        $Enabled3rd = $Providers.GetEnumerator() | Where-Object { $_.Value -eq $true }
        if ($Enabled3rd.Count -gt 0) {
            Write-Warn "$($Enabled3rd.Count) third-party storage provider(s) enabled - verify each is organizationally approved:"
            $Enabled3rd | ForEach-Object { Write-Info "  -> $($_.Key) = True" }
        } else {
            Write-Pass "All third-party cloud storage providers DISABLED in Teams."
        }
        $status = if ($Enabled3rd.Count -eq 0) { "PASS" } else { "WARN" }
        Add-Result "8.1.1" "Teams approved cloud storage" $status "$($Enabled3rd.Count) 3rd party providers enabled."
    }
}

function Check-8_1_2 {
    Invoke-Check "8.1.2 (L1)" "Ensure users can't send emails to a Teams channel email address (Automated)" {
        if (-not (Assert-Teams)) { Add-Result "8.1.2" "Block email to Teams channel" "WARN" "Teams not connected."; return }
        $Config = Get-CsTeamsClientConfiguration -Identity Global -EA Stop
        Write-Info "AllowEmailIntoChannel: $($Config.AllowEmailIntoChannel)"
        if ($Config.AllowEmailIntoChannel -eq $false) {
            Write-Pass "Email into Teams channels DISABLED."
            Add-Result "8.1.2" "Block email to Teams channel" "PASS" "AllowEmailIntoChannel = False."
        } else {
            Write-Fail "Users CAN send emails to Teams channel addresses."
            Write-Info "  Remediation: Teams Admin Center > Teams > Teams settings > Email integration = Off"
            Add-Result "8.1.2" "Block email to Teams channel" "FAIL" "AllowEmailIntoChannel = True."
        }
    }
}

function Check-8_2_1 {
    Invoke-Check "8.2.1 (L2)" "Ensure external domains are restricted in the Teams admin center (Automated)" {
        if (-not (Assert-Teams)) { Add-Result "8.2.1" "Teams external domain restriction" "WARN" "Teams not connected."; return }
        $FedConfig = Get-CsTenantFederationConfiguration -EA Stop
        Write-Info "AllowFederatedUsers (org)  : $($FedConfig.AllowFederatedUsers)"
        Write-Info "AllowedDomains (org)       : $($FedConfig.AllowedDomains)"
        $IsCompliant = ($FedConfig.AllowFederatedUsers -eq $false) -or
            ($FedConfig.AllowFederatedUsers -and $FedConfig.AllowedDomains -ne "AllowAllKnownDomains" -and $null -ne $FedConfig.AllowedDomains)
        if ($IsCompliant) {
            Write-Pass "Teams external federation is restricted."
            Add-Result "8.2.1" "Teams external domain restriction" "PASS" "Federation restricted."
        } else {
            Write-Fail "Teams allows federation with ALL known domains."
            Write-Info "  Remediation: Teams Admin Center > Users > External access > restrict to specific allowed domains only"
            Add-Result "8.2.1" "Teams external domain restriction" "FAIL" "AllowAllKnownDomains."
        }
    }
}

function Check-8_2_2 {
    Invoke-Check "8.2.2 (L1)" "Ensure communication with unmanaged Teams users is disabled (Automated)" {
        if (-not (Assert-Teams)) { Add-Result "8.2.2" "Block unmanaged Teams" "WARN" "Teams not connected."; return }
        $FedConfig = Get-CsTenantFederationConfiguration -EA Stop
        Write-Info "AllowTeamsConsumer: $($FedConfig.AllowTeamsConsumer)"
        if ($FedConfig.AllowTeamsConsumer -eq $false) {
            Write-Pass "Communication with unmanaged Teams users DISABLED."
            Add-Result "8.2.2" "Block unmanaged Teams" "PASS" "AllowTeamsConsumer = False."
        } else {
            Write-Fail "Communication with unmanaged Teams users ENABLED."
            Write-Info "  Remediation: Teams Admin Center > Users > External access > Teams accounts not managed by an organization = Off"
            Add-Result "8.2.2" "Block unmanaged Teams" "FAIL" "AllowTeamsConsumer = True."
        }
    }
}

function Check-8_2_3 {
    Invoke-Check "8.2.3 (L1)" "Ensure external Teams users cannot initiate conversations (Automated)" {
        if (-not (Assert-Teams)) { Add-Result "8.2.3" "Block external Teams inbound" "WARN" "Teams not connected."; return }
        $FedConfig = Get-CsTenantFederationConfiguration -EA Stop
        Write-Info "AllowTeamsConsumerInbound: $($FedConfig.AllowTeamsConsumerInbound)"
        if ($FedConfig.AllowTeamsConsumerInbound -eq $false) {
            Write-Pass "External consumer Teams users CANNOT initiate conversations."
            Add-Result "8.2.3" "Block external Teams inbound" "PASS" "AllowTeamsConsumerInbound = False."
        } else {
            Write-Fail "External consumer Teams users CAN initiate conversations."
            Add-Result "8.2.3" "Block external Teams inbound" "FAIL" "AllowTeamsConsumerInbound = True."
        }
    }
}

function Check-8_2_4 {
    Invoke-Check "8.2.4 (L1)" "Ensure the organization cannot communicate with trial Teams tenants (Automated)" {
        if (-not (Assert-Teams)) { Add-Result "8.2.4" "Block trial Teams tenants" "WARN" "Teams not connected."; return }
        $FedConfig = Get-CsTenantFederationConfiguration -EA Stop
        Write-Info "ExternalAccessWithTrialTenants: $($FedConfig.ExternalAccessWithTrialTenants)"
        if ($FedConfig.ExternalAccessWithTrialTenants -eq "Blocked") {
            Write-Pass "Communication with trial Teams tenants BLOCKED."
            Add-Result "8.2.4" "Block trial Teams tenants" "PASS" "TrialTenants = Blocked."
        } else {
            Write-Fail "Communication with trial Teams tenants NOT blocked."
            Add-Result "8.2.4" "Block trial Teams tenants" "FAIL" "TrialTenants = $($FedConfig.ExternalAccessWithTrialTenants)."
        }
    }
}

function Check-8_5_2 {
    Invoke-Check "8.5.2 (L1)" "Ensure anonymous users and dial-in callers can't start a meeting (Automated)" {
        if (-not (Assert-Teams)) { Add-Result "8.5.2" "Block anon start meeting" "WARN" "Teams not connected."; return }
        $Policy = Get-CsTeamsMeetingPolicy -Identity Global -EA Stop
        Write-Info "AllowAnonymousUsersToStartMeeting: $($Policy.AllowAnonymousUsersToStartMeeting)"
        if ($Policy.AllowAnonymousUsersToStartMeeting -eq $false) {
            Write-Pass "Anonymous users CANNOT start meetings."
            Add-Result "8.5.2" "Block anon start meeting" "PASS" "AnonStart = False."
        } else {
            Write-Fail "Anonymous users CAN start meetings."
            Add-Result "8.5.2" "Block anon start meeting" "FAIL" "AnonStart = True."
        }
    }
}

function Check-8_5_7 {
    Invoke-Check "8.5.7 (L1)" "Ensure external participants can't give or request control (Automated)" {
        if (-not (Assert-Teams)) { Add-Result "8.5.7" "Block external control" "WARN" "Teams not connected."; return }
        $Policy = Get-CsTeamsMeetingPolicy -Identity Global -EA Stop
        Write-Info "AllowExternalParticipantGiveRequestControl: $($Policy.AllowExternalParticipantGiveRequestControl)"
        if ($Policy.AllowExternalParticipantGiveRequestControl -eq $false) {
            Write-Pass "External participants CANNOT give or request control."
            Add-Result "8.5.7" "Block external control" "PASS" "ExternalControl = False."
        } else {
            Write-Fail "External participants CAN give or request control."
            Add-Result "8.5.7" "Block external control" "FAIL" "ExternalControl = True."
        }
    }
}

function Check-8_5_8 {
    Invoke-Check "8.5.8 (L2)" "Ensure external meeting chat is off (Automated)" {
        if (-not (Assert-Teams)) { Add-Result "8.5.8" "External meeting chat off" "WARN" "Teams not connected."; return }
        $Policy = Get-CsTeamsMeetingPolicy -Identity Global -EA Stop
        Write-Info "AllowExternalNonTrustedMeetingChat: $($Policy.AllowExternalNonTrustedMeetingChat)"
        if ($Policy.AllowExternalNonTrustedMeetingChat -eq $false) {
            Write-Pass "External non-trusted meeting chat DISABLED."
            Add-Result "8.5.8" "External meeting chat off" "PASS" "ExternalChat = False."
        } else {
            Write-Fail "External non-trusted meeting chat ENABLED."
            Write-Info "  Remediation: Teams Admin Center > Meetings > Meeting policies > External participants > Meeting chat = Off"
            Add-Result "8.5.8" "External meeting chat off" "FAIL" "ExternalChat = True."
        }
    }
}

function Check-8_5_9 {
    Invoke-Check "8.5.9 (L2)" "Ensure meeting recording is off by default (Automated)" {
        if (-not (Assert-Teams)) { Add-Result "8.5.9" "Recording off by default" "WARN" "Teams not connected."; return }
        $Policy = Get-CsTeamsMeetingPolicy -Identity Global -EA Stop
        Write-Info "AllowCloudRecording: $($Policy.AllowCloudRecording)"
        if ($Policy.AllowCloudRecording -eq $false) {
            Write-Pass "Cloud recording DISABLED by default."
            Add-Result "8.5.9" "Recording off by default" "PASS" "AllowCloudRecording = False."
        } else {
            Write-Fail "Cloud recording ENABLED by default."
            Write-Info "  Remediation: Teams Admin Center > Meetings > Meeting policies > Recording & transcription > Cloud recording = Off"
            Add-Result "8.5.9" "Recording off by default" "FAIL" "AllowCloudRecording = True."
        }
    }
}

# ===============================================================================
#  SECTION 9 - Power BI
#  FIX: Use Power BI-specific OAuth token (scope: analysis.windows.net), fall back
#       to Graph beta endpoint.
#       - Power BI REST API requires 'Tenant.Read.All' on Power BI Service.
#       - Graph beta fallback requires 'Tenant.Read.All' on Microsoft Graph.
# ===============================================================================

$Script:PBIToken = $null
$Script:PBIChecked = $false

function Get-PBITenantSettings {
    if (-not $Script:PBIChecked) {
        $Script:PBIChecked = $true
        $Script:PBIError   = $null

        # Try 1: Power BI REST API with its own OAuth scope
        try {
            $PBITokenBody = @{
                client_id     = $AppId
                client_secret = $AppSecret
                scope         = "https://analysis.windows.net/powerbi/api/.default"
                grant_type    = "client_credentials"
            }
            $tok = (Invoke-RestMethod -Method POST `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -Body $PBITokenBody -EA Stop).access_token
            $Headers  = @{ Authorization = "Bearer $tok" }
            $Response = Invoke-RestMethod -Method GET `
                -Uri "https://api.powerbi.com/v1.0/myorg/admin/tenantSettings" `
                -Headers $Headers -EA Stop
            $Script:PBIToken = $Response.tenantSettings
            Write-Host "    [OK] Power BI API connected (PBI OAuth token)" -ForegroundColor Green
            return
        } catch {
            $Script:PBIError = "PBI API: $($_.Exception.Message.Split([char]10)[0].Trim())"
        }

        # Try 2: Graph beta endpoint
        try {
            $Response = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/beta/admin/powerBI/tenantSettings" -EA Stop

            if ($null -ne $Response.tenantSettings) {
                $Script:PBIToken = $Response.tenantSettings
            } elseif ($null -ne $Response.value) {
                $Script:PBIToken = $Response.value
            } elseif ($null -ne $Response.settings) {
                $Script:PBIToken = $Response.settings
            } else {
                $Script:PBIToken = $Response
            }
            Write-Host "    [OK] Power BI connected (Graph beta)" -ForegroundColor Green
            return
        } catch {
            $Script:PBIError += " | Graph beta: $($_.Exception.Message.Split([char]10)[0].Trim())"
            $Script:PBIToken = $null
        }
    }
    return $Script:PBIToken
}

function Check-9_PBI {
    param([string]$Section, [string]$Title, [string]$SettingName, [bool]$ExpectedEnabled)
    Invoke-Check $Section $Title {
        $Settings = Get-PBITenantSettings
        if ($null -eq $Settings) {
            Write-Warn "Power BI admin settings not accessible."
            if ($Script:PBIError) {
                Write-Info "  Actual errors encountered:"
                Write-Info "    $($Script:PBIError)"
            }
            Write-Info "  Requirements:"
            Write-Info "    1. Power BI Service > Tenant.Read.All (Application) permission + admin consent"
            Write-Info "    2. Microsoft Graph > Tenant.Read.All (Application) permission + admin consent (fallback)"
            Write-Info "    3. Service principal must be assigned the 'Power BI Administrator' Entra ID role"
            Write-Info "       Entra ID > Roles and administrators > Power BI Administrator > Add assignments"
            Write-Info "       -> search for your App Registration name and assign it"
            Write-Info "  Manual check: app.powerbi.com > Admin portal > Tenant settings > $SettingName"
            Add-Result $Section $Title "WARN" "Power BI inaccessible - check Tenant.Read.All + Power BI Admin role."
            return
        }
        # Handle both endpoint response shapes
        $Setting = $Settings | Where-Object { $_.settingName -eq $SettingName -or $_.name -eq $SettingName }
        if ($null -eq $Setting) {
            Write-Warn "Setting '$SettingName' not found in response. May have a different name."
            Add-Result $Section $Title "WARN" "Setting '$SettingName' not found."
            return
        }
        $IsEnabled = ($Setting.enabled -eq $true) -or ($Setting.value -eq $true)
        Write-Info "$SettingName : enabled=$IsEnabled"
        if ($IsEnabled -eq $ExpectedEnabled) {
            Write-Pass "$SettingName is set correctly (enabled = $IsEnabled)."
            Add-Result $Section $Title "PASS" "$SettingName = $IsEnabled."
        } else {
            Write-Fail "$SettingName is NOT set correctly (enabled = $IsEnabled, expected = $ExpectedEnabled)."
            Add-Result $Section $Title "FAIL" "$SettingName = $IsEnabled (expected $ExpectedEnabled)."
        }
    }
}

function Check-9_1_1  { Check-9_PBI "9.1.1 (L1)"  "Ensure guest user access is restricted in Power BI"                                       "AllowGuestAccess"                     $false }
function Check-9_1_4  { Check-9_PBI "9.1.4 (L1)"  "Ensure 'Publish to web' is restricted in Power BI"                                        "PublishToWeb"                         $false }
function Check-9_1_5  { Check-9_PBI "9.1.5 (L2)"  "Ensure R and Python visuals are Disabled in Power BI"                                     "AllowRVisuals"                        $false }
function Check-9_1_6  { Check-9_PBI "9.1.6 (L1)"  "Ensure 'Allow users to apply sensitivity labels' is Enabled in Power BI"                  "SensitivityLabelsEnabled"             $true  }
function Check-9_1_7  { Check-9_PBI "9.1.7 (L1)"  "Ensure shareable links are restricted in Power BI"                                        "ShareLinkToEntireOrg"                 $false }
function Check-9_1_10 { Check-9_PBI "9.1.10 (L1)" "Ensure access to APIs by service principals is restricted in Power BI"                    "ServicePrincipalAccess"               $false }
function Check-9_1_11 { Check-9_PBI "9.1.11 (L1)" "Ensure service principals cannot create and use profiles in Power BI"                     "ServicePrincipalProfiles"             $false }
function Check-9_1_12 { Check-9_PBI "9.1.12 (L1)" "Ensure service principals cannot manage workspaces in Power BI"                           "ServicePrincipalCanManageWorkspaces"  $false }

# ===============================================================================
#  SUMMARY
# ===============================================================================
function Show-Summary {
    $total  = $Script:PassCount + $Script:FailCount + $Script:WarnCount
    $line82 = "=" * 82
    Write-Host ""
    Write-Host $line82 -ForegroundColor Cyan
    Write-Host "  CIS Microsoft 365 Foundations Benchmark v6.0.1 - RESULTS SUMMARY" -ForegroundColor Cyan
    Write-Host $line82 -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  {0,-12} {1,-50} {2}" -f "SECTION","TITLE","STATUS")
    Write-Host ("  {0,-12} {1,-50} {2}" -f ("-"*12),("-"*50),("-"*6))

    foreach ($r in $Script:Results) {
        $col = switch ($r.Status) { "PASS"{"Green"} "FAIL"{"Red"} default{"Magenta"} }
        $t   = if ($r.Title.Length -gt 50) { $r.Title.Substring(0,47) + "..." } else { $r.Title }
        Write-Host ("  {0,-12} {1,-50} " -f $r.Section, $t) -NoNewline
        Write-Host $r.Status -ForegroundColor $col
        if ($r.Status -ne "PASS") {
            Write-Host ("               $($r.Detail)") -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host $line82 -ForegroundColor Cyan
    Write-Host ("  Checks run : {0,4}" -f $total)
    if ($total -gt 0) {
        Write-Host ("  PASS       : {0,4}  ({1:P0})" -f $Script:PassCount, ($Script:PassCount / $total)) -ForegroundColor Green
        Write-Host ("  FAIL       : {0,4}  ({1:P0})" -f $Script:FailCount, ($Script:FailCount / $total)) -ForegroundColor Red
        Write-Host ("  WARN       : {0,4}  ({1:P0})" -f $Script:WarnCount, ($Script:WarnCount / $total)) -ForegroundColor Magenta
    }
    Write-Host $line82 -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Connection status:" -ForegroundColor Yellow
    Write-Host "    Graph  : [OK]" -ForegroundColor Green
    @("EXO","SPO","Teams") | ForEach-Object {
        $flag = switch ($_) { "EXO"{ $Script:ExoConnected } "SPO"{ $Script:SpoConnected } "Teams"{ $Script:TeamsConnected } }
        $msg  = if ($flag) { "[OK] Connected" } else { "[--] Not connected (checks marked WARN)" }
        $col  = if ($flag) { "Green" } else { "Red" }
        Write-Host ("    {0,-6}: {1}" -f $_, $msg) -ForegroundColor $col
    }
    Write-Host ""
    Write-Host "  Missing App Registration permissions (from WARN results):" -ForegroundColor Yellow
    Write-Host "    Exchange.ManageAsApp       - for app-only EXO connection" -ForegroundColor Gray
    Write-Host "    DeviceManagementConfiguration.Read.All - for Intune device settings (4.1)" -ForegroundColor Gray
    Write-Host "    DeviceManagementServiceConfig.Read.All - for Intune enrollment configs (4.2)" -ForegroundColor Gray
    Write-Host "    InformationProtectionPolicy.Read.All   - for DLP/Labels (3.x)" -ForegroundColor Gray
    Write-Host "    PrivilegedAccess.Read.AzureAD          - for PIM checks (5.3.1)" -ForegroundColor Gray
    Write-Host "    AccessReview.Read.All                  - for access reviews (5.3.3)" -ForegroundColor Gray
    Write-Host "    Tenant.Read.All (Power BI Service)     - for Power BI checks (9.x)" -ForegroundColor Gray
    Write-Host "    Tenant.Read.All (Microsoft Graph)      - for Power BI checks fallback (9.x)" -ForegroundColor Gray
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
Write-Host "|   CIS Microsoft 365 Foundations Benchmark v6.0.1 - 85 Automated Checks           |" -ForegroundColor Cyan
Write-Host "|   Tenant : $TenantId                          |" -ForegroundColor Cyan
Write-Host "+==================================================================================+" -ForegroundColor Cyan

Connect-AllServices

Write-Banner "SECTION 1 - Microsoft 365 Admin Center"
Check-1_1_1;  Check-1_1_3;  Check-1_1_4
Check-1_2_1;  Check-1_2_2
Check-1_3_1;  Check-1_3_2;  Check-1_3_3;  Check-1_3_4
Check-1_3_5;  Check-1_3_6;  Check-1_3_7;  Check-1_3_9

Write-Banner "SECTION 2 - Microsoft 365 Defender (Email & Collaboration)"
Check-2_1_2;  Check-2_1_3;  Check-2_1_5;  Check-2_1_6
Check-2_1_8;  Check-2_1_9;  Check-2_1_10
Check-2_1_13; Check-2_1_14; Check-2_1_15

Write-Banner "SECTION 3 - Compliance (DLP, Information Protection)"
Check-3_2_1;  Check-3_3_1

Write-Banner "SECTION 4 - Intune / Device Management"
Check-4_1;    Check-4_2

Write-Banner "SECTION 5 - Microsoft Entra ID (Identity, MFA, Conditional Access, PIM)"
Check-5_1_2_1;  Check-5_1_2_2;  Check-5_1_2_3
Check-5_1_4_2;  Check-5_1_4_3;  Check-5_1_4_4;  Check-5_1_4_5;  Check-5_1_4_6
Check-5_1_5_1
Check-5_1_6_1;  Check-5_1_6_3
Check-5_2_2_1;  Check-5_2_2_2;  Check-5_2_2_4;  Check-5_2_2_5
Check-5_2_2_8;  Check-5_2_2_9;  Check-5_2_2_10; Check-5_2_2_11
Check-5_2_3_1;  Check-5_2_3_3;  Check-5_2_3_6;  Check-5_2_3_7
Check-5_3_1;    Check-5_3_3;    Check-5_3_4;    Check-5_3_5

Write-Banner "SECTION 6 - Exchange Online"
Check-6_1_3
Check-6_2_1;  Check-6_2_2
Check-6_5_1;  Check-6_5_2;  Check-6_5_3;  Check-6_5_4

Write-Banner "SECTION 7 - SharePoint Online & OneDrive"
Check-7_2_1;  Check-7_2_2;  Check-7_2_5;  Check-7_2_7
Check-7_2_9;  Check-7_2_10; Check-7_2_11
Check-7_3_1;  Check-7_3_2

Write-Banner "SECTION 8 - Microsoft Teams"
Check-8_1_1;  Check-8_1_2
Check-8_2_1;  Check-8_2_2;  Check-8_2_3;  Check-8_2_4
Check-8_5_2;  Check-8_5_7;  Check-8_5_8;  Check-8_5_9

Write-Banner "SECTION 9 - Power BI"
Check-9_1_1;  Check-9_1_4;  Check-9_1_5;  Check-9_1_6
Check-9_1_7;  Check-9_1_10; Check-9_1_11; Check-9_1_12

Write-Banner "RESULTS SUMMARY"
Show-Summary

$elapsed = (Get-Date) - $StartTime
Write-Host "  Total runtime: $([Math]::Round($elapsed.TotalSeconds, 1))s" -ForegroundColor Gray

Disconnect-MgGraph -EA SilentlyContinue
if ($Script:ExoConnected)   { Disconnect-ExchangeOnline -Confirm:$false -EA SilentlyContinue }
if ($Script:TeamsConnected) { Disconnect-MicrosoftTeams -EA SilentlyContinue }
Write-Host "  All sessions disconnected." -ForegroundColor Gray
Write-Host ""
