<#
.SYNOPSIS
    CIS Microsoft Azure Foundations Benchmark v5.0.0 - Permissions Setup

.DESCRIPTION
    Sets up the required permissions for running the CIS Azure Foundations Benchmark checks.
    Uses Azure CLI (az) to:
      - Create or reuse an Entra ID App Registration (for Microsoft Graph - Entra ID checks)
      - Ensure a Service Principal exists
      - Create a client secret (optional)
      - Add Microsoft Graph application permissions for Entra ID checks (Section 5)
      - Grant admin consent
      - Assign Azure RBAC roles at the subscription scope
      - Optionally install required PowerShell modules

    Required Azure RBAC Roles (assigned at subscription scope):
      - Reader                -> General read access to all Azure resources
      - Security Reader       -> Microsoft Defender for Cloud (Section 8.1.x)
      - Key Vault Reader      -> Key Vault properties (Section 8.3.x)

    Required Microsoft Graph Permissions (Application, admin consent required):
      - Directory.Read.All               -> Entra ID directory settings
      - Policy.Read.All                  -> Authorization policies, security defaults
      - User.Read.All                    -> User enumeration, MFA status
      - RoleManagement.Read.All          -> Role assignments
      - Organization.Read.All            -> Tenant settings

    Manual (MANL) checks:
      The 62 MANL checks in CIS_Azure_Benchmark_Full.ps1 print portal path,
      audit steps, and remediation for CIS items marked (Manual); they do not
      call any Azure or Graph API that is not already covered by the grants
      above, so no additional permissions are required for MANL coverage.
      Re-verify this statement whenever new MANL (or Automated) checks are
      added.

    Required PowerShell Modules:
      Az.Accounts, Az.Resources, Az.Security, Az.Network, Az.Monitor,
      Az.KeyVault, Az.Storage, Az.Websites, Az.ApplicationInsights, Az.Compute,
      Microsoft.Graph.Identity.SignIns,
      Microsoft.Graph.Identity.DirectoryManagement

.EXAMPLE
    .\CIS_Azure_Permissions.ps1 -TenantId "<tenant-guid>" -SubscriptionId "<sub-guid>"

.EXAMPLE
    .\CIS_Azure_Permissions.ps1 -TenantId "<tenant-guid>" -SubscriptionId "<sub-guid>" -AppId "<existing-app-guid>"

.EXAMPLE
    .\CIS_Azure_Permissions.ps1 -TenantId "<tenant-guid>" -SubscriptionId "<sub-guid>" -SkipModuleInstall
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$AppName = "CIS-Azure-Benchmark-Audit",

    [Parameter(Mandatory = $false)]
    [string]$AppId,

    [Parameter(Mandatory = $false)]
    [switch]$NoSecret,

    [Parameter(Mandatory = $false)]
    [int]$SecretYears = 1,

    [Parameter(Mandatory = $false)]
    [switch]$SkipModuleInstall,

    [Parameter(Mandatory = $false)]
    [switch]$SkipGraphPermissions,

    [Parameter(Mandatory = $false)]
    [switch]$SkipRbacRoles,

    [Parameter(Mandatory = $false)]
    [switch]$NoPause,

    [Parameter(Mandatory = $false)]
    [switch]$AutoLogin,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\CIS_Azure_Permissions_Output.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:AzReauthAttempted = $false

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

function Write-Step  { param([string]$M); Write-Host "`n► $M" -ForegroundColor Cyan }
function Write-OK    { param([string]$M); Write-Host "  ✓ $M" -ForegroundColor Green }
function Write-Warn  { param([string]$M); Write-Host "  ⚠ $M" -ForegroundColor Yellow }
function Write-Err   { param([string]$M); Write-Host "  ✗ $M" -ForegroundColor Red }
function Write-Detail{ param([string]$M); Write-Host "    $M" -ForegroundColor Gray }

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
        $ErrorActionPreference = 'SilentlyContinue'
        az logout 2>$null
    } finally { $ErrorActionPreference = $prevEap }
    az login --tenant $ExpectedTenantId --output none 2>&1
}

function Invoke-Az {
    param([string[]]$Arguments, [switch]$AllowFailure)
    $raw = & az @Arguments 2>&1
    $code = $LASTEXITCODE
    $stderr = ($raw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"
    $stdout = ($raw | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"

    if ($code -ne 0) {
        if (Test-AzAuthError $stderr) {
            Repair-AzLogin $TenantId
            $raw = & az @Arguments 2>&1
            $code = $LASTEXITCODE
            $stderr = ($raw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join "`n"
            $stdout = ($raw | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
        }
        if ($code -ne 0 -and -not $AllowFailure) {
            throw "az $($Arguments -join ' ') failed (exit $code): $stderr"
        }
    }
    return $stdout
}

function Invoke-AzJson {
    param([string[]]$Arguments, [switch]$AllowFailure)
    $out = Invoke-Az -Arguments ($Arguments + @('--output','json')) -AllowFailure:$AllowFailure
    if ([string]::IsNullOrWhiteSpace($out)) { return $null }
    return ($out | ConvertFrom-Json)
}

function Pause-IfInteractive {
    if (-not $NoPause) {
        Write-Host ""
        Read-Host "Press Enter to continue (or Ctrl+C to abort)"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host ("=" * 82) -ForegroundColor Cyan
Write-Host "  CIS Microsoft Azure Foundations Benchmark v5.0.0 - Permissions Setup" -ForegroundColor Cyan
Write-Host ("=" * 82) -ForegroundColor Cyan

# ── 1. Verify Azure CLI login ────────────────────────────────────────────────
Write-Step "Verifying Azure CLI login and tenant"

$currentAccount = Invoke-AzJson -Arguments @('account','show') -AllowFailure
if (-not $currentAccount) {
    Write-Warn "Not logged in to Azure CLI. Logging in..."
    az login --tenant $TenantId --output none 2>&1
    $currentAccount = Invoke-AzJson -Arguments @('account','show')
}

if ($currentAccount.tenantId -ne $TenantId) {
    if ($AutoLogin) {
        Write-Warn "Switching to tenant $TenantId"
        az login --tenant $TenantId --output none 2>&1
        $currentAccount = Invoke-AzJson -Arguments @('account','show')
    } else {
        Write-Err "Azure CLI is logged into tenant $($currentAccount.tenantId) but expected $TenantId"
        Write-Detail "Run: az login --tenant $TenantId"
        exit 1
    }
}

# Set subscription context
Invoke-Az -Arguments @('account','set','--subscription',$SubscriptionId)
Write-OK "Logged in as $($currentAccount.user.name) | Tenant: $TenantId | Subscription: $SubscriptionId"

# ── 2. Create or reuse App Registration ──────────────────────────────────────
Write-Step "Setting up App Registration for Microsoft Graph permissions"

if ($SkipGraphPermissions) {
    Write-Warn "Skipping Graph permissions setup (-SkipGraphPermissions)"
    $AppId = "SKIPPED"
    $clientSecret = "SKIPPED"
} else {
    if (-not $AppId) {
        $existingApp = Invoke-AzJson -Arguments @('ad','app','list','--display-name',$AppName,'--query','[0]') -AllowFailure
        if ($existingApp -and $existingApp.appId) {
            $AppId = $existingApp.appId
            Write-OK "Reusing existing app registration: $AppName ($AppId)"
        } else {
            Write-Detail "Creating new app registration: $AppName"
            $newApp = Invoke-AzJson -Arguments @('ad','app','create','--display-name',$AppName)
            $AppId = $newApp.appId
            Write-OK "Created app registration: $AppName ($AppId)"
        }
    } else {
        Write-OK "Using provided AppId: $AppId"
    }

    # Ensure Service Principal exists
    $sp = Invoke-AzJson -Arguments @('ad','sp','show','--id',$AppId) -AllowFailure
    if (-not $sp) {
        Write-Detail "Creating service principal..."
        $sp = Invoke-AzJson -Arguments @('ad','sp','create','--id',$AppId)
        Write-OK "Service principal created"
    } else {
        Write-OK "Service principal already exists"
    }
    $spObjectId = $sp.id

    # Create client secret
    $clientSecret = $null
    if (-not $NoSecret) {
        Write-Detail "Creating client secret (valid for $SecretYears year(s))..."
        $endDate = (Get-Date).AddYears($SecretYears).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $secretResult = Invoke-AzJson -Arguments @(
            'ad','app','credential','reset',
            '--id', $AppId,
            '--append',
            '--display-name', "CIS-Azure-Benchmark-Secret",
            '--end-date', $endDate
        )
        $clientSecret = $secretResult.password
        Write-OK "Client secret created (expires: $endDate)"
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "  ║  SAVE THIS SECRET NOW - it will not be shown again!         ║" -ForegroundColor Yellow
        Write-Host "  ║  Secret: $clientSecret" -ForegroundColor Yellow
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    }

    # ── 3. Add Microsoft Graph permissions ───────────────────────────────────
    Write-Step "Adding Microsoft Graph API permissions"

    # Microsoft Graph App ID (well-known)
    $graphAppId = "00000003-0000-0000-c000-000000000000"

    # Required Graph permissions for Entra ID checks (Section 5)
    $graphPermissions = @(
        @{ Name = "Directory.Read.All";          Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" }
        @{ Name = "Policy.Read.All";             Id = "246dd0d5-5bd0-4def-940b-0421030a5b68" }
        @{ Name = "User.Read.All";               Id = "df021288-bdef-4463-88db-98f22de89214" }
        @{ Name = "RoleManagement.Read.All";     Id = "c7fbd983-d9aa-4fa7-84b8-17382c103bc4" }
        @{ Name = "Organization.Read.All";       Id = "498476ce-e0fe-48b0-b801-37ba7e2685c6" }
    )

    foreach ($perm in $graphPermissions) {
        Write-Detail "Adding permission: $($perm.Name)"
        Invoke-Az -Arguments @(
            'ad','app','permission','add',
            '--id', $AppId,
            '--api', $graphAppId,
            '--api-permissions', "$($perm.Id)=Role"
        ) -AllowFailure
    }
    Write-OK "Graph permissions added"

    # ── 4. Grant admin consent ───────────────────────────────────────────────
    Write-Step "Granting admin consent for Microsoft Graph permissions"
    Write-Detail "Waiting 10 seconds for permission propagation..."
    Start-Sleep -Seconds 10

    Invoke-Az -Arguments @(
        'ad','app','permission','admin-consent',
        '--id', $AppId
    ) -AllowFailure
    Write-OK "Admin consent granted (verify in Azure Portal if needed)"
}

# ── 5. Assign Azure RBAC roles ───────────────────────────────────────────────
if (-not $SkipRbacRoles) {
    Write-Step "Assigning Azure RBAC roles at subscription scope"

    $rolesToAssign = @(
        "Reader",
        "Security Reader",
        "Key Vault Reader"
    )

    $scope = "/subscriptions/$SubscriptionId"

    # Determine assignee - use SP if we have one, otherwise use current user
    if ($AppId -and $AppId -ne "SKIPPED" -and $spObjectId) {
        $assigneeId = $spObjectId
        $assigneeType = "ServicePrincipal"
        Write-Detail "Assigning roles to Service Principal: $assigneeId"
    } else {
        $assigneeId = $currentAccount.user.name
        $assigneeType = "User"
        Write-Detail "Assigning roles to current user: $assigneeId"
    }

    foreach ($roleName in $rolesToAssign) {
        Write-Detail "Assigning role: $roleName"
        $existing = Invoke-AzJson -Arguments @(
            'role','assignment','list',
            '--assignee', $assigneeId,
            '--role', $roleName,
            '--scope', $scope,
            '--query', '[0]'
        ) -AllowFailure

        if ($existing) {
            Write-OK "  $roleName - already assigned"
        } else {
            Invoke-Az -Arguments @(
                'role','assignment','create',
                '--assignee-object-id', $assigneeId,
                '--assignee-principal-type', $assigneeType,
                '--role', $roleName,
                '--scope', $scope
            ) -AllowFailure
            Write-OK "  $roleName - assigned"
        }
    }
} else {
    Write-Warn "Skipping RBAC role assignments (-SkipRbacRoles)"
}

# ── 6. Install PowerShell modules ────────────────────────────────────────────
if (-not $SkipModuleInstall) {
    Write-Step "Installing required PowerShell modules"

    $requiredModules = @(
        "Az.Accounts",
        "Az.Resources",
        "Az.Security",
        "Az.Network",
        "Az.Monitor",
        "Az.KeyVault",
        "Az.Storage",
        "Az.Websites",
        "Az.ApplicationInsights",
        "Az.Compute",
        "Microsoft.Graph.Identity.SignIns",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )

    # Optional modules (may not be available in all environments)
    $optionalModules = @(
        "Az.Databricks"
    )

    foreach ($mod in $requiredModules) {
        $installed = Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue
        if ($installed) {
            Write-OK "$mod (v$($installed[0].Version)) - already installed"
        } else {
            Write-Detail "Installing $mod..."
            try {
                Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-OK "$mod - installed"
            } catch {
                Write-Err "Failed to install $mod : $($_.Exception.Message)"
            }
        }
    }

    foreach ($mod in $optionalModules) {
        $installed = Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue
        if ($installed) {
            Write-OK "$mod (v$($installed[0].Version)) - already installed (optional)"
        } else {
            Write-Detail "Installing optional module $mod..."
            try {
                Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-OK "$mod - installed"
            } catch {
                Write-Warn "Optional module $mod not installed: $($_.Exception.Message)"
            }
        }
    }
} else {
    Write-Warn "Skipping module installation (-SkipModuleInstall)"
}

# ── 7. Output configuration ─────────────────────────────────────────────────
Write-Step "Saving configuration"

$config = [ordered]@{
    TenantId       = $TenantId
    SubscriptionId = $SubscriptionId
    AppId          = $AppId
    ClientSecret   = if ($clientSecret) { $clientSecret } else { "NOT_CREATED" }
    RolesAssigned  = if (-not $SkipRbacRoles) { @("Reader","Security Reader","Key Vault Reader") } else { @() }
    GraphPerms     = if (-not $SkipGraphPermissions) { @("Directory.Read.All","Policy.Read.All","User.Read.All","RoleManagement.Read.All","Organization.Read.All") } else { @() }
    CreatedAt      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}

$config | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-OK "Configuration saved to: $OutputPath"

# ── 8. Summary ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host ("=" * 82) -ForegroundColor Green
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host ("=" * 82) -ForegroundColor Green
Write-Host ""
Write-Host "  To run the CIS Azure Foundations Benchmark:" -ForegroundColor White
Write-Host ""

if ($AppId -and $AppId -ne "SKIPPED") {
    $secretDisplay = if ($clientSecret) { $clientSecret } else { "<NOT_CREATED - re-run without -NoSecret>" }
    Write-Host "    .\CIS_Azure_Benchmark_Full.ps1 ``" -ForegroundColor Yellow
    Write-Host "        -TenantId `"$TenantId`" ``" -ForegroundColor Yellow
    Write-Host "        -SubscriptionId `"$SubscriptionId`" ``" -ForegroundColor Yellow
    Write-Host "        -ClientId `"$AppId`" ``" -ForegroundColor Yellow
    Write-Host "        -ClientSecret `"$secretDisplay`"" -ForegroundColor Yellow
} else {
    Write-Host "    .\CIS_Azure_Benchmark_Full.ps1 ``" -ForegroundColor Yellow
    Write-Host "        -TenantId `"$TenantId`" ``" -ForegroundColor Yellow
    Write-Host "        -SubscriptionId `"$SubscriptionId`"" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Configuration saved to: $OutputPath" -ForegroundColor Gray
Write-Host ""

if (-not $NoPause -and $AppId -and $AppId -ne "SKIPPED" -and $clientSecret) {
    $runNow = Read-Host '  Run benchmark now? [Y/N]'
    if ($runNow -match '^[Yy]') {
        $benchmarkPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'CIS_Azure_Benchmark_Full.ps1'
        if (Test-Path $benchmarkPath) {
            & $benchmarkPath -TenantId $TenantId -SubscriptionId $SubscriptionId -ClientId $AppId -ClientSecret $clientSecret
        } else {
            Write-Warn "Script not found: $benchmarkPath"
            Write-Detail "Make sure both scripts are in the same directory."
        }
    }
}
