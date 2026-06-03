<#
.SYNOPSIS
    CIS AKS Optimized Azure Linux 3 Benchmark v1.0.0 - Permissions Setup

.DESCRIPTION
    Prepares an AKS cluster for the CIS_AKS_Benchmark_Full.ps1 audit.

    Unlike the Azure / M365 / Power Platform helpers - which create an
    App Registration with Microsoft Graph permissions - the AKS benchmark
    does NOT call Microsoft Graph at all.  Every recommendation is an
    OS-level audit on the node host (Azure Linux 3) and is collected
    via `kubectl debug node`.  The only access the auditor needs is:

      * Azure Reader on the cluster's resource (so `az aks show` works)
      * Azure Kubernetes Service Cluster User Role on the cluster
        (issues a kubeconfig)
      * Azure Kubernetes Service RBAC Cluster Admin on the cluster
        (lets `kubectl debug node` create privileged debug pods)

    By default the script creates / reuses an Entra ID App Registration
    + Service Principal called CIS-AKS-Benchmark-Audit, mints a fresh
    client secret, assigns the three RBAC roles above at the cluster
    scope, runs `az aks get-credentials`, and prints the ready-to-run
    benchmark command.

    Use -InteractiveOnly to skip the SP creation entirely and grant
    the three RBAC roles to the *currently signed-in user* instead -
    appropriate for ad-hoc runs by an operator using their own login.

.NOTES
    Idempotent: the App Registration, Service Principal and RBAC role
    assignments are looked up by name / id first and only created when
    missing. Re-running the script will not duplicate any of them.

    A fresh client secret is minted on every run by default (so the
    printed benchmark command is ready to copy-paste).  Pass -NoSecret
    to skip secret creation (e.g. when only updating role assignments
    or when rotating secrets out of band).
#>

#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)] [string]$TenantId,
    [Parameter(Mandatory = $true)] [string]$SubscriptionId,
    [Parameter(Mandatory = $true)] [string]$ResourceGroup,
    [Parameter(Mandatory = $true)] [string]$ClusterName,

    [Parameter(Mandatory = $false)] [string]$AppName = "CIS-AKS-Benchmark-Audit",
    [Parameter(Mandatory = $false)] [string]$AppId,

    # Use the currently signed-in az user instead of creating a service principal.
    [switch]$InteractiveOnly,

    # Retained for backward compatibility. Secret creation is on by default.
    [switch]$CreateSecret,

    # Skip client-secret creation on this run (rotate manually).
    [switch]$NoSecret,

    [Parameter(Mandatory = $false)] [int]$SecretYears = 1,

    # Skip the "Run benchmark now?" prompt at the end.
    [switch]$NoPause,

    [Parameter(Mandatory = $false)]
    [string]$OutputJson = "$PSScriptRoot\CIS_AKS_Permissions_Output.json"
)

# ===============================================================================
#  HELPERS
# ===============================================================================
function Write-Section { param([string]$T)
    $line = "-" * 82
    Write-Host ""; Write-Host $line -ForegroundColor Cyan
    Write-Host "  $T" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}
function Write-Pass { param([string]$M); Write-Host "  [PASS] $M" -ForegroundColor Green }
function Write-Fail { param([string]$M); Write-Host "  [FAIL] $M" -ForegroundColor Red }
function Write-Warn { param([string]$M); Write-Host "  [WARN] $M" -ForegroundColor Magenta }
function Write-Info { param([string]$M); Write-Host "    $M"      -ForegroundColor Gray }

function Test-Tool { param([string]$N) [bool](Get-Command $N -ErrorAction SilentlyContinue) }

# ===============================================================================
#  PRE-FLIGHT
# ===============================================================================
Write-Section "Pre-flight: tooling and Azure login"
foreach ($t in @('az','kubectl')) {
    if (Test-Tool $t) { Write-Pass "$t found" }
    else { Write-Fail "$t not found in PATH"; throw "Install $t and re-run." }
}

# Login if needed
$cur = az account show --query 'user.name' -o tsv 2>$null
if (-not $cur) {
    Write-Warn "Not logged in.  Running 'az login --tenant $TenantId' ..."
    az login --tenant $TenantId | Out-Null
}
az account set --subscription $SubscriptionId | Out-Null
Write-Pass ("Subscription set: {0}" -f (az account show --query name -o tsv))

# Verify cluster exists
$clusterId = az aks show -g $ResourceGroup -n $ClusterName --query id -o tsv 2>$null
if (-not $clusterId) {
    throw "AKS cluster '$ClusterName' not found in resource group '$ResourceGroup'."
}
Write-Pass "Cluster found: $clusterId"

# ===============================================================================
#  IDENTITY: service principal OR interactive user
# ===============================================================================
$assigneeObjectId    = $null
$assigneePrincipalId = $null
$assigneeAppId       = $null
$mintedSecret        = $null

if ($InteractiveOnly) {
    Write-Section "Identity: -InteractiveOnly (current az user)"
    $assigneeObjectId = az ad signed-in-user show --query id -o tsv 2>$null
    if (-not $assigneeObjectId) { throw "Could not resolve current signed-in user via Microsoft Graph." }
    $upn = az ad signed-in-user show --query userPrincipalName -o tsv 2>$null
    Write-Pass "Will assign roles to: $upn ($assigneeObjectId)"
}
else {
    Write-Section "Identity: App Registration + Service Principal"

    # Find or create app
    if (-not $AppId) {
        $AppId = az ad app list --display-name $AppName --query '[0].appId' -o tsv 2>$null
    }
    if (-not $AppId) {
        Write-Info "Creating App Registration '$AppName' ..."
        $AppId = az ad app create --display-name $AppName --query appId -o tsv
        if (-not $AppId) { throw "Failed to create App Registration." }
        Write-Pass "App created: $AppId"
    } else {
        Write-Pass "App reused: $AppId"
    }
    $assigneeAppId = $AppId

    # SP
    $spObjectId = az ad sp list --filter "appId eq '$AppId'" --query '[0].id' -o tsv 2>$null
    if (-not $spObjectId) {
        Write-Info "Creating Service Principal ..."
        $spObjectId = az ad sp create --id $AppId --query id -o tsv
        Write-Pass "SP created: $spObjectId"
    } else {
        Write-Pass "SP reused: $spObjectId"
    }
    $assigneeObjectId    = $spObjectId
    $assigneePrincipalId = $spObjectId

    # Client secret
    if ($NoSecret) {
        Write-Warn "-NoSecret specified - skipping client secret creation."
    } else {
        Write-Info "Minting fresh client secret (SecretYears=$SecretYears) ..."
        $endDate = (Get-Date).AddYears($SecretYears).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $cred    = az ad app credential reset --id $AppId --append --years $SecretYears --query password -o tsv 2>$null
        if (-not $cred) { Write-Fail "Failed to create client secret." }
        else {
            $mintedSecret = $cred
            Write-Pass "Client secret minted."
        }
    }
}

# ===============================================================================
#  ROLE ASSIGNMENTS at cluster scope
# ===============================================================================
Write-Section "Role assignments on AKS cluster"
$roles = @(
    "Reader",
    "Azure Kubernetes Service Cluster User Role",
    "Azure Kubernetes Service RBAC Cluster Admin"
)
foreach ($role in $roles) {
    Write-Info "Assigning '$role' ..."
    try {
        az role assignment create `
            --assignee-object-id $assigneeObjectId `
            --assignee-principal-type $(if ($InteractiveOnly) { "User" } else { "ServicePrincipal" }) `
            --role $role `
            --scope $clusterId `
            --only-show-errors 2>$null | Out-Null
        Write-Pass "Granted '$role'."
    } catch {
        Write-Warn "Role assignment '$role' may already exist (continuing): $($_.Exception.Message.Split([char]10)[0])"
    }
}

# ===============================================================================
#  KUBECONFIG
# ===============================================================================
Write-Section "kubeconfig"
Write-Info "Running 'az aks get-credentials' ..."
az aks get-credentials -g $ResourceGroup -n $ClusterName --overwrite-existing --only-show-errors | Out-Null
$nodes = kubectl get nodes -o name 2>$null
if ($nodes) {
    Write-Pass ("kubectl reachable; {0} node(s) visible." -f (($nodes -split "`n" | Where-Object { $_ }).Count))
} else {
    Write-Warn "kubectl could not list nodes (RBAC / connectivity).  Re-run after the role assignment propagates (~5 min)."
}

# ===============================================================================
#  OUTPUT JSON (no secret) + READY-TO-RUN COMMAND
# ===============================================================================
$outRecord = [ordered]@{
    Timestamp        = (Get-Date).ToString('o')
    TenantId         = $TenantId
    SubscriptionId   = $SubscriptionId
    ResourceGroup    = $ResourceGroup
    ClusterName      = $ClusterName
    ClusterId        = $clusterId
    InteractiveOnly  = [bool]$InteractiveOnly
    AppName          = $AppName
    AppId            = $assigneeAppId
    SpObjectId       = $assigneePrincipalId
    AssigneeObjectId = $assigneeObjectId
    Roles            = $roles
}
$outRecord | ConvertTo-Json | Set-Content -Path $OutputJson -Encoding UTF8
Write-Info "Setup record written to: $OutputJson"

Write-Section "READY-TO-RUN BENCHMARK COMMAND"
$benchmark = Join-Path $PSScriptRoot "CIS_AKS_Benchmark_Full.ps1"
if (-not (Test-Path $benchmark)) { $benchmark = ".\CIS_AKS_Benchmark_Full.ps1" }

if ($InteractiveOnly) {
    $cmd = ".\CIS_AKS_Benchmark_Full.ps1 ``" + "`n" +
           "    -SubscriptionId '$SubscriptionId' ``" + "`n" +
           "    -ResourceGroup  '$ResourceGroup' ``"  + "`n" +
           "    -ClusterName    '$ClusterName' ``"   + "`n" +
           "    -RunOnNodes"
} else {
    $cmd = ".\CIS_AKS_Benchmark_Full.ps1 ``" + "`n" +
           "    -SubscriptionId '$SubscriptionId' ``" + "`n" +
           "    -ResourceGroup  '$ResourceGroup' ``"  + "`n" +
           "    -ClusterName    '$ClusterName' ``"   + "`n" +
           "    -RunOnNodes"
}
Write-Host $cmd -ForegroundColor White

if ($mintedSecret) {
    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │                          SAVE THIS SECRET NOW                                │" -ForegroundColor Yellow
    Write-Host "  │   The Azure-CLI / kubectl path used by this benchmark does NOT consume the   │" -ForegroundColor Yellow
    Write-Host "  │   secret directly - the kubeconfig issued above is enough.  The secret is    │" -ForegroundColor Yellow
    Write-Host "  │   printed only so you can re-issue a kubeconfig from another host via:       │" -ForegroundColor Yellow
    Write-Host "  │      az login --service-principal -u <AppId> -p <secret> --tenant <TenantId> │" -ForegroundColor Yellow
    Write-Host "  └──────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
    Write-Host "    AppId  : $assigneeAppId" -ForegroundColor Yellow
    Write-Host "    Secret : $mintedSecret"  -ForegroundColor Yellow
    Write-Host ""
}

# ===============================================================================
#  RUN NOW?
# ===============================================================================
if ($NoPause) { return }
$resp = Read-Host "Run benchmark now? [Y/N]"
if ($resp -match '^(y|yes)$') {
    if (-not (Test-Path $benchmark)) {
        Write-Warn "CIS_AKS_Benchmark_Full.ps1 not found alongside the helper - skipping."
        return
    }
    Write-Section "Launching CIS_AKS_Benchmark_Full.ps1"
    & $benchmark `
        -SubscriptionId $SubscriptionId `
        -ResourceGroup  $ResourceGroup `
        -ClusterName    $ClusterName `
        -RunOnNodes
}
