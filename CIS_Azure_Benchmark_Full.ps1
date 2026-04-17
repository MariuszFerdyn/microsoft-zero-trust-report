#Requires -Version 5.1
<#
.SYNOPSIS
    CIS Microsoft Azure Foundations Benchmark v5.0.0 - 103 Checks (Automated + Manual)

.DESCRIPTION
    Implements all 93 automated checks from the CIS Microsoft Azure Foundations
    Benchmark v5.0.0 covering:
      Section 2  - Databricks (6 checks)
      Section 5  - Identity / Entra ID (9 checks)
      Section 6  - Logging & Monitoring (16 checks)
      Section 7  - Networking (14 checks)
      Section 8  - Security (30 checks)
      Section 9  - Storage (18 checks)

    Supports service-principal (non-interactive) and interactive authentication.
    Outputs results to console and CSV.

.NOTES
    Required PowerShell Modules:
        Install-Module Az               -Scope CurrentUser -Force
        Install-Module Microsoft.Graph   -Scope CurrentUser -Force

    For service-principal authentication the app registration needs:
        Azure RBAC : Reader role on the target subscription
        Microsoft Graph : Directory.Read.All, Policy.Read.All (Application, admin-consented)
#>

param(
    [string]$SubscriptionId = "",
    [string]$TenantId       = "",
    [string]$ClientId       = "",
    [string]$ClientSecret   = "",
    [string]$OutputPath     = "$PSScriptRoot\CIS_Azure_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# ===============================================================================
#  RESULT TRACKING
# ===============================================================================
$Script:PassCount = 0
$Script:FailCount = 0
$Script:WarnCount = 0
$Script:Results   = [System.Collections.Generic.List[object]]::new()

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

function Connect-AllServices {
    Write-Banner "Connecting to Azure Services"

    # -- Az modules ----------------------------------------------------------------
    Write-Host "  Loading Az modules..." -ForegroundColor Yellow
    foreach ($mod in @(
        "Az.Accounts",
        "Az.Resources",
        "Az.Network",
        "Az.Security",
        "Az.Monitor",
        "Az.KeyVault",
        "Az.Storage",
        "Az.Websites",
        "Az.Compute",
        "Az.OperationalInsights"
    )) { Ensure-Module $mod }

    # -- Connect to Azure ----------------------------------------------------------
    Write-Host "  Connecting to Azure..." -ForegroundColor Yellow
    try {
        if ($ClientId -and $ClientSecret -and $TenantId) {
            $SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
            $Cred = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)
            Connect-AzAccount -ServicePrincipal -Credential $Cred -Tenant $TenantId -ErrorAction Stop | Out-Null
            Write-Host "  [OK] Azure connected (Service Principal)" -ForegroundColor Green
        } else {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            Write-Host "  [OK] Azure connected (Interactive)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [FAIL] Azure connection failed: $_" -ForegroundColor Red
        exit 1
    }

    # -- Set subscription context --------------------------------------------------
    if ($SubscriptionId) {
        try {
            Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
            Write-Host "  [OK] Subscription set: $SubscriptionId" -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] Could not set subscription: $_" -ForegroundColor Red
            exit 1
        }
    } else {
        $ctx = Get-AzContext
        $SubscriptionId = $ctx.Subscription.Id
        Write-Host "  [OK] Using current subscription: $SubscriptionId" -ForegroundColor Green
    }

    # -- Microsoft Graph (for Entra ID / Section 5) --------------------------------
    Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        foreach ($gmod in @(
            "Microsoft.Graph.Authentication",
            "Microsoft.Graph.Identity.DirectoryManagement",
            "Microsoft.Graph.Identity.SignIns"
        )) { Ensure-Module $gmod }

        if ($ClientId -and $ClientSecret -and $TenantId) {
            $SecureSecret2 = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
            $ClientCred    = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret2)
            Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientCred -NoWelcome -ErrorAction Stop
        } else {
            Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All" -NoWelcome -ErrorAction Stop
        }
        Write-Host "  [OK] Microsoft Graph connected" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Graph connection failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "         Entra ID checks (Section 5) may be skipped." -ForegroundColor Yellow
    }
}
# ===============================================================================
#  SHARED HELPERS FOR MULTI-RESOURCE CHECKS
# ===============================================================================

# -- Activity Log Alert helper (Section 6.1.2) ----------------------------------
function Check-ActivityLogAlert {
    param([string]$Section, [string]$Title, [string]$OperationName)
    Invoke-Check $Section $Title {
        $alerts = Get-AzActivityLogAlert -ErrorAction SilentlyContinue
        if (-not $alerts) {
            Write-Fail "No Activity Log Alerts configured"
            Add-Result $Section $Title "FAIL" "No Activity Log Alerts found"
            return
        }
        $found = $false
        foreach ($alert in $alerts) {
            if (-not $alert.Enabled) { continue }
            $conditions = $alert.ConditionAllOf
            foreach ($cond in $conditions) {
                if ($cond.Field -eq "operationName" -and $cond.Equal -eq $OperationName) {
                    $found = $true
                    break
                }
            }
            if ($found) { break }
        }
        if ($found) {
            Write-Pass "Activity Log Alert exists for $OperationName"
            Add-Result $Section $Title "PASS" "Alert found for $OperationName"
        } else {
            Write-Fail "No Activity Log Alert for $OperationName"
            Add-Result $Section $Title "FAIL" "No alert for $OperationName"
        }
    }
}

# -- Defender pricing tier helper (Section 8.1) ---------------------------------
function Check-DefenderPricing {
    param([string]$Section, [string]$Title, [string]$PlanName)
    Invoke-Check $Section $Title {
        try {
            $pricing = Get-AzSecurityPricing -Name $PlanName -ErrorAction Stop
            if ($pricing.PricingTier -eq "Standard") {
                Write-Pass "Defender for $PlanName is On (Standard)"
                Add-Result $Section $Title "PASS" "PricingTier: Standard"
            } else {
                Write-Fail "Defender for $PlanName is Off (Free)"
                Add-Result $Section $Title "FAIL" "PricingTier: $($pricing.PricingTier)"
            }
        } catch {
            Write-Warn "Could not check Defender for $PlanName : $($_.Exception.Message)"
            Add-Result $Section $Title "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

# -- NSG port-from-internet test helper (Section 7) -----------------------------
function Test-NSGPortOpenFromInternet {
    param([object]$Rule, [int[]]$Ports)
    if ($Rule.Access -ne "Allow") { return $false }
    if ($Rule.Direction -ne "Inbound") { return $false }

    $internetSources = @("*", "Internet", "0.0.0.0/0", "0.0.0.0", "<nw>/0", "/0", "any")
    $srcMatch = $false
    foreach ($prefix in @($Rule.SourceAddressPrefix) + @($Rule.SourceAddressPrefixes)) {
        if ($prefix -and $internetSources -contains $prefix) { $srcMatch = $true; break }
    }
    if (-not $srcMatch) { return $false }

    # Check destination ports
    $allPorts = @()
    if ($Rule.DestinationPortRange)  { $allPorts += @($Rule.DestinationPortRange) }
    if ($Rule.DestinationPortRanges) { $allPorts += @($Rule.DestinationPortRanges) }

    foreach ($portSpec in $allPorts) {
        if ($portSpec -eq "*") { return $true }
        if ($portSpec -match "^(\d+)-(\d+)$") {
            $low  = [int]$Matches[1]
            $high = [int]$Matches[2]
            foreach ($p in $Ports) {
                if ($p -ge $low -and $p -le $high) { return $true }
            }
        } elseif ($portSpec -match "^\d+$") {
            if ([int]$portSpec -in $Ports) { return $true }
        }
    }
    return $false
}

function Check-NSGPortFromInternet {
    param([string]$Section, [string]$Title, [int[]]$Ports, [object[]]$NSGs)
    Invoke-Check $Section $Title {
        if (-not $NSGs -or $NSGs.Count -eq 0) {
            Write-Info "No NSGs found - check not applicable"
            Add-Result $Section $Title "INFO" "No NSGs found"
            return
        }
        $violations = @()
        foreach ($nsg in $NSGs) {
            $allRules = @($nsg.SecurityRules) + @($nsg.DefaultSecurityRules)
            foreach ($rule in $allRules) {
                if (Test-NSGPortOpenFromInternet -Rule $rule -Ports $Ports) {
                    $violations += "$($nsg.Name) / $($rule.Name) allows port(s) $($Ports -join ',') from Internet"
                }
            }
        }
        if ($violations.Count -eq 0) {
            Write-Pass "No NSG rules allow port(s) $($Ports -join ',') from Internet"
            Add-Result $Section $Title "PASS" "No open rules found"
        } else {
            foreach ($v in $violations) { Write-Fail $v }
            Add-Result $Section $Title "FAIL" "$($violations.Count) violation(s) found"
        }
    }
}

# ===============================================================================
#  SECTION 2 - DATABRICKS
# ===============================================================================
function Check-2_1_1 {
    Invoke-Check "2.1.1" "Ensure Azure Databricks is deployed in customer-managed VNet" {
        try {
            $workspaces = @(Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ErrorAction SilentlyContinue)
            if ($workspaces.Count -eq 0) {
                Write-Info "No Databricks workspaces found - check not applicable"
                Add-Result "2.1.1" "Databricks in customer-managed VNet" "INFO" "No Databricks workspaces found"
                return
            }
            $allGood = $true
            foreach ($ws in $workspaces) {
                $detail = Get-AzResource -ResourceId $ws.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $vnetId = $detail.Properties.parameters.customVirtualNetworkId.value
                if (-not $vnetId) {
                    Write-Fail "Workspace '$($ws.Name)' is NOT in a customer-managed VNet"
                    $allGood = $false
                } else {
                    Write-Pass "Workspace '$($ws.Name)' is in VNet: $vnetId"
                }
            }
            if ($allGood) {
                Add-Result "2.1.1" "Databricks in customer-managed VNet" "PASS" "All workspaces in customer VNet"
            } else {
                Add-Result "2.1.1" "Databricks in customer-managed VNet" "FAIL" "One or more workspaces not in customer VNet"
            }
        } catch {
            Write-Warn "Error checking Databricks VNets: $($_.Exception.Message)"
            Add-Result "2.1.1" "Databricks in customer-managed VNet" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-2_1_2 {
    Invoke-Check "2.1.2" "Ensure NSGs configured for Databricks subnets" {
        try {
            $workspaces = @(Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ErrorAction SilentlyContinue)
            if ($workspaces.Count -eq 0) {
                Write-Info "No Databricks workspaces found - check not applicable"
                Add-Result "2.1.2" "NSGs on Databricks subnets" "INFO" "No Databricks workspaces found"
                return
            }
            $allGood = $true
            foreach ($ws in $workspaces) {
                $detail = Get-AzResource -ResourceId $ws.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $vnetId = $detail.Properties.parameters.customVirtualNetworkId.value
                if (-not $vnetId) { continue }
                $pubSubnet  = $detail.Properties.parameters.customPublicSubnetName.value
                $privSubnet = $detail.Properties.parameters.customPrivateSubnetName.value
                $vnetName = ($vnetId -split "/")[-1]
                $vnetRg   = ($vnetId -split "/")[4]
                $vnet = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $vnetRg -ErrorAction SilentlyContinue
                if (-not $vnet) { continue }
                foreach ($subName in @($pubSubnet, $privSubnet)) {
                    if (-not $subName) { continue }
                    $subnet = $vnet.Subnets | Where-Object { $_.Name -eq $subName }
                    if ($subnet -and -not $subnet.NetworkSecurityGroup) {
                        Write-Fail "Subnet '$subName' in VNet '$vnetName' has no NSG (workspace: $($ws.Name))"
                        $allGood = $false
                    } elseif ($subnet) {
                        Write-Pass "Subnet '$subName' has NSG associated"
                    }
                }
            }
            if ($allGood) {
                Add-Result "2.1.2" "NSGs on Databricks subnets" "PASS" "All Databricks subnets have NSGs"
            } else {
                Add-Result "2.1.2" "NSGs on Databricks subnets" "FAIL" "One or more subnets missing NSGs"
            }
        } catch {
            Write-Warn "Error checking Databricks NSGs: $($_.Exception.Message)"
            Add-Result "2.1.2" "NSGs on Databricks subnets" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-2_1_7 {
    Invoke-Check "2.1.7" "Ensure diagnostic log delivery configured for Databricks" {
        try {
            $workspaces = @(Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ErrorAction SilentlyContinue)
            if ($workspaces.Count -eq 0) {
                Write-Info "No Databricks workspaces found - check not applicable"
                Add-Result "2.1.7" "Databricks diagnostic logs" "INFO" "No Databricks workspaces found"
                return
            }
            $allGood = $true
            foreach ($ws in $workspaces) {
                $diag = Get-AzDiagnosticSetting -ResourceId $ws.ResourceId -ErrorAction SilentlyContinue
                if (-not $diag) {
                    Write-Fail "No diagnostic settings for workspace '$($ws.Name)'"
                    $allGood = $false
                } else {
                    Write-Pass "Diagnostic settings exist for workspace '$($ws.Name)'"
                }
            }
            if ($allGood) {
                Add-Result "2.1.7" "Databricks diagnostic logs" "PASS" "All workspaces have diagnostic settings"
            } else {
                Add-Result "2.1.7" "Databricks diagnostic logs" "FAIL" "One or more workspaces missing diagnostics"
            }
        } catch {
            Write-Warn "Error checking Databricks diagnostics: $($_.Exception.Message)"
            Add-Result "2.1.7" "Databricks diagnostic logs" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-2_1_9 {
    Invoke-Check "2.1.9" "Ensure 'No Public IP' is Enabled" {
        try {
            $workspaces = @(Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ErrorAction SilentlyContinue)
            if ($workspaces.Count -eq 0) {
                Write-Info "No Databricks workspaces found - check not applicable"
                Add-Result "2.1.9" "Databricks No Public IP" "INFO" "No Databricks workspaces found"
                return
            }
            $allGood = $true
            foreach ($ws in $workspaces) {
                $detail = Get-AzResource -ResourceId $ws.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $noPublicIp = $detail.Properties.parameters.enableNoPublicIp.value
                if ($noPublicIp -eq $true) {
                    Write-Pass "Workspace '$($ws.Name)' has No Public IP enabled"
                } else {
                    Write-Fail "Workspace '$($ws.Name)' does NOT have No Public IP enabled"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "2.1.9" "Databricks No Public IP" "PASS" "All workspaces have No Public IP"
            } else {
                Add-Result "2.1.9" "Databricks No Public IP" "FAIL" "One or more workspaces allow public IPs"
            }
        } catch {
            Write-Warn "Error checking Databricks No Public IP: $($_.Exception.Message)"
            Add-Result "2.1.9" "Databricks No Public IP" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-2_1_10 {
    Invoke-Check "2.1.10" "Ensure 'Allow Public Network Access' is Disabled" {
        try {
            $workspaces = @(Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ErrorAction SilentlyContinue)
            if ($workspaces.Count -eq 0) {
                Write-Info "No Databricks workspaces found - check not applicable"
                Add-Result "2.1.10" "Databricks Public Network Access" "INFO" "No Databricks workspaces found"
                return
            }
            $allGood = $true
            foreach ($ws in $workspaces) {
                $detail = Get-AzResource -ResourceId $ws.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $pna = $detail.Properties.publicNetworkAccess
                if ($pna -eq "Disabled") {
                    Write-Pass "Workspace '$($ws.Name)' public network access is Disabled"
                } else {
                    Write-Fail "Workspace '$($ws.Name)' public network access is '$pna'"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "2.1.10" "Databricks Public Network Access" "PASS" "All workspaces have public access disabled"
            } else {
                Add-Result "2.1.10" "Databricks Public Network Access" "FAIL" "One or more workspaces allow public access"
            }
        } catch {
            Write-Warn "Error checking Databricks public access: $($_.Exception.Message)"
            Add-Result "2.1.10" "Databricks Public Network Access" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-2_1_11 {
    Invoke-Check "2.1.11" "Ensure private endpoints are used" {
        try {
            $workspaces = @(Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ErrorAction SilentlyContinue)
            if ($workspaces.Count -eq 0) {
                Write-Info "No Databricks workspaces found - check not applicable"
                Add-Result "2.1.11" "Databricks private endpoints" "INFO" "No Databricks workspaces found"
                return
            }
            $allGood = $true
            foreach ($ws in $workspaces) {
                $detail = Get-AzResource -ResourceId $ws.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $pe = $detail.Properties.privateEndpointConnections
                if ($pe -and @($pe).Count -gt 0) {
                    Write-Pass "Workspace '$($ws.Name)' has private endpoint connections"
                } else {
                    Write-Fail "Workspace '$($ws.Name)' has NO private endpoint connections"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "2.1.11" "Databricks private endpoints" "PASS" "All workspaces use private endpoints"
            } else {
                Add-Result "2.1.11" "Databricks private endpoints" "FAIL" "One or more workspaces lack private endpoints"
            }
        } catch {
            Write-Warn "Error checking Databricks private endpoints: $($_.Exception.Message)"
            Add-Result "2.1.11" "Databricks private endpoints" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-2_1_8 {
    Invoke-Check "2.1.8" "Ensure critical data in Databricks is encrypted with customer-managed keys (all workspaces)" {
        try {
            $workspaces = @(Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ErrorAction SilentlyContinue)
            if ($workspaces.Count -eq 0) {
                Write-Info "No Databricks workspaces found - check not applicable"
                Add-Result "2.1.8" "Databricks CMK encryption" "INFO" "No Databricks workspaces found"
                return
            }
            $allGood = $true
            foreach ($ws in $workspaces) {
                $detail = Get-AzResource -ResourceId $ws.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $encryption = $detail.Properties.encryption
                $parameters = $detail.Properties.parameters
                $cmkManaged = ($parameters.encryption.value.keySource -eq "Microsoft.Keyvault") -or `
                              ($encryption.entities.managedDisk.keySource -eq "Microsoft.Keyvault") -or `
                              ($encryption.entities.managedServices.keySource -eq "Microsoft.Keyvault")
                if ($cmkManaged) {
                    Write-Pass "Workspace '$($ws.Name)' is using customer-managed keys"
                } else {
                    Write-Fail "Workspace '$($ws.Name)' is NOT using customer-managed keys (Microsoft-managed only)"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "2.1.8" "Databricks CMK encryption" "PASS" "All workspaces use CMK"
            } else {
                Add-Result "2.1.8" "Databricks CMK encryption" "FAIL" "One or more workspaces without CMK"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "2.1.8" "Databricks CMK encryption" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}
# ===============================================================================
#  SECTION 5 - IDENTITY / ENTRA ID
# ===============================================================================
function Check-5_1_1 {
    Invoke-Check "5.1.1" "Ensure security defaults are enabled" {
        try {
            $policy = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
            if ($policy.IsEnabled -eq $true) {
                Write-Pass "Security defaults are enabled"
                Add-Result "5.1.1" "Security defaults enabled" "PASS" "IsEnabled: True"
            } else {
                Write-Fail "Security defaults are NOT enabled"
                Write-Info "Note: Security defaults and Conditional Access are mutually exclusive"
                Add-Result "5.1.1" "Security defaults enabled" "FAIL" "IsEnabled: False (may use Conditional Access instead)"
            }
        } catch {
            Write-Warn "Could not check security defaults: $($_.Exception.Message)"
            Add-Result "5.1.1" "Security defaults enabled" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-5_1_2 {
    Invoke-Check "5.1.2" "Ensure MFA is enabled for all users" {
        try {
            # Check Conditional Access policies for MFA requirement
            $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
            $mfaPolicy = $policies | Where-Object {
                $_.State -eq "enabled" -and
                $_.GrantControls.BuiltInControls -contains "mfa" -and
                $_.Conditions.Users.IncludeUsers -contains "All"
            }
            if ($mfaPolicy) {
                Write-Pass "Conditional Access policy requiring MFA for all users found"
                Add-Result "5.1.2" "MFA enabled for all users" "PASS" "CA policy with MFA found"
            } else {
                # Check if security defaults are on (which enforce MFA)
                $secDef = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue
                if ($secDef -and $secDef.IsEnabled) {
                    Write-Pass "Security defaults enforce MFA for all users"
                    Add-Result "5.1.2" "MFA enabled for all users" "PASS" "Security defaults enabled (enforces MFA)"
                } else {
                    Write-Warn "No Conditional Access policy requiring MFA for all users found"
                    Write-Info "Verify MFA enforcement via per-user MFA or Conditional Access manually"
                    Add-Result "5.1.2" "MFA enabled for all users" "WARN" "No CA policy with MFA for all users detected"
                }
            }
        } catch {
            Write-Warn "Could not check MFA: $($_.Exception.Message)"
            Add-Result "5.1.2" "MFA enabled for all users" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-5_3_3 {
    Invoke-Check "5.3.3" "Ensure User Access Administrator role not assigned at root scope" {
        try {
            $assignments = Get-AzRoleAssignment -RoleDefinitionName "User Access Administrator" -Scope "/" -ErrorAction SilentlyContinue
            if (-not $assignments -or @($assignments).Count -eq 0) {
                Write-Pass "No User Access Administrator assignments at root scope"
                Add-Result "5.3.3" "User Access Admin at root scope" "PASS" "No assignments at root scope"
            } else {
                foreach ($a in $assignments) {
                    Write-Fail "User Access Administrator at root scope: $($a.DisplayName) ($($a.SignInName))"
                }
                Add-Result "5.3.3" "User Access Admin at root scope" "FAIL" "$(@($assignments).Count) assignment(s) at root scope"
            }
        } catch {
            Write-Warn "Error checking root scope role assignments: $($_.Exception.Message)"
            Add-Result "5.3.3" "User Access Admin at root scope" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-5_4 {
    Invoke-Check "5.4" "Ensure non-admin users cannot create tenants" {
        try {
            $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
            $allowed = $authPolicy.DefaultUserRolePermissions.AllowedToCreateTenants
            if ($allowed -eq $false) {
                Write-Pass "Users cannot create tenants"
                Add-Result "5.4" "Users cannot create tenants" "PASS" "AllowedToCreateTenants: False"
            } else {
                Write-Fail "Users CAN create tenants"
                Add-Result "5.4" "Users cannot create tenants" "FAIL" "AllowedToCreateTenants: $allowed"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "5.4" "Users cannot create tenants" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-5_14 {
    Invoke-Check "5.14" "Ensure users cannot register applications" {
        try {
            $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
            $allowed = $authPolicy.DefaultUserRolePermissions.AllowedToCreateApps
            if ($allowed -eq $false) {
                Write-Pass "Users cannot register applications"
                Add-Result "5.14" "Users cannot register apps" "PASS" "AllowedToCreateApps: False"
            } else {
                Write-Fail "Users CAN register applications"
                Add-Result "5.14" "Users cannot register apps" "FAIL" "AllowedToCreateApps: $allowed"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "5.14" "Users cannot register apps" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-5_15 {
    Invoke-Check "5.15" "Ensure guest user access is restricted" {
        try {
            $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
            $guestRoleId = $authPolicy.GuestUserRoleId
            # 2af84b1e-32c8-42b7-82bc-daa82404023b = restricted to own directory objects
            $restrictedGuid = "2af84b1e-32c8-42b7-82bc-daa82404023b"
            if ($guestRoleId -eq $restrictedGuid) {
                Write-Pass "Guest user access is restricted to own directory objects"
                Add-Result "5.15" "Guest user access restricted" "PASS" "GuestUserRoleId: $restrictedGuid"
            } else {
                Write-Fail "Guest user access is NOT fully restricted (GuestUserRoleId: $guestRoleId)"
                Add-Result "5.15" "Guest user access restricted" "FAIL" "GuestUserRoleId: $guestRoleId"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "5.15" "Guest user access restricted" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-5_16 {
    Invoke-Check "5.16" "Ensure guest invite restrictions are configured" {
        try {
            $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
            $inviteSetting = $authPolicy.AllowInvitesFrom
            if ($inviteSetting -in @("adminsAndGuestInviters", "none")) {
                Write-Pass "Guest invite restricted to: $inviteSetting"
                Add-Result "5.16" "Guest invite restrictions" "PASS" "AllowInvitesFrom: $inviteSetting"
            } else {
                Write-Fail "Guest invite setting is too permissive: $inviteSetting"
                Add-Result "5.16" "Guest invite restrictions" "FAIL" "AllowInvitesFrom: $inviteSetting"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "5.16" "Guest invite restrictions" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-5_23 {
    Invoke-Check "5.23" "Ensure no custom subscription admin roles exist" {
        try {
            $customRoles = Get-AzRoleDefinition -Custom $true -ErrorAction SilentlyContinue
            if (-not $customRoles) {
                Write-Pass "No custom role definitions found"
                Add-Result "5.23" "No custom sub admin roles" "PASS" "No custom roles"
                return
            }
            $overprivileged = @()
            foreach ($role in $customRoles) {
                if ($role.Actions -contains "*") {
                    $subScope = $role.AssignableScopes | Where-Object { $_ -match "/subscriptions/" -or $_ -eq "/" }
                    if ($subScope) {
                        $overprivileged += $role
                        Write-Fail "Custom role '$($role.Name)' has wildcard (*) action at subscription scope"
                    }
                }
            }
            if ($overprivileged.Count -eq 0) {
                Write-Pass "No overprivileged custom subscription admin roles found"
                Add-Result "5.23" "No custom sub admin roles" "PASS" "No wildcard custom roles at subscription scope"
            } else {
                Add-Result "5.23" "No custom sub admin roles" "FAIL" "$($overprivileged.Count) overprivileged custom role(s)"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "5.23" "No custom sub admin roles" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-5_27 {
    Invoke-Check "5.27" "Ensure between 2 and 3 subscription owners" {
        try {
            $owners = @(Get-AzRoleAssignment -RoleDefinitionName "Owner" `
                -Scope "/subscriptions/$SubscriptionId" -ErrorAction SilentlyContinue |
                Where-Object { $_.Scope -eq "/subscriptions/$SubscriptionId" })
            $count = $owners.Count
            if ($count -ge 2 -and $count -le 3) {
                Write-Pass "Subscription has $count Owner(s) (within 2-3 range)"
                Add-Result "5.27" "2-3 subscription owners" "PASS" "Owner count: $count"
            } elseif ($count -lt 2) {
                Write-Fail "Subscription has only $count Owner(s) - should be at least 2"
                Add-Result "5.27" "2-3 subscription owners" "FAIL" "Owner count: $count (too few)"
            } else {
                Write-Fail "Subscription has $count Owner(s) - should be at most 3"
                Add-Result "5.27" "2-3 subscription owners" "FAIL" "Owner count: $count (too many)"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "5.27" "2-3 subscription owners" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}
# ===============================================================================
#  SECTION 6 - LOGGING & MONITORING
# ===============================================================================
function Check-6_1_1_1 {
    Invoke-Check "6.1.1.1" "Ensure Diagnostic Setting exists for subscription" {
        try {
            $diagSettings = Get-AzSubscriptionDiagnosticSetting -ErrorAction Stop
            if ($diagSettings -and @($diagSettings).Count -gt 0) {
                Write-Pass "Subscription diagnostic setting(s) found: $(@($diagSettings).Count)"
                Add-Result "6.1.1.1" "Subscription diagnostic setting exists" "PASS" "$(@($diagSettings).Count) setting(s) found"
            } else {
                Write-Fail "No diagnostic settings configured for the subscription"
                Add-Result "6.1.1.1" "Subscription diagnostic setting exists" "FAIL" "No diagnostic settings"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.1.1" "Subscription diagnostic setting exists" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-6_1_1_2 {
    Invoke-Check "6.1.1.2" "Ensure Diagnostic Setting captures appropriate categories" {
        try {
            $diagSettings = Get-AzSubscriptionDiagnosticSetting -ErrorAction Stop
            if (-not $diagSettings) {
                Write-Fail "No subscription diagnostic settings to evaluate"
                Add-Result "6.1.1.2" "Diagnostic categories" "FAIL" "No diagnostic settings"
                return
            }
            $requiredCategories = @("Administrative", "Alert", "Policy", "Security")
            $allCovered = $true
            foreach ($cat in $requiredCategories) {
                $found = $false
                foreach ($ds in $diagSettings) {
                    $enabledCats = @($ds.Log | Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty Category)
                    # Also check CategoryGroup for 'allLogs' or 'audit'
                    $enabledGroups = @($ds.Log | Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty CategoryGroup -ErrorAction SilentlyContinue)
                    if ($cat -in $enabledCats -or "allLogs" -in $enabledGroups -or "audit" -in $enabledGroups) {
                        $found = $true; break
                    }
                }
                if (-not $found) {
                    Write-Fail "Required category '$cat' is not captured"
                    $allCovered = $false
                }
            }
            if ($allCovered) {
                Write-Pass "All required categories (Administrative, Alert, Policy, Security) are captured"
                Add-Result "6.1.1.2" "Diagnostic categories" "PASS" "All required categories enabled"
            } else {
                Add-Result "6.1.1.2" "Diagnostic categories" "FAIL" "Missing required log categories"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.1.2" "Diagnostic categories" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-6_1_1_4 {
    Invoke-Check "6.1.1.4" "Ensure Key Vault logging is enabled" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            if ($vaults.Count -eq 0) {
                Write-Info "No Key Vaults found - check not applicable"
                Add-Result "6.1.1.4" "Key Vault logging" "INFO" "No Key Vaults found"
                return
            }
            $allGood = $true
            foreach ($kv in $vaults) {
                $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName -ErrorAction SilentlyContinue
                if (-not $kvDetail) { continue }
                $diag = Get-AzDiagnosticSetting -ResourceId $kvDetail.ResourceId -ErrorAction SilentlyContinue
                if (-not $diag) {
                    Write-Fail "No diagnostic settings for Key Vault '$($kv.VaultName)'"
                    $allGood = $false
                } else {
                    $auditEnabled = $diag | ForEach-Object {
                        $_.Log | Where-Object { $_.Enabled -eq $true -and ($_.Category -eq "AuditEvent" -or $_.CategoryGroup -eq "allLogs" -or $_.CategoryGroup -eq "audit") }
                    }
                    if ($auditEnabled) {
                        Write-Pass "Key Vault '$($kv.VaultName)' has audit logging enabled"
                    } else {
                        Write-Fail "Key Vault '$($kv.VaultName)' audit logging is NOT enabled"
                        $allGood = $false
                    }
                }
            }
            if ($allGood) {
                Add-Result "6.1.1.4" "Key Vault logging" "PASS" "All Key Vaults have logging enabled"
            } else {
                Add-Result "6.1.1.4" "Key Vault logging" "FAIL" "One or more Key Vaults missing logging"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.1.4" "Key Vault logging" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-6_1_1_6 {
    Invoke-Check "6.1.1.6" "Ensure App Service HTTP logs are enabled" {
        try {
            $webApps = @(Get-AzWebApp -ErrorAction SilentlyContinue)
            if ($webApps.Count -eq 0) {
                Write-Info "No App Services found - check not applicable"
                Add-Result "6.1.1.6" "App Service HTTP logs" "INFO" "No App Services found"
                return
            }
            $allGood = $true
            foreach ($app in $webApps) {
                $diag = Get-AzDiagnosticSetting -ResourceId $app.Id -ErrorAction SilentlyContinue
                if (-not $diag) {
                    Write-Fail "No diagnostic settings for App Service '$($app.Name)'"
                    $allGood = $false
                    continue
                }
                $httpLogEnabled = $diag | ForEach-Object {
                    $_.Log | Where-Object { $_.Enabled -eq $true -and ($_.Category -eq "AppServiceHTTPLogs" -or $_.CategoryGroup -eq "allLogs") }
                }
                if ($httpLogEnabled) {
                    Write-Pass "App Service '$($app.Name)' has HTTP logs enabled"
                } else {
                    Write-Fail "App Service '$($app.Name)' HTTP logs NOT enabled"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "6.1.1.6" "App Service HTTP logs" "PASS" "All App Services have HTTP logs"
            } else {
                Add-Result "6.1.1.6" "App Service HTTP logs" "FAIL" "One or more App Services missing HTTP logs"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.1.6" "App Service HTTP logs" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

# -- Activity Log Alert checks (6.1.2.1 through 6.1.2.10) -----------------------
function Check-6_1_2_1  { Check-ActivityLogAlert "6.1.2.1"  "Alert for Create Policy Assignment"         "Microsoft.Authorization/policyAssignments/write" }
function Check-6_1_2_2  { Check-ActivityLogAlert "6.1.2.2"  "Alert for Delete Policy Assignment"         "Microsoft.Authorization/policyAssignments/delete" }
function Check-6_1_2_3  { Check-ActivityLogAlert "6.1.2.3"  "Alert for Create/Update NSG"                "Microsoft.Network/networkSecurityGroups/write" }
function Check-6_1_2_4  { Check-ActivityLogAlert "6.1.2.4"  "Alert for Delete NSG"                       "Microsoft.Network/networkSecurityGroups/delete" }
function Check-6_1_2_5  { Check-ActivityLogAlert "6.1.2.5"  "Alert for Create/Update Security Solution"  "Microsoft.Security/securitySolutions/write" }
function Check-6_1_2_6  { Check-ActivityLogAlert "6.1.2.6"  "Alert for Delete Security Solution"         "Microsoft.Security/securitySolutions/delete" }
function Check-6_1_2_7  { Check-ActivityLogAlert "6.1.2.7"  "Alert for Create/Update SQL Firewall Rule"  "Microsoft.Sql/servers/firewallRules/write" }
function Check-6_1_2_8  { Check-ActivityLogAlert "6.1.2.8"  "Alert for Delete SQL Firewall Rule"         "Microsoft.Sql/servers/firewallRules/delete" }
function Check-6_1_2_9  { Check-ActivityLogAlert "6.1.2.9"  "Alert for Create/Update Public IP"          "Microsoft.Network/publicIPAddresses/write" }
function Check-6_1_2_10 { Check-ActivityLogAlert "6.1.2.10" "Alert for Delete Public IP"                 "Microsoft.Network/publicIPAddresses/delete" }

function Check-6_1_2_11 {
    Invoke-Check "6.1.2.11" "Ensure Activity Log Alert for Service Health" {
        try {
            $alerts = Get-AzActivityLogAlert -ErrorAction SilentlyContinue
            if (-not $alerts) {
                Write-Fail "No Activity Log Alerts configured"
                Add-Result "6.1.2.11" "Service Health alert" "FAIL" "No Activity Log Alerts found"
                return
            }
            $found = $false
            foreach ($alert in $alerts) {
                if (-not $alert.Enabled) { continue }
                $conditions = $alert.ConditionAllOf
                foreach ($cond in $conditions) {
                    if ($cond.Field -eq "category" -and $cond.Equal -eq "ServiceHealth") {
                        $found = $true; break
                    }
                }
                if ($found) { break }
            }
            if ($found) {
                Write-Pass "Activity Log Alert for Service Health exists"
                Add-Result "6.1.2.11" "Service Health alert" "PASS" "ServiceHealth alert found"
            } else {
                Write-Fail "No Activity Log Alert for Service Health"
                Add-Result "6.1.2.11" "Service Health alert" "FAIL" "No ServiceHealth alert"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.2.11" "Service Health alert" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-6_1_3_1 {
    Invoke-Check "6.1.3.1" "Ensure Application Insights is configured (on all App Services / Function Apps)" {
        try {
            $appInsights = @(Get-AzResource -ResourceType "Microsoft.Insights/components" -ErrorAction SilentlyContinue)
            Write-Info "Application Insights components in subscription: $($appInsights.Count)"

            # Collect App Services (web apps) and Function Apps to verify coverage
            $webApps = @(Get-AzResource -ResourceType "Microsoft.Web/sites" -ErrorAction SilentlyContinue)
            if ($webApps.Count -eq 0) {
                if ($appInsights.Count -gt 0) {
                    Write-Pass "No App Services/Function Apps to evaluate; $($appInsights.Count) Application Insights resource(s) exist"
                    Add-Result "6.1.3.1" "Application Insights configured" "PASS" "$($appInsights.Count) AI components; no web/function apps"
                } else {
                    Write-Info "No Application Insights resources and no App Services/Function Apps - check not applicable"
                    Add-Result "6.1.3.1" "Application Insights configured" "INFO" "No AI components and no web/function apps"
                }
                return
            }

            $allGood = $true
            $missing = @()
            foreach ($app in $webApps) {
                try {
                    $detail = Get-AzResource -ResourceId $app.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                    # Fetch app settings (these hold the AI instrumentation wiring)
                    $settings = @{}
                    try {
                        $slot = Invoke-AzResourceAction -ResourceId "$($app.ResourceId)/config/appsettings" -Action list -Force -ErrorAction SilentlyContinue
                        if ($slot -and $slot.properties) {
                            foreach ($k in $slot.properties.PSObject.Properties.Name) { $settings[$k] = $slot.properties.$k }
                        }
                    } catch { }
                    $hasKey = $settings.ContainsKey("APPINSIGHTS_INSTRUMENTATIONKEY") -and -not [string]::IsNullOrWhiteSpace($settings["APPINSIGHTS_INSTRUMENTATIONKEY"])
                    $hasCs  = $settings.ContainsKey("APPLICATIONINSIGHTS_CONNECTION_STRING") -and -not [string]::IsNullOrWhiteSpace($settings["APPLICATIONINSIGHTS_CONNECTION_STRING"])
                    if ($hasKey -or $hasCs) {
                        Write-Pass "App '$($app.Name)' [$($app.ResourceGroupName)] has Application Insights configured"
                    } else {
                        Write-Fail "App '$($app.Name)' [$($app.ResourceGroupName)] is NOT configured with Application Insights"
                        $missing += "$($app.ResourceGroupName)/$($app.Name)"
                        $allGood = $false
                    }
                } catch {
                    Write-Warn "Could not evaluate app '$($app.Name)': $($_.Exception.Message)"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "6.1.3.1" "Application Insights configured" "PASS" "All $($webApps.Count) App Services/Function Apps configured with AI"
            } else {
                Add-Result "6.1.3.1" "Application Insights configured" "FAIL" "Missing AI on: $($missing -join '; ')"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.3.1" "Application Insights configured" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-6_1_1_3 {
    Invoke-Check "6.1.1.3" "Ensure storage account for Activity Log export uses CMK encryption" {
        try {
            $diagSettings = @(Get-AzSubscriptionDiagnosticSetting -ErrorAction SilentlyContinue)
            $storageIds = @($diagSettings | Where-Object { $_.StorageAccountId } | Select-Object -ExpandProperty StorageAccountId -Unique)
            if ($storageIds.Count -eq 0) {
                Write-Info "No subscription diagnostic setting exports to storage - check not applicable"
                Add-Result "6.1.1.3" "Activity Log storage CMK" "INFO" "No storage-based activity log export"
                return
            }
            $allGood = $true
            foreach ($sid in $storageIds) {
                $sa = Get-AzResource -ResourceId $sid -ExpandProperties -ErrorAction SilentlyContinue
                if (-not $sa) {
                    Write-Warn "Could not resolve storage account: $sid"
                    $allGood = $false; continue
                }
                $keySource = $sa.Properties.encryption.keySource
                if ($keySource -eq "Microsoft.Keyvault") {
                    Write-Pass "Storage account '$($sa.Name)' uses customer-managed key (Key Vault)"
                } else {
                    Write-Fail "Storage account '$($sa.Name)' uses '$keySource' (expected Microsoft.Keyvault / CMK)"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "6.1.1.3" "Activity Log storage CMK" "PASS" "All activity log storage accounts use CMK"
            } else {
                Add-Result "6.1.1.3" "Activity Log storage CMK" "FAIL" "One or more storage accounts not using CMK"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.1.3" "Activity Log storage CMK" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-6_1_1_5 {
    Invoke-Check "6.1.1.5" "Ensure NSG flow logs are captured and sent to Log Analytics (all NSGs)" {
        try {
            $allNSGs = @(Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue)
            if ($allNSGs.Count -eq 0) {
                Write-Info "No NSGs found - check not applicable"
                Add-Result "6.1.1.5" "NSG flow logs to Log Analytics" "INFO" "No NSGs found"
                return
            }
            $watchers = @(Get-AzNetworkWatcher -ErrorAction SilentlyContinue)
            $allFlowLogs = @()
            foreach ($watcher in $watchers) {
                $allFlowLogs += @(Get-AzNetworkWatcherFlowLog -NetworkWatcher $watcher -ErrorAction SilentlyContinue)
            }
            $nsgFlowLogs = @($allFlowLogs | Where-Object { $_.TargetResourceId -match "Microsoft.Network/networkSecurityGroups" })
            $allGood = $true
            foreach ($nsg in $allNSGs) {
                $fl = $nsgFlowLogs | Where-Object { $_.TargetResourceId.ToLower() -eq $nsg.Id.ToLower() } | Select-Object -First 1
                if (-not $fl) {
                    Write-Fail "NSG '$($nsg.Name)' has NO flow log configured"
                    $allGood = $false; continue
                }
                $taEnabled = $false
                $wsId = $null
                if ($fl.FlowAnalyticsConfiguration -and $fl.FlowAnalyticsConfiguration.NetworkWatcherFlowAnalyticsConfiguration) {
                    $ta = $fl.FlowAnalyticsConfiguration.NetworkWatcherFlowAnalyticsConfiguration
                    $taEnabled = $ta.Enabled
                    $wsId = $ta.WorkspaceResourceId
                }
                if ($taEnabled -and $wsId) {
                    Write-Pass "NSG '$($nsg.Name)' flow log → Log Analytics workspace"
                } else {
                    Write-Fail "NSG '$($nsg.Name)' flow log exists but Traffic Analytics / Log Analytics not enabled"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "6.1.1.5" "NSG flow logs to Log Analytics" "PASS" "All $($allNSGs.Count) NSGs send flow logs to Log Analytics"
            } else {
                Add-Result "6.1.1.5" "NSG flow logs to Log Analytics" "FAIL" "One or more NSGs missing flow log or Log Analytics sink"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.1.5" "NSG flow logs to Log Analytics" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-6_1_1_7 {
    Invoke-Check "6.1.1.7" "Ensure VNet flow logs are captured and sent to Log Analytics (all VNets)" {
        try {
            $allVNets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)
            if ($allVNets.Count -eq 0) {
                Write-Info "No VNets found - check not applicable"
                Add-Result "6.1.1.7" "VNet flow logs to Log Analytics" "INFO" "No VNets found"
                return
            }
            $watchers = @(Get-AzNetworkWatcher -ErrorAction SilentlyContinue)
            $allFlowLogs = @()
            foreach ($watcher in $watchers) {
                $allFlowLogs += @(Get-AzNetworkWatcherFlowLog -NetworkWatcher $watcher -ErrorAction SilentlyContinue)
            }
            $vnetFlowLogs = @($allFlowLogs | Where-Object { $_.TargetResourceId -match "Microsoft.Network/virtualNetworks" })
            $allGood = $true
            foreach ($vnet in $allVNets) {
                $fl = $vnetFlowLogs | Where-Object { $_.TargetResourceId.ToLower() -eq $vnet.Id.ToLower() } | Select-Object -First 1
                if (-not $fl) {
                    Write-Fail "VNet '$($vnet.Name)' (RG: $($vnet.ResourceGroupName)) has NO VNet flow log"
                    $allGood = $false; continue
                }
                $taEnabled = $false
                $wsId = $null
                if ($fl.FlowAnalyticsConfiguration -and $fl.FlowAnalyticsConfiguration.NetworkWatcherFlowAnalyticsConfiguration) {
                    $ta = $fl.FlowAnalyticsConfiguration.NetworkWatcherFlowAnalyticsConfiguration
                    $taEnabled = $ta.Enabled
                    $wsId = $ta.WorkspaceResourceId
                }
                if ($taEnabled -and $wsId) {
                    Write-Pass "VNet '$($vnet.Name)' flow log → Log Analytics workspace"
                } else {
                    Write-Fail "VNet '$($vnet.Name)' flow log exists but Traffic Analytics / Log Analytics not enabled"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "6.1.1.7" "VNet flow logs to Log Analytics" "PASS" "All $($allVNets.Count) VNets send flow logs to Log Analytics"
            } else {
                Add-Result "6.1.1.7" "VNet flow logs to Log Analytics" "FAIL" "One or more VNets missing flow log or Log Analytics sink"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.1.7" "VNet flow logs to Log Analytics" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-6_1_1_8 {
    Invoke-Check "6.1.1.8" "Ensure Entra diagnostic setting exists for Microsoft Graph activity logs" {
        try {
            # Tenant-scoped Azure AD diagnostic settings (Graph activity logs are a category under AAD diagnostic)
            $uri = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"
            $resp = Invoke-AzRestMethod -Uri $uri -Method GET -ErrorAction SilentlyContinue
            if (-not $resp -or $resp.StatusCode -ne 200) {
                Write-Warn "Unable to query tenant diagnostic settings (status: $($resp.StatusCode))"
                Add-Result "6.1.1.8" "Entra Graph activity diagnostic" "WARN" "Could not query tenant diag settings"
                return
            }
            $data = ($resp.Content | ConvertFrom-Json).value
            if (-not $data -or $data.Count -eq 0) {
                Write-Fail "No Entra (AADIAM) diagnostic settings found"
                Add-Result "6.1.1.8" "Entra Graph activity diagnostic" "FAIL" "No AADIAM diagnostic settings"
                return
            }
            $found = $false
            foreach ($ds in $data) {
                $logs = @($ds.properties.logs | Where-Object { $_.enabled -eq $true })
                if ($logs | Where-Object { $_.category -in @("MicrosoftGraphActivityLogs","NetworkAccessTrafficLogs") }) {
                    $found = $true
                    Write-Pass "Diagnostic '$($ds.name)' captures MicrosoftGraphActivityLogs"
                }
            }
            if ($found) {
                Add-Result "6.1.1.8" "Entra Graph activity diagnostic" "PASS" "Graph activity logs captured"
            } else {
                Write-Fail "No AADIAM diagnostic setting has MicrosoftGraphActivityLogs enabled"
                Add-Result "6.1.1.8" "Entra Graph activity diagnostic" "FAIL" "Not captured"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.1.8" "Entra Graph activity diagnostic" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-6_1_1_9 {
    Invoke-Check "6.1.1.9" "Ensure Entra diagnostic setting captures SignIn/Audit activity logs" {
        try {
            $uri = "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview"
            $resp = Invoke-AzRestMethod -Uri $uri -Method GET -ErrorAction SilentlyContinue
            if (-not $resp -or $resp.StatusCode -ne 200) {
                Write-Warn "Unable to query tenant diagnostic settings (status: $($resp.StatusCode))"
                Add-Result "6.1.1.9" "Entra activity diagnostic" "WARN" "Could not query tenant diag settings"
                return
            }
            $data = ($resp.Content | ConvertFrom-Json).value
            if (-not $data -or $data.Count -eq 0) {
                Write-Fail "No Entra (AADIAM) diagnostic settings found"
                Add-Result "6.1.1.9" "Entra activity diagnostic" "FAIL" "No AADIAM diagnostic settings"
                return
            }
            $required = @("SignInLogs","AuditLogs")
            $missing = @()
            foreach ($cat in $required) {
                $has = $false
                foreach ($ds in $data) {
                    $logs = @($ds.properties.logs | Where-Object { $_.enabled -eq $true -and $_.category -eq $cat })
                    if ($logs.Count -gt 0) { $has = $true; break }
                }
                if (-not $has) { $missing += $cat }
            }
            if ($missing.Count -eq 0) {
                Write-Pass "Entra diagnostic captures SignInLogs and AuditLogs"
                Add-Result "6.1.1.9" "Entra activity diagnostic" "PASS" "SignIn + Audit captured"
            } else {
                Write-Fail "Missing Entra log categories: $($missing -join ', ')"
                Add-Result "6.1.1.9" "Entra activity diagnostic" "FAIL" "Missing: $($missing -join ', ')"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "6.1.1.9" "Entra activity diagnostic" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-6_1_1_10 {
    Invoke-Check "6.1.1.10" "Ensure Intune logs are captured and sent to Log Analytics (Manual)" {
        try {
            # Intune diagnostic settings live under Microsoft.Intune; list via ARM
            $uri = "https://management.azure.com/providers/microsoft.intune/diagnosticSettings?api-version=2017-04-01-preview"
            $resp = Invoke-AzRestMethod -Uri $uri -Method GET -ErrorAction SilentlyContinue
            if (-not $resp -or $resp.StatusCode -ne 200) {
                Write-Warn "Intune diagnostic settings query returned status $($resp.StatusCode) - manual verification required"
                Add-Result "6.1.1.10" "Intune logs to Log Analytics" "WARN" "Manual verification required"
                return
            }
            $data = ($resp.Content | ConvertFrom-Json).value
            if (-not $data -or $data.Count -eq 0) {
                Write-Fail "No Intune diagnostic settings found"
                Add-Result "6.1.1.10" "Intune logs to Log Analytics" "FAIL" "None configured"
                return
            }
            $laFound = $false
            foreach ($ds in $data) {
                if ($ds.properties.workspaceId) {
                    Write-Pass "Intune diagnostic '$($ds.name)' → Log Analytics workspace"
                    $laFound = $true
                }
            }
            if ($laFound) {
                Add-Result "6.1.1.10" "Intune logs to Log Analytics" "PASS" "Intune logs sent to LAW"
            } else {
                Write-Fail "Intune diagnostic settings exist but none target Log Analytics"
                Add-Result "6.1.1.10" "Intune logs to Log Analytics" "FAIL" "No LAW destination"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message) - manual verification required"
            Add-Result "6.1.1.10" "Intune logs to Log Analytics" "WARN" "Manual verification"
        }
    }
}
# ===============================================================================
#  SECTION 7 - NETWORKING
# ===============================================================================
function Check-7_1 {
    param([object[]]$NSGs)
    Check-NSGPortFromInternet -Section "7.1" -Title "Ensure RDP (port 3389) not allowed from Internet" -Ports @(3389) -NSGs $NSGs
}

function Check-7_2 {
    param([object[]]$NSGs)
    Check-NSGPortFromInternet -Section "7.2" -Title "Ensure SSH (port 22) not allowed from Internet" -Ports @(22) -NSGs $NSGs
}

function Check-7_3 {
    param([object[]]$NSGs)
    Check-NSGPortFromInternet -Section "7.3" -Title "Ensure UDP services not allowed from Internet" -Ports @(53, 123, 161, 389, 1900) -NSGs $NSGs
}

function Check-7_4 {
    param([object[]]$NSGs)
    Check-NSGPortFromInternet -Section "7.4" -Title "Ensure HTTP/S (80,443) access restricted from Internet" -Ports @(80, 443) -NSGs $NSGs
}

function Check-7_5 {
    Invoke-Check "7.5" "Ensure NSG flow log retention >= 90 days (all NSGs covered)" {
        try {
            $watchers = @(Get-AzNetworkWatcher -ErrorAction SilentlyContinue)
            if ($watchers.Count -eq 0) {
                Write-Warn "No Network Watchers found - cannot check flow logs"
                Add-Result "7.5" "NSG flow log retention >= 90 days" "WARN" "No Network Watchers"
                return
            }
            $allNSGs = @(Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue)
            $allFlowLogs = @()
            foreach ($watcher in $watchers) {
                $allFlowLogs += @(Get-AzNetworkWatcherFlowLog -NetworkWatcher $watcher -ErrorAction SilentlyContinue)
            }
            $nsgFlowLogs = @($allFlowLogs | Where-Object { $_.TargetResourceId -match "Microsoft.Network/networkSecurityGroups" })
            $allGood = $true
            # 1) retention check on each existing NSG flow log
            foreach ($fl in $nsgFlowLogs) {
                $retEnabled = $fl.RetentionPolicy.Enabled
                $retDays    = $fl.RetentionPolicy.Days
                if ($retEnabled -and $retDays -ge 90) {
                    Write-Pass "Flow log '$($fl.Name)' retention: $retDays days"
                } else {
                    Write-Fail "Flow log '$($fl.Name)' retention: $retDays days (Enabled: $retEnabled)"
                    $allGood = $false
                }
            }
            # 2) coverage check - every NSG must have a flow log
            $coveredIds = @($nsgFlowLogs | Select-Object -ExpandProperty TargetResourceId) | ForEach-Object { $_.ToLower() }
            $uncovered = @($allNSGs | Where-Object { $_.Id.ToLower() -notin $coveredIds })
            foreach ($nsg in $uncovered) {
                Write-Fail "NSG '$($nsg.Name)' (RG: $($nsg.ResourceGroupName)) has NO flow log configured"
                $allGood = $false
            }
            if ($nsgFlowLogs.Count -eq 0 -and $allNSGs.Count -eq 0) {
                Write-Info "No NSGs and no flow logs - check not applicable"
                Add-Result "7.5" "NSG flow log retention >= 90 days" "INFO" "No NSGs found"
            } elseif ($allGood) {
                Add-Result "7.5" "NSG flow log retention >= 90 days" "PASS" "All $($allNSGs.Count) NSGs have flow logs >=90d retention"
            } else {
                Add-Result "7.5" "NSG flow log retention >= 90 days" "FAIL" "$($uncovered.Count) NSG(s) without flow log; retention issues on existing logs"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.5" "NSG flow log retention >= 90 days" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_6 {
    Invoke-Check "7.6" "Ensure Network Watcher enabled for regions in use" {
        try {
            $resources = @(Get-AzResource -ErrorAction SilentlyContinue)
            $usedLocations = @($resources | Select-Object -ExpandProperty Location -Unique | Where-Object { $_ })
            if ($usedLocations.Count -eq 0) {
                Write-Info "No resources found - check not applicable"
                Add-Result "7.6" "Network Watcher for all regions" "INFO" "No resources found"
                return
            }
            $watchers = @(Get-AzNetworkWatcher -ErrorAction SilentlyContinue)
            $watcherLocations = @($watchers | Select-Object -ExpandProperty Location)
            $missing = @()
            foreach ($loc in $usedLocations) {
                if ($loc -notin $watcherLocations) {
                    $missing += $loc
                }
            }
            if ($missing.Count -eq 0) {
                Write-Pass "Network Watcher enabled in all $($usedLocations.Count) regions with resources"
                Add-Result "7.6" "Network Watcher for all regions" "PASS" "All regions covered"
            } else {
                foreach ($m in $missing) { Write-Fail "No Network Watcher in region: $m" }
                Add-Result "7.6" "Network Watcher for all regions" "FAIL" "Missing in: $($missing -join ', ')"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.6" "Network Watcher for all regions" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_8 {
    Invoke-Check "7.8" "Ensure VNet flow log retention >= 90 days (all VNets covered)" {
        try {
            $watchers = @(Get-AzNetworkWatcher -ErrorAction SilentlyContinue)
            if ($watchers.Count -eq 0) {
                Write-Warn "No Network Watchers found"
                Add-Result "7.8" "VNet flow log retention >= 90 days" "WARN" "No Network Watchers"
                return
            }
            $allVNets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)
            $allFlowLogs = @()
            foreach ($watcher in $watchers) {
                $allFlowLogs += @(Get-AzNetworkWatcherFlowLog -NetworkWatcher $watcher -ErrorAction SilentlyContinue)
            }
            $vnetFlowLogs = @($allFlowLogs | Where-Object { $_.TargetResourceId -match "Microsoft.Network/virtualNetworks" })
            $allGood = $true
            # 1) retention check on each existing VNet flow log
            foreach ($fl in $vnetFlowLogs) {
                $retEnabled = $fl.RetentionPolicy.Enabled
                $retDays    = $fl.RetentionPolicy.Days
                if ($retEnabled -and $retDays -ge 90) {
                    Write-Pass "VNet flow log '$($fl.Name)' retention: $retDays days"
                } else {
                    Write-Fail "VNet flow log '$($fl.Name)' retention: $retDays days (Enabled: $retEnabled)"
                    $allGood = $false
                }
            }
            # 2) coverage check - every VNet must have a flow log
            $coveredIds = @($vnetFlowLogs | Select-Object -ExpandProperty TargetResourceId) | ForEach-Object { $_.ToLower() }
            $uncovered = @($allVNets | Where-Object { $_.Id.ToLower() -notin $coveredIds })
            foreach ($vnet in $uncovered) {
                Write-Fail "VNet '$($vnet.Name)' (RG: $($vnet.ResourceGroupName)) has NO VNet flow log configured"
                $allGood = $false
            }
            if ($allVNets.Count -eq 0 -and $vnetFlowLogs.Count -eq 0) {
                Write-Info "No VNets found - check not applicable"
                Add-Result "7.8" "VNet flow log retention >= 90 days" "INFO" "No VNets found"
            } elseif ($allGood) {
                Add-Result "7.8" "VNet flow log retention >= 90 days" "PASS" "All $($allVNets.Count) VNets have flow logs >=90d retention"
            } else {
                Add-Result "7.8" "VNet flow log retention >= 90 days" "FAIL" "$($uncovered.Count) VNet(s) without flow log; retention issues on existing logs"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.8" "VNet flow log retention >= 90 days" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_10 {
    Invoke-Check "7.10" "Ensure WAF is enabled on Application Gateway" {
        try {
            $gateways = @(Get-AzApplicationGateway -ErrorAction SilentlyContinue)
            if ($gateways.Count -eq 0) {
                Write-Info "No Application Gateways found - check not applicable"
                Add-Result "7.10" "WAF on App Gateway" "INFO" "No Application Gateways"
                return
            }
            $allGood = $true
            foreach ($gw in $gateways) {
                $hasWaf = ($gw.WebApplicationFirewallConfiguration -ne $null) -or ($gw.FirewallPolicy -ne $null)
                if ($hasWaf) {
                    Write-Pass "Application Gateway '$($gw.Name)' has WAF enabled"
                } else {
                    Write-Fail "Application Gateway '$($gw.Name)' does NOT have WAF enabled"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "7.10" "WAF on App Gateway" "PASS" "All gateways have WAF"
            } else {
                Add-Result "7.10" "WAF on App Gateway" "FAIL" "One or more gateways missing WAF"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.10" "WAF on App Gateway" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_11 {
    Invoke-Check "7.11" "Ensure subnets are associated with NSGs" {
        try {
            $vnets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)
            if ($vnets.Count -eq 0) {
                Write-Info "No VNets found - check not applicable"
                Add-Result "7.11" "Subnets with NSGs" "INFO" "No VNets found"
                return
            }
            $excludeSubnets = @("GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet", "AzureFirewallManagementSubnet", "RouteServerSubnet")
            $allGood = $true
            foreach ($vnet in $vnets) {
                foreach ($subnet in $vnet.Subnets) {
                    if ($subnet.Name -in $excludeSubnets) { continue }
                    if (-not $subnet.NetworkSecurityGroup) {
                        Write-Fail "Subnet '$($subnet.Name)' in VNet '$($vnet.Name)' has no NSG"
                        $allGood = $false
                    }
                }
            }
            if ($allGood) {
                Write-Pass "All applicable subnets have NSGs associated"
                Add-Result "7.11" "Subnets with NSGs" "PASS" "All subnets have NSGs"
            } else {
                Add-Result "7.11" "Subnets with NSGs" "FAIL" "One or more subnets missing NSGs"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.11" "Subnets with NSGs" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_12 {
    Invoke-Check "7.12" "Ensure App Gateway SSL policy uses TLS 1.2 minimum" {
        try {
            $gateways = @(Get-AzApplicationGateway -ErrorAction SilentlyContinue)
            if ($gateways.Count -eq 0) {
                Write-Info "No Application Gateways found - check not applicable"
                Add-Result "7.12" "App Gateway TLS 1.2" "INFO" "No Application Gateways"
                return
            }
            $allGood = $true
            foreach ($gw in $gateways) {
                $minTls = $gw.SslPolicy.MinProtocolVersion
                if ($minTls -in @("TLSv1_2", "TLSv1_3")) {
                    Write-Pass "App Gateway '$($gw.Name)' min TLS: $minTls"
                } else {
                    Write-Fail "App Gateway '$($gw.Name)' min TLS: $minTls (should be TLSv1_2 or higher)"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "7.12" "App Gateway TLS 1.2" "PASS" "All gateways use TLS 1.2+"
            } else {
                Add-Result "7.12" "App Gateway TLS 1.2" "FAIL" "One or more gateways below TLS 1.2"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.12" "App Gateway TLS 1.2" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_13 {
    Invoke-Check "7.13" "Ensure HTTP2 is enabled on Application Gateway" {
        try {
            $gateways = @(Get-AzApplicationGateway -ErrorAction SilentlyContinue)
            if ($gateways.Count -eq 0) {
                Write-Info "No Application Gateways found - check not applicable"
                Add-Result "7.13" "App Gateway HTTP2" "INFO" "No Application Gateways"
                return
            }
            $allGood = $true
            foreach ($gw in $gateways) {
                if ($gw.Http2 -eq "Enabled" -or $gw.EnableHttp2 -eq $true) {
                    Write-Pass "App Gateway '$($gw.Name)' has HTTP2 enabled"
                } else {
                    Write-Fail "App Gateway '$($gw.Name)' does NOT have HTTP2 enabled"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "7.13" "App Gateway HTTP2" "PASS" "All gateways have HTTP2"
            } else {
                Add-Result "7.13" "App Gateway HTTP2" "FAIL" "One or more gateways without HTTP2"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.13" "App Gateway HTTP2" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_14 {
    Invoke-Check "7.14" "Ensure WAF request body inspection is enabled" {
        try {
            $policies = @(Get-AzApplicationGatewayFirewallPolicy -ErrorAction SilentlyContinue)
            if ($policies.Count -eq 0) {
                Write-Info "No WAF policies found - check not applicable"
                Add-Result "7.14" "WAF request body inspection" "INFO" "No WAF policies"
                return
            }
            $allGood = $true
            foreach ($pol in $policies) {
                if ($pol.PolicySettings.RequestBodyCheck -eq $true) {
                    Write-Pass "WAF policy '$($pol.Name)' has request body inspection enabled"
                } else {
                    Write-Fail "WAF policy '$($pol.Name)' request body inspection is disabled"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "7.14" "WAF request body inspection" "PASS" "All policies have body inspection"
            } else {
                Add-Result "7.14" "WAF request body inspection" "FAIL" "One or more policies missing body inspection"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.14" "WAF request body inspection" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_15 {
    Invoke-Check "7.15" "Ensure WAF bot protection is enabled" {
        try {
            $policies = @(Get-AzApplicationGatewayFirewallPolicy -ErrorAction SilentlyContinue)
            if ($policies.Count -eq 0) {
                Write-Info "No WAF policies found - check not applicable"
                Add-Result "7.15" "WAF bot protection" "INFO" "No WAF policies"
                return
            }
            $allGood = $true
            foreach ($pol in $policies) {
                $botProtection = $pol.ManagedRules.ManagedRuleSets | Where-Object {
                    $_.RuleSetType -match "Bot" -or $_.RuleSetType -eq "Microsoft_BotManagerRuleSet"
                }
                if ($botProtection) {
                    Write-Pass "WAF policy '$($pol.Name)' has bot protection enabled"
                } else {
                    Write-Fail "WAF policy '$($pol.Name)' is missing bot protection"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "7.15" "WAF bot protection" "PASS" "All policies have bot protection"
            } else {
                Add-Result "7.15" "WAF bot protection" "FAIL" "One or more policies missing bot protection"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.15" "WAF bot protection" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_7 {
    Invoke-Check "7.7" "Ensure Public IP addresses are evaluated on a periodic basis (list all Public IPs)" {
        try {
            $pips = @(Get-AzPublicIpAddress -ErrorAction SilentlyContinue)
            if ($pips.Count -eq 0) {
                Write-Info "No Public IP addresses found"
                Add-Result "7.7" "Public IPs inventory" "INFO" "None found"
                return
            }
            Write-Info "Found $($pips.Count) Public IP address(es). Manual review required:"
            foreach ($ip in $pips) {
                $assoc = if ($ip.IpConfiguration) { "associated" } else { "UNASSOCIATED" }
                $addr  = if ($ip.IpAddress) { $ip.IpAddress } else { "<not assigned>" }
                Write-Info "  - $($ip.Name) [$($ip.ResourceGroupName)] $addr ($($ip.PublicIpAllocationMethod), $assoc)"
            }
            Add-Result "7.7" "Public IPs inventory" "WARN" "$($pips.Count) Public IPs - manual review required"
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.7" "Public IPs inventory" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_9 {
    Invoke-Check "7.9" "Ensure Azure AD authentication is configured on VPN Gateways (all gateways)" {
        try {
            $gatewayResources = @(Get-AzResource -ResourceType "Microsoft.Network/virtualNetworkGateways" -ErrorAction SilentlyContinue)
            if ($gatewayResources.Count -eq 0) {
                Write-Info "No VPN Gateways found - check not applicable"
                Add-Result "7.9" "VPN Gateway AAD auth" "INFO" "No VPN Gateways"
                return
            }
            $gateways = @()
            foreach ($gr in $gatewayResources) {
                $g = Get-AzVirtualNetworkGateway -ResourceGroupName $gr.ResourceGroupName -Name $gr.Name -ErrorAction SilentlyContinue
                if ($g) { $gateways += $g }
            }
            $vpnGateways = @($gateways | Where-Object { $_.GatewayType -eq "Vpn" })
            if ($vpnGateways.Count -eq 0) {
                Write-Info "No VPN Gateways (GatewayType=Vpn) found - check not applicable"
                Add-Result "7.9" "VPN Gateway AAD auth" "INFO" "No VPN Gateways"
                return
            }
            $allGood = $true
            foreach ($vg in $vpnGateways) {
                $vpnClient = $vg.VpnClientConfiguration
                if (-not $vpnClient) {
                    Write-Fail "VPN Gateway '$($vg.Name)' has no P2S VPN client config - AAD auth N/A"
                    $allGood = $false; continue
                }
                $authTypes = @($vpnClient.VpnAuthenticationTypes)
                $aadTenant = $vpnClient.AadTenant
                if ($authTypes -contains "AAD" -and $aadTenant) {
                    Write-Pass "VPN Gateway '$($vg.Name)' uses AAD authentication (tenant: $aadTenant)"
                } else {
                    Write-Fail "VPN Gateway '$($vg.Name)' does NOT use AAD authentication (auth: $($authTypes -join ','))"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "7.9" "VPN Gateway AAD auth" "PASS" "All VPN gateways use AAD auth"
            } else {
                Add-Result "7.9" "VPN Gateway AAD auth" "FAIL" "One or more VPN gateways without AAD auth"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "7.9" "VPN Gateway AAD auth" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-7_16 {
    Invoke-Check "7.16" "Ensure Network Security Perimeter is used to protect PaaS resources (Manual)" {
        try {
            $perimeters = @(Get-AzResource -ResourceType "Microsoft.Network/networkSecurityPerimeters" -ErrorAction SilentlyContinue)
            if ($perimeters.Count -eq 0) {
                Write-Fail "No Network Security Perimeters found in subscription"
                Add-Result "7.16" "Network Security Perimeter" "FAIL" "No NSPs configured"
                return
            }
            Write-Pass "Found $($perimeters.Count) Network Security Perimeter(s). Manual review of associations required:"
            foreach ($p in $perimeters) { Write-Info "  - $($p.Name) [$($p.ResourceGroupName)] ($($p.Location))" }
            Add-Result "7.16" "Network Security Perimeter" "WARN" "$($perimeters.Count) NSP(s) found - manual review of associations required"
        } catch {
            Write-Warn "Error: $($_.Exception.Message) - manual verification required"
            Add-Result "7.16" "Network Security Perimeter" "WARN" "Manual verification"
        }
    }
}
# ===============================================================================
#  SECTION 8 - SECURITY
# ===============================================================================

# -- Defender pricing tier checks (8.1.1.1 through 8.1.9.1) ---------------------
function Check-8_1_1_1 { Check-DefenderPricing "8.1.1.1" "Defender for Cloud Posture (CSPM)"         "CloudPosture" }
function Check-8_1_2_1 { Check-DefenderPricing "8.1.2.1" "Defender for APIs"                         "Api" }
function Check-8_1_3_1 { Check-DefenderPricing "8.1.3.1" "Defender for Virtual Machines"              "VirtualMachines" }
function Check-8_1_4_1 { Check-DefenderPricing "8.1.4.1" "Defender for Containers"                    "Containers" }
function Check-8_1_5_1 { Check-DefenderPricing "8.1.5.1" "Defender for Storage Accounts"              "StorageAccounts" }
function Check-8_1_6_1 { Check-DefenderPricing "8.1.6.1" "Defender for App Services"                  "AppServices" }
function Check-8_1_7_1 { Check-DefenderPricing "8.1.7.1" "Defender for Cosmos DB"                     "CosmosDbs" }
function Check-8_1_7_2 { Check-DefenderPricing "8.1.7.2" "Defender for Open Source Relational DBs"    "OpenSourceRelationalDatabases" }
function Check-8_1_7_3 { Check-DefenderPricing "8.1.7.3" "Defender for SQL Servers"                   "SqlServers" }
function Check-8_1_7_4 { Check-DefenderPricing "8.1.7.4" "Defender for SQL Server VMs"                "SqlServerVirtualMachines" }
function Check-8_1_8_1 { Check-DefenderPricing "8.1.8.1" "Defender for Key Vaults"                    "KeyVaults" }
function Check-8_1_9_1 { Check-DefenderPricing "8.1.9.1" "Defender for ARM"                           "Arm" }

function Check-8_1_3_3 {
    Invoke-Check "8.1.3.3" "Ensure endpoint protection component is enabled" {
        try {
            $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings/VirtualMachines?api-version=2024-01-01"
            $response = Invoke-RestMethod -Uri $uri -Headers @{Authorization = "Bearer $token"} -Method Get -ErrorAction Stop
            $extensions = $response.properties.extensions
            $mde = $extensions | Where-Object { $_.name -eq "MDE.Windows" -or $_.name -eq "MDE.Linux" -or $_.name -eq "MDE" }
            if ($mde) {
                $allEnabled = ($mde | Where-Object { $_.isEnabled -eq "True" -or $_.isEnabled -eq $true }).Count -gt 0
                if ($allEnabled) {
                    Write-Pass "Endpoint protection (MDE) is enabled"
                    Add-Result "8.1.3.3" "Endpoint protection enabled" "PASS" "MDE extension enabled"
                } else {
                    Write-Fail "Endpoint protection (MDE) extension found but NOT enabled"
                    Add-Result "8.1.3.3" "Endpoint protection enabled" "FAIL" "MDE extension disabled"
                }
            } else {
                Write-Fail "Endpoint protection (MDE) extension not found"
                Add-Result "8.1.3.3" "Endpoint protection enabled" "FAIL" "MDE extension not configured"
            }
        } catch {
            Write-Warn "Could not check endpoint protection: $($_.Exception.Message)"
            Add-Result "8.1.3.3" "Endpoint protection enabled" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_1_10 {
    Invoke-Check "8.1.10" "Ensure VM OS updates assessment is enabled" {
        try {
            $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/assessments?api-version=2021-06-01"
            $response = Invoke-RestMethod -Uri $uri -Headers @{Authorization = "Bearer $token"} -Method Get -ErrorAction Stop
            # Look for system updates assessment
            $updateAssessment = $response.value | Where-Object {
                $_.properties.displayName -match "system updates" -or
                $_.properties.displayName -match "System updates should be installed"
            }
            if ($updateAssessment) {
                $unhealthy = @($updateAssessment | Where-Object { $_.properties.status.code -eq "Unhealthy" })
                if ($unhealthy.Count -gt 0) {
                    Write-Fail "$($unhealthy.Count) resource(s) missing system updates"
                    Add-Result "8.1.10" "VM OS updates" "FAIL" "$($unhealthy.Count) resource(s) unhealthy"
                } else {
                    Write-Pass "All resources up to date or assessment healthy"
                    Add-Result "8.1.10" "VM OS updates" "PASS" "Assessment healthy"
                }
            } else {
                Write-Warn "System updates assessment not found - may require Defender for Servers"
                Add-Result "8.1.10" "VM OS updates" "WARN" "Assessment not found"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.1.10" "VM OS updates" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_1_12 {
    Invoke-Check "8.1.12" "Ensure security contact roles include Owner" {
        try {
            $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview"
            $response = Invoke-RestMethod -Uri $uri -Headers @{Authorization = "Bearer $token"} -Method Get -ErrorAction Stop
            $contacts = $response.value
            if (-not $contacts -or $contacts.Count -eq 0) {
                Write-Fail "No security contacts configured"
                Add-Result "8.1.12" "Security contact roles" "FAIL" "No security contacts"
                return
            }
            $ownerNotify = $false
            foreach ($contact in $contacts) {
                $roles = $contact.properties.notificationsByRole
                if ($roles -and $roles.state -eq "On" -and $roles.roles -contains "Owner") {
                    $ownerNotify = $true
                }
            }
            if ($ownerNotify) {
                Write-Pass "Security contact notifications include Owner role"
                Add-Result "8.1.12" "Security contact roles" "PASS" "Owner role notified"
            } else {
                Write-Fail "Security contacts do not notify Owner role"
                Add-Result "8.1.12" "Security contact roles" "FAIL" "Owner role not in notifications"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.1.12" "Security contact roles" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_1_13 {
    Invoke-Check "8.1.13" "Ensure additional email addresses are configured" {
        try {
            $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview"
            $response = Invoke-RestMethod -Uri $uri -Headers @{Authorization = "Bearer $token"} -Method Get -ErrorAction Stop
            $contacts = $response.value
            if (-not $contacts -or $contacts.Count -eq 0) {
                Write-Fail "No security contacts configured"
                Add-Result "8.1.13" "Additional email addresses" "FAIL" "No security contacts"
                return
            }
            $hasEmail = $false
            foreach ($contact in $contacts) {
                $emails = $contact.properties.emails
                if ($emails) { $hasEmail = $true }
            }
            if ($hasEmail) {
                Write-Pass "Additional email addresses are configured"
                Add-Result "8.1.13" "Additional email addresses" "PASS" "Email addresses configured"
            } else {
                Write-Fail "No additional email addresses configured"
                Add-Result "8.1.13" "Additional email addresses" "FAIL" "No emails in security contacts"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.1.13" "Additional email addresses" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_1_14 {
    Invoke-Check "8.1.14" "Ensure notify about alerts with severity is enabled" {
        try {
            $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview"
            $response = Invoke-RestMethod -Uri $uri -Headers @{Authorization = "Bearer $token"} -Method Get -ErrorAction Stop
            $contacts = $response.value
            if (-not $contacts -or $contacts.Count -eq 0) {
                Write-Fail "No security contacts configured"
                Add-Result "8.1.14" "Alert severity notifications" "FAIL" "No security contacts"
                return
            }
            $alertNotifOn = $false
            foreach ($contact in $contacts) {
                $alertNotif = $contact.properties.alertNotifications
                if ($alertNotif -and $alertNotif.state -eq "On" -and $alertNotif.minimalSeverity) {
                    $alertNotifOn = $true
                }
            }
            if ($alertNotifOn) {
                Write-Pass "Alert notifications with severity filtering enabled"
                Add-Result "8.1.14" "Alert severity notifications" "PASS" "Alert notifications on"
            } else {
                Write-Fail "Alert notifications not properly configured"
                Add-Result "8.1.14" "Alert severity notifications" "FAIL" "Alert notifications off or no severity set"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.1.14" "Alert severity notifications" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_1_15 {
    Invoke-Check "8.1.15" "Ensure notify about attack paths is enabled" {
        try {
            $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com").Token
            $uri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview"
            $response = Invoke-RestMethod -Uri $uri -Headers @{Authorization = "Bearer $token"} -Method Get -ErrorAction Stop
            $contacts = $response.value
            if (-not $contacts -or $contacts.Count -eq 0) {
                Write-Fail "No security contacts configured"
                Add-Result "8.1.15" "Attack path notifications" "FAIL" "No security contacts"
                return
            }
            $attackPathNotif = $false
            foreach ($contact in $contacts) {
                $notifSources = $contact.properties.notificationsSources
                if ($notifSources) {
                    $apSource = $notifSources | Where-Object { $_.sourceType -eq "AttackPath" }
                    if ($apSource -and $apSource.minimalRiskLevel) {
                        $attackPathNotif = $true
                    }
                }
            }
            if ($attackPathNotif) {
                Write-Pass "Attack path notifications are enabled"
                Add-Result "8.1.15" "Attack path notifications" "PASS" "Attack path notifications on"
            } else {
                Write-Fail "Attack path notifications not configured"
                Add-Result "8.1.15" "Attack path notifications" "FAIL" "No attack path notification source"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.1.15" "Attack path notifications" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}
# -- Key Vault checks (8.3.x) ---------------------------------------------------
function Check-8_3_1 {
    Invoke-Check "8.3.1" "Ensure key expiration is set (RBAC Key Vaults)" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            $rbacVaults = @($vaults | ForEach-Object { Get-AzKeyVault -VaultName $_.VaultName -ErrorAction SilentlyContinue } | Where-Object { $_.EnableRbacAuthorization -eq $true })
            if ($rbacVaults.Count -eq 0) {
                Write-Info "No RBAC-enabled Key Vaults found - check not applicable"
                Add-Result "8.3.1" "Key expiration (RBAC KVs)" "INFO" "No RBAC Key Vaults"
                return
            }
            $allGood = $true
            foreach ($kv in $rbacVaults) {
                $keys = @(Get-AzKeyVaultKey -VaultName $kv.VaultName -ErrorAction SilentlyContinue)
                foreach ($key in $keys) {
                    if ($key.Enabled -eq $true -and -not $key.Expires) {
                        Write-Fail "Key '$($key.Name)' in vault '$($kv.VaultName)' has no expiration set"
                        $allGood = $false
                    }
                }
            }
            if ($allGood) {
                Write-Pass "All enabled keys in RBAC vaults have expiration set"
                Add-Result "8.3.1" "Key expiration (RBAC KVs)" "PASS" "All keys have expiry"
            } else {
                Add-Result "8.3.1" "Key expiration (RBAC KVs)" "FAIL" "Keys without expiry found"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.3.1" "Key expiration (RBAC KVs)" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_3_2 {
    Invoke-Check "8.3.2" "Ensure key expiration is set (Non-RBAC Key Vaults)" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            $nonRbacVaults = @($vaults | ForEach-Object { Get-AzKeyVault -VaultName $_.VaultName -ErrorAction SilentlyContinue } | Where-Object { $_.EnableRbacAuthorization -ne $true })
            if ($nonRbacVaults.Count -eq 0) {
                Write-Info "No non-RBAC Key Vaults found - check not applicable"
                Add-Result "8.3.2" "Key expiration (Non-RBAC KVs)" "INFO" "No non-RBAC Key Vaults"
                return
            }
            $allGood = $true
            foreach ($kv in $nonRbacVaults) {
                $keys = @(Get-AzKeyVaultKey -VaultName $kv.VaultName -ErrorAction SilentlyContinue)
                foreach ($key in $keys) {
                    if ($key.Enabled -eq $true -and -not $key.Expires) {
                        Write-Fail "Key '$($key.Name)' in vault '$($kv.VaultName)' has no expiration set"
                        $allGood = $false
                    }
                }
            }
            if ($allGood) {
                Write-Pass "All enabled keys in non-RBAC vaults have expiration set"
                Add-Result "8.3.2" "Key expiration (Non-RBAC KVs)" "PASS" "All keys have expiry"
            } else {
                Add-Result "8.3.2" "Key expiration (Non-RBAC KVs)" "FAIL" "Keys without expiry found"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.3.2" "Key expiration (Non-RBAC KVs)" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_3_3 {
    Invoke-Check "8.3.3" "Ensure secret expiration is set (RBAC Key Vaults)" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            $rbacVaults = @($vaults | ForEach-Object { Get-AzKeyVault -VaultName $_.VaultName -ErrorAction SilentlyContinue } | Where-Object { $_.EnableRbacAuthorization -eq $true })
            if ($rbacVaults.Count -eq 0) {
                Write-Info "No RBAC-enabled Key Vaults found - check not applicable"
                Add-Result "8.3.3" "Secret expiration (RBAC KVs)" "INFO" "No RBAC Key Vaults"
                return
            }
            $allGood = $true
            foreach ($kv in $rbacVaults) {
                $secrets = @(Get-AzKeyVaultSecret -VaultName $kv.VaultName -ErrorAction SilentlyContinue)
                foreach ($secret in $secrets) {
                    if ($secret.Enabled -eq $true -and -not $secret.Expires) {
                        Write-Fail "Secret '$($secret.Name)' in vault '$($kv.VaultName)' has no expiration"
                        $allGood = $false
                    }
                }
            }
            if ($allGood) {
                Write-Pass "All enabled secrets in RBAC vaults have expiration set"
                Add-Result "8.3.3" "Secret expiration (RBAC KVs)" "PASS" "All secrets have expiry"
            } else {
                Add-Result "8.3.3" "Secret expiration (RBAC KVs)" "FAIL" "Secrets without expiry found"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.3.3" "Secret expiration (RBAC KVs)" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_3_4 {
    Invoke-Check "8.3.4" "Ensure secret expiration is set (Non-RBAC Key Vaults)" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            $nonRbacVaults = @($vaults | ForEach-Object { Get-AzKeyVault -VaultName $_.VaultName -ErrorAction SilentlyContinue } | Where-Object { $_.EnableRbacAuthorization -ne $true })
            if ($nonRbacVaults.Count -eq 0) {
                Write-Info "No non-RBAC Key Vaults found - check not applicable"
                Add-Result "8.3.4" "Secret expiration (Non-RBAC KVs)" "INFO" "No non-RBAC Key Vaults"
                return
            }
            $allGood = $true
            foreach ($kv in $nonRbacVaults) {
                $secrets = @(Get-AzKeyVaultSecret -VaultName $kv.VaultName -ErrorAction SilentlyContinue)
                foreach ($secret in $secrets) {
                    if ($secret.Enabled -eq $true -and -not $secret.Expires) {
                        Write-Fail "Secret '$($secret.Name)' in vault '$($kv.VaultName)' has no expiration"
                        $allGood = $false
                    }
                }
            }
            if ($allGood) {
                Write-Pass "All enabled secrets in non-RBAC vaults have expiration set"
                Add-Result "8.3.4" "Secret expiration (Non-RBAC KVs)" "PASS" "All secrets have expiry"
            } else {
                Add-Result "8.3.4" "Secret expiration (Non-RBAC KVs)" "FAIL" "Secrets without expiry found"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.3.4" "Secret expiration (Non-RBAC KVs)" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_3_5 {
    Invoke-Check "8.3.5" "Ensure purge protection is enabled for Key Vault" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            if ($vaults.Count -eq 0) {
                Write-Info "No Key Vaults found - check not applicable"
                Add-Result "8.3.5" "KV purge protection" "INFO" "No Key Vaults"
                return
            }
            $allGood = $true
            foreach ($kv in $vaults) {
                $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName -ErrorAction SilentlyContinue
                if ($kvDetail.EnablePurgeProtection -eq $true) {
                    Write-Pass "Key Vault '$($kv.VaultName)' has purge protection enabled"
                } else {
                    Write-Fail "Key Vault '$($kv.VaultName)' does NOT have purge protection"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "8.3.5" "KV purge protection" "PASS" "All vaults have purge protection"
            } else {
                Add-Result "8.3.5" "KV purge protection" "FAIL" "One or more vaults lack purge protection"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.3.5" "KV purge protection" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_3_6 {
    Invoke-Check "8.3.6" "Ensure RBAC is enabled for Key Vault" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            if ($vaults.Count -eq 0) {
                Write-Info "No Key Vaults found - check not applicable"
                Add-Result "8.3.6" "KV RBAC enabled" "INFO" "No Key Vaults"
                return
            }
            $allGood = $true
            foreach ($kv in $vaults) {
                $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName -ErrorAction SilentlyContinue
                if ($kvDetail.EnableRbacAuthorization -eq $true) {
                    Write-Pass "Key Vault '$($kv.VaultName)' uses RBAC authorization"
                } else {
                    Write-Fail "Key Vault '$($kv.VaultName)' does NOT use RBAC authorization"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "8.3.6" "KV RBAC enabled" "PASS" "All vaults use RBAC"
            } else {
                Add-Result "8.3.6" "KV RBAC enabled" "FAIL" "One or more vaults not using RBAC"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.3.6" "KV RBAC enabled" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_3_7 {
    Invoke-Check "8.3.7" "Ensure Public Network Access disabled for Key Vault" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            if ($vaults.Count -eq 0) {
                Write-Info "No Key Vaults found - check not applicable"
                Add-Result "8.3.7" "KV public access disabled" "INFO" "No Key Vaults"
                return
            }
            $allGood = $true
            foreach ($kv in $vaults) {
                $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName -ErrorAction SilentlyContinue
                if ($kvDetail.PublicNetworkAccess -eq "Disabled") {
                    Write-Pass "Key Vault '$($kv.VaultName)' public network access is disabled"
                } else {
                    Write-Fail "Key Vault '$($kv.VaultName)' public network access: $($kvDetail.PublicNetworkAccess)"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "8.3.7" "KV public access disabled" "PASS" "All vaults have public access disabled"
            } else {
                Add-Result "8.3.7" "KV public access disabled" "FAIL" "One or more vaults allow public access"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.3.7" "KV public access disabled" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_3_8 {
    Invoke-Check "8.3.8" "Ensure private endpoints are used for Key Vault" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            if ($vaults.Count -eq 0) {
                Write-Info "No Key Vaults found - check not applicable"
                Add-Result "8.3.8" "KV private endpoints" "INFO" "No Key Vaults"
                return
            }
            $allGood = $true
            foreach ($kv in $vaults) {
                $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName -ErrorAction SilentlyContinue
                $pe = $kvDetail.NetworkAcls.VirtualNetworkRules
                $peConn = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $kvDetail.ResourceId -ErrorAction SilentlyContinue
                if ($peConn -and @($peConn).Count -gt 0) {
                    Write-Pass "Key Vault '$($kv.VaultName)' has private endpoint connections"
                } else {
                    Write-Fail "Key Vault '$($kv.VaultName)' has NO private endpoint connections"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "8.3.8" "KV private endpoints" "PASS" "All vaults have private endpoints"
            } else {
                Add-Result "8.3.8" "KV private endpoints" "FAIL" "One or more vaults lack private endpoints"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.3.8" "KV private endpoints" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_3_9 {
    Invoke-Check "8.3.9" "Ensure auto key rotation is enabled" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            if ($vaults.Count -eq 0) {
                Write-Info "No Key Vaults found - check not applicable"
                Add-Result "8.3.9" "KV auto key rotation" "INFO" "No Key Vaults"
                return
            }
            $allGood = $true
            $keyFound = $false
            foreach ($kv in $vaults) {
                $keys = @(Get-AzKeyVaultKey -VaultName $kv.VaultName -ErrorAction SilentlyContinue)
                foreach ($key in $keys) {
                    $keyFound = $true
                    try {
                        $rotPolicy = Get-AzKeyVaultKeyRotationPolicy -VaultName $kv.VaultName -Name $key.Name -ErrorAction SilentlyContinue
                        $hasRotate = $rotPolicy.LifetimeActions | Where-Object { $_.Action -eq "Rotate" }
                        if ($hasRotate) {
                            Write-Pass "Key '$($key.Name)' in '$($kv.VaultName)' has auto-rotation"
                        } else {
                            Write-Fail "Key '$($key.Name)' in '$($kv.VaultName)' has no auto-rotation policy"
                            $allGood = $false
                        }
                    } catch {
                        Write-Fail "Key '$($key.Name)' in '$($kv.VaultName)' - could not get rotation policy"
                        $allGood = $false
                    }
                }
            }
            if (-not $keyFound) {
                Write-Info "No keys found in any Key Vault - check not applicable"
                Add-Result "8.3.9" "KV auto key rotation" "INFO" "No keys found"
            } elseif ($allGood) {
                Add-Result "8.3.9" "KV auto key rotation" "PASS" "All keys have auto-rotation"
            } else {
                Add-Result "8.3.9" "KV auto key rotation" "FAIL" "One or more keys lack auto-rotation"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.3.9" "KV auto key rotation" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_3_11 {
    Invoke-Check "8.3.11" "Ensure certificate validity is <= 12 months" {
        try {
            $vaults = @(Get-AzKeyVault -ErrorAction SilentlyContinue)
            if ($vaults.Count -eq 0) {
                Write-Info "No Key Vaults found - check not applicable"
                Add-Result "8.3.11" "KV certificate validity" "INFO" "No Key Vaults"
                return
            }
            $allGood = $true
            $certFound = $false
            foreach ($kv in $vaults) {
                $certs = @(Get-AzKeyVaultCertificate -VaultName $kv.VaultName -ErrorAction SilentlyContinue)
                foreach ($cert in $certs) {
                    $certFound = $true
                    try {
                        $policy = Get-AzKeyVaultCertificatePolicy -VaultName $kv.VaultName -Name $cert.Name -ErrorAction SilentlyContinue
                        if ($policy -and $policy.ValidityInMonths -le 12) {
                            Write-Pass "Certificate '$($cert.Name)' validity: $($policy.ValidityInMonths) months"
                        } else {
                            $months = if ($policy) { $policy.ValidityInMonths } else { "unknown" }
                            Write-Fail "Certificate '$($cert.Name)' validity: $months months (should be <= 12)"
                            $allGood = $false
                        }
                    } catch {
                        Write-Warn "Could not check policy for certificate '$($cert.Name)'"
                    }
                }
            }
            if (-not $certFound) {
                Write-Info "No certificates found in any Key Vault - check not applicable"
                Add-Result "8.3.11" "KV certificate validity" "INFO" "No certificates found"
            } elseif ($allGood) {
                Add-Result "8.3.11" "KV certificate validity" "PASS" "All certificates <= 12 months"
            } else {
                Add-Result "8.3.11" "KV certificate validity" "FAIL" "Certificates with > 12 months validity found"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.3.11" "KV certificate validity" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_4_1 {
    Invoke-Check "8.4.1" "Ensure Azure Bastion Host Exists (covers every VNet that has VMs)" {
        try {
            $bastions = @(Get-AzResource -ResourceType "Microsoft.Network/bastionHosts" -ErrorAction SilentlyContinue)
            $vms      = @(Get-AzVM -ErrorAction SilentlyContinue)
            if ($bastions.Count -eq 0 -and $vms.Count -eq 0) {
                Write-Info "No Bastion hosts and no VMs - check not applicable"
                Add-Result "8.4.1" "Azure Bastion exists" "INFO" "No VMs and no Bastion"
                return
            }
            if ($bastions.Count -eq 0) {
                Write-Fail "No Azure Bastion hosts found, but $($vms.Count) VM(s) exist"
                Add-Result "8.4.1" "Azure Bastion exists" "FAIL" "No Bastion hosts; $($vms.Count) VMs present"
                return
            }
            Write-Pass "Azure Bastion host(s) found: $($bastions.Count)"
            foreach ($b in $bastions) { Write-Info "  - $($b.Name) ($($b.Location))" }

            # Build: map of VNetId -> bastion-present (either own Bastion or via peering)
            $allVNets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)
            $bastionVNetIds = New-Object System.Collections.Generic.HashSet[string]
            foreach ($b in $bastions) {
                $bDetail = Get-AzResource -ResourceId $b.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $ipConfigs = $bDetail.Properties.ipConfigurations
                foreach ($ic in $ipConfigs) {
                    $subnetId = $ic.properties.subnet.id
                    if ($subnetId) {
                        # VNet id is everything before /subnets/
                        $vnetId = ($subnetId -split "/subnets/")[0]
                        [void]$bastionVNetIds.Add($vnetId.ToLower())
                    }
                }
            }
            # Expand via peerings (a VNet is "covered" if it is peered to a VNet with a Bastion)
            $coveredVNetIds = New-Object System.Collections.Generic.HashSet[string]
            foreach ($id in $bastionVNetIds) { [void]$coveredVNetIds.Add($id) }
            foreach ($vnet in $allVNets) {
                foreach ($peer in @($vnet.VirtualNetworkPeerings)) {
                    $remoteId = $peer.RemoteVirtualNetwork.Id
                    if ($remoteId -and $bastionVNetIds.Contains($remoteId.ToLower())) {
                        [void]$coveredVNetIds.Add($vnet.Id.ToLower())
                    }
                    if ($remoteId -and $vnet.Id -and $coveredVNetIds.Contains($vnet.Id.ToLower())) {
                        [void]$coveredVNetIds.Add($remoteId.ToLower())
                    }
                }
            }

            # Find VNets that host VMs (via NICs)
            $nics = @(Get-AzNetworkInterface -ErrorAction SilentlyContinue)
            $vmVNetIds = New-Object System.Collections.Generic.HashSet[string]
            foreach ($nic in $nics) {
                if (-not $nic.VirtualMachine) { continue }
                foreach ($ic in $nic.IpConfigurations) {
                    $subnetId = $ic.Subnet.Id
                    if ($subnetId) {
                        $vnetId = ($subnetId -split "/subnets/")[0]
                        [void]$vmVNetIds.Add($vnetId.ToLower())
                    }
                }
            }

            $allCovered = $true
            foreach ($vnetId in $vmVNetIds) {
                $vnetName = ($vnetId -split "/")[-1]
                if ($coveredVNetIds.Contains($vnetId)) {
                    Write-Pass "VNet '$vnetName' (hosts VMs) is covered by a Bastion host (same VNet or peered)"
                } else {
                    Write-Fail "VNet '$vnetName' hosts VMs but has NO Bastion host in same or peered VNet"
                    $allCovered = $false
                }
            }
            if ($vmVNetIds.Count -eq 0) {
                Add-Result "8.4.1" "Azure Bastion exists" "PASS" "$($bastions.Count) Bastion host(s); no VM-hosting VNets to cover"
            } elseif ($allCovered) {
                Add-Result "8.4.1" "Azure Bastion exists" "PASS" "$($bastions.Count) Bastion host(s); all $($vmVNetIds.Count) VM-hosting VNets covered"
            } else {
                Add-Result "8.4.1" "Azure Bastion exists" "FAIL" "One or more VM-hosting VNets lack Bastion coverage"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.4.1" "Azure Bastion exists" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-8_5 {
    Invoke-Check "8.5" "Ensure DDoS Network Protection is enabled on VNets" {
        try {
            $vnets = @(Get-AzVirtualNetwork -ErrorAction SilentlyContinue)
            if ($vnets.Count -eq 0) {
                Write-Info "No VNets found - check not applicable"
                Add-Result "8.5" "DDoS protection on VNets" "INFO" "No VNets"
                return
            }
            $allGood = $true
            foreach ($vnet in $vnets) {
                if ($vnet.EnableDdosProtection -eq $true) {
                    Write-Pass "VNet '$($vnet.Name)' has DDoS protection enabled"
                } else {
                    Write-Fail "VNet '$($vnet.Name)' does NOT have DDoS protection"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "8.5" "DDoS protection on VNets" "PASS" "All VNets have DDoS protection"
            } else {
                Add-Result "8.5" "DDoS protection on VNets" "FAIL" "One or more VNets lack DDoS protection"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "8.5" "DDoS protection on VNets" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}
# ===============================================================================
#  SECTION 9 - STORAGE
# ===============================================================================
function Check-9_1_1 {
    Invoke-Check "9.1.1" "Ensure soft delete is enabled for Azure File Shares" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.1.1" "File share soft delete" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                try {
                    $fileSvc = Get-AzStorageFileServiceProperty -ResourceGroupName $sa.ResourceGroupName -AccountName $sa.StorageAccountName -ErrorAction SilentlyContinue
                    if ($fileSvc -and $fileSvc.ShareDeleteRetentionPolicy.Enabled -eq $true -and
                        $fileSvc.ShareDeleteRetentionPolicy.Days -ge 1 -and $fileSvc.ShareDeleteRetentionPolicy.Days -le 365) {
                        Write-Pass "Storage '$($sa.StorageAccountName)' file share soft delete: $($fileSvc.ShareDeleteRetentionPolicy.Days) days"
                    } else {
                        Write-Fail "Storage '$($sa.StorageAccountName)' file share soft delete NOT enabled"
                        $allGood = $false
                    }
                } catch { }
            }
            if ($allGood) {
                Add-Result "9.1.1" "File share soft delete" "PASS" "All storage accounts have file share soft delete"
            } else {
                Add-Result "9.1.1" "File share soft delete" "FAIL" "One or more accounts missing file share soft delete"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.1.1" "File share soft delete" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_1_2 {
    Invoke-Check "9.1.2" "Ensure SMB protocol version is SMB 3.1.1" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.1.2" "SMB protocol version" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                try {
                    $fileSvc = Get-AzStorageFileServiceProperty -ResourceGroupName $sa.ResourceGroupName -AccountName $sa.StorageAccountName -ErrorAction SilentlyContinue
                    $smbVersions = $fileSvc.ProtocolSettings.Smb.Versions
                    if ($smbVersions -and ($smbVersions -join ",") -eq "SMB3.1.1") {
                        Write-Pass "Storage '$($sa.StorageAccountName)' SMB: $($smbVersions -join ',')"
                    } elseif ($smbVersions) {
                        Write-Fail "Storage '$($sa.StorageAccountName)' SMB versions: $($smbVersions -join ',') (should be SMB3.1.1 only)"
                        $allGood = $false
                    }
                } catch { }
            }
            if ($allGood) {
                Add-Result "9.1.2" "SMB protocol version" "PASS" "All accounts use SMB 3.1.1"
            } else {
                Add-Result "9.1.2" "SMB protocol version" "FAIL" "One or more accounts allow older SMB"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.1.2" "SMB protocol version" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_1_3 {
    Invoke-Check "9.1.3" "Ensure SMB channel encryption is AES-256-GCM" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.1.3" "SMB channel encryption" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                try {
                    $fileSvc = Get-AzStorageFileServiceProperty -ResourceGroupName $sa.ResourceGroupName -AccountName $sa.StorageAccountName -ErrorAction SilentlyContinue
                    $chanEnc = $fileSvc.ProtocolSettings.Smb.ChannelEncryption
                    if ($chanEnc -and ($chanEnc -join ",") -match "AES-256-GCM") {
                        Write-Pass "Storage '$($sa.StorageAccountName)' SMB encryption: $($chanEnc -join ',')"
                    } elseif ($chanEnc) {
                        Write-Fail "Storage '$($sa.StorageAccountName)' SMB encryption: $($chanEnc -join ',') (should include AES-256-GCM)"
                        $allGood = $false
                    }
                } catch { }
            }
            if ($allGood) {
                Add-Result "9.1.3" "SMB channel encryption" "PASS" "All accounts use AES-256-GCM"
            } else {
                Add-Result "9.1.3" "SMB channel encryption" "FAIL" "One or more accounts lack AES-256-GCM"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.1.3" "SMB channel encryption" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_2_1 {
    Invoke-Check "9.2.1" "Ensure soft delete is enabled for blobs" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.2.1" "Blob soft delete" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                try {
                    $blobSvc = Get-AzStorageBlobServiceProperty -ResourceGroupName $sa.ResourceGroupName -AccountName $sa.StorageAccountName -ErrorAction SilentlyContinue
                    if ($blobSvc -and $blobSvc.DeleteRetentionPolicy.Enabled -eq $true -and
                        $blobSvc.DeleteRetentionPolicy.Days -ge 1) {
                        Write-Pass "Storage '$($sa.StorageAccountName)' blob soft delete: $($blobSvc.DeleteRetentionPolicy.Days) days"
                    } else {
                        Write-Fail "Storage '$($sa.StorageAccountName)' blob soft delete NOT enabled"
                        $allGood = $false
                    }
                } catch { }
            }
            if ($allGood) {
                Add-Result "9.2.1" "Blob soft delete" "PASS" "All accounts have blob soft delete"
            } else {
                Add-Result "9.2.1" "Blob soft delete" "FAIL" "One or more accounts missing blob soft delete"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.2.1" "Blob soft delete" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_2_2 {
    Invoke-Check "9.2.2" "Ensure soft delete is enabled for containers" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.2.2" "Container soft delete" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                try {
                    $blobSvc = Get-AzStorageBlobServiceProperty -ResourceGroupName $sa.ResourceGroupName -AccountName $sa.StorageAccountName -ErrorAction SilentlyContinue
                    if ($blobSvc -and $blobSvc.ContainerDeleteRetentionPolicy.Enabled -eq $true) {
                        Write-Pass "Storage '$($sa.StorageAccountName)' container soft delete enabled"
                    } else {
                        Write-Fail "Storage '$($sa.StorageAccountName)' container soft delete NOT enabled"
                        $allGood = $false
                    }
                } catch { }
            }
            if ($allGood) {
                Add-Result "9.2.2" "Container soft delete" "PASS" "All accounts have container soft delete"
            } else {
                Add-Result "9.2.2" "Container soft delete" "FAIL" "One or more accounts missing container soft delete"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.2.2" "Container soft delete" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_2_3 {
    Invoke-Check "9.2.3" "Ensure blob versioning is enabled" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.2.3" "Blob versioning" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                try {
                    $blobSvc = Get-AzStorageBlobServiceProperty -ResourceGroupName $sa.ResourceGroupName -AccountName $sa.StorageAccountName -ErrorAction SilentlyContinue
                    if ($blobSvc -and $blobSvc.IsVersioningEnabled -eq $true) {
                        Write-Pass "Storage '$($sa.StorageAccountName)' blob versioning enabled"
                    } else {
                        Write-Fail "Storage '$($sa.StorageAccountName)' blob versioning NOT enabled"
                        $allGood = $false
                    }
                } catch { }
            }
            if ($allGood) {
                Add-Result "9.2.3" "Blob versioning" "PASS" "All accounts have blob versioning"
            } else {
                Add-Result "9.2.3" "Blob versioning" "FAIL" "One or more accounts lack blob versioning"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.2.3" "Blob versioning" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}
function Check-9_3_1_1 {
    Invoke-Check "9.3.1.1" "Ensure key rotation reminders are enabled" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.1.1" "Storage key rotation reminders" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                $keyPolicy = $sa.KeyPolicy
                if ($keyPolicy -and $keyPolicy.KeyExpirationPeriodInDays -gt 0) {
                    Write-Pass "Storage '$($sa.StorageAccountName)' key expiration: $($keyPolicy.KeyExpirationPeriodInDays) days"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' has no key expiration policy"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.1.1" "Storage key rotation reminders" "PASS" "All accounts have key expiration policy"
            } else {
                Add-Result "9.3.1.1" "Storage key rotation reminders" "FAIL" "One or more accounts lack key expiration"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.1.1" "Storage key rotation reminders" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_1_2 {
    Invoke-Check "9.3.1.2" "Ensure storage account keys are periodically regenerated" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.1.2" "Storage keys regenerated" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            $cutoff = (Get-Date).AddDays(-90)
            foreach ($sa in $storageAccounts) {
                $keyCreation = $sa.KeyCreationTime
                if ($keyCreation) {
                    $key1Time = $keyCreation.Key1
                    $key2Time = $keyCreation.Key2
                    if ($key1Time -and $key1Time -lt $cutoff) {
                        Write-Fail "Storage '$($sa.StorageAccountName)' Key1 last rotated: $key1Time (> 90 days)"
                        $allGood = $false
                    }
                    if ($key2Time -and $key2Time -lt $cutoff) {
                        Write-Fail "Storage '$($sa.StorageAccountName)' Key2 last rotated: $key2Time (> 90 days)"
                        $allGood = $false
                    }
                    if (($key1Time -and $key1Time -ge $cutoff) -and ($key2Time -and $key2Time -ge $cutoff)) {
                        Write-Pass "Storage '$($sa.StorageAccountName)' keys rotated within 90 days"
                    }
                } else {
                    Write-Warn "Storage '$($sa.StorageAccountName)' - could not determine key creation time"
                }
            }
            if ($allGood) {
                Add-Result "9.3.1.2" "Storage keys regenerated" "PASS" "All keys within 90 days"
            } else {
                Add-Result "9.3.1.2" "Storage keys regenerated" "FAIL" "One or more keys older than 90 days"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.1.2" "Storage keys regenerated" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_1_3 {
    Invoke-Check "9.3.1.3" "Ensure storage account key access is disabled" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.1.3" "Storage key access disabled" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                if ($sa.AllowSharedKeyAccess -eq $false) {
                    Write-Pass "Storage '$($sa.StorageAccountName)' shared key access is disabled"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' shared key access is enabled"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.1.3" "Storage key access disabled" "PASS" "All accounts have shared key access disabled"
            } else {
                Add-Result "9.3.1.3" "Storage key access disabled" "FAIL" "One or more accounts allow shared key access"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.1.3" "Storage key access disabled" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_2_1 {
    Invoke-Check "9.3.2.1" "Ensure private endpoints are used for storage accounts" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.2.1" "Storage private endpoints" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                $pe = $sa.PrivateEndpointConnections
                if ($pe -and @($pe).Count -gt 0) {
                    Write-Pass "Storage '$($sa.StorageAccountName)' has private endpoint(s)"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' has NO private endpoints"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.2.1" "Storage private endpoints" "PASS" "All accounts have private endpoints"
            } else {
                Add-Result "9.3.2.1" "Storage private endpoints" "FAIL" "One or more accounts lack private endpoints"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.2.1" "Storage private endpoints" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_2_2 {
    Invoke-Check "9.3.2.2" "Ensure public network access is disabled for storage" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.2.2" "Storage public access disabled" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                if ($sa.PublicNetworkAccess -eq "Disabled") {
                    Write-Pass "Storage '$($sa.StorageAccountName)' public network access is disabled"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' public network access: $($sa.PublicNetworkAccess)"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.2.2" "Storage public access disabled" "PASS" "All accounts have public access disabled"
            } else {
                Add-Result "9.3.2.2" "Storage public access disabled" "FAIL" "One or more accounts allow public access"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.2.2" "Storage public access disabled" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_2_3 {
    Invoke-Check "9.3.2.3" "Ensure default network access rule set to deny" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.2.3" "Storage default deny" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                $nrs = $sa.NetworkRuleSet
                if ($nrs -and $nrs.DefaultAction -eq "Deny") {
                    Write-Pass "Storage '$($sa.StorageAccountName)' default action: Deny"
                } else {
                    $action = if ($nrs) { $nrs.DefaultAction } else { "unknown" }
                    Write-Fail "Storage '$($sa.StorageAccountName)' default action: $action (should be Deny)"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.2.3" "Storage default deny" "PASS" "All accounts default to Deny"
            } else {
                Add-Result "9.3.2.3" "Storage default deny" "FAIL" "One or more accounts default to Allow"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.2.3" "Storage default deny" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_3_1 {
    Invoke-Check "9.3.3.1" "Ensure default to Entra authorization is enabled" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.3.1" "Storage Entra authorization" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                $defaultOAuth = $sa.DefaultToOAuthAuthentication
                if ($defaultOAuth -eq $true) {
                    Write-Pass "Storage '$($sa.StorageAccountName)' defaults to Entra authorization"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' does NOT default to Entra authorization"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.3.1" "Storage Entra authorization" "PASS" "All accounts default to Entra auth"
            } else {
                Add-Result "9.3.3.1" "Storage Entra authorization" "FAIL" "One or more accounts not defaulting to Entra"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.3.1" "Storage Entra authorization" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_4 {
    Invoke-Check "9.3.4" "Ensure secure transfer required is enabled" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.4" "Secure transfer required" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                if ($sa.EnableHttpsTrafficOnly -eq $true) {
                    Write-Pass "Storage '$($sa.StorageAccountName)' requires secure transfer"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' does NOT require secure transfer"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.4" "Secure transfer required" "PASS" "All accounts require HTTPS"
            } else {
                Add-Result "9.3.4" "Secure transfer required" "FAIL" "One or more accounts allow HTTP"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.4" "Secure transfer required" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_5 {
    Invoke-Check "9.3.5" "Ensure Azure trusted services access is enabled" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.5" "Trusted services bypass" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                $bypass = $sa.NetworkRuleSet.Bypass
                if ($bypass -match "AzureServices") {
                    Write-Pass "Storage '$($sa.StorageAccountName)' allows Azure trusted services"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' does NOT allow Azure trusted services (Bypass: $bypass)"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.5" "Trusted services bypass" "PASS" "All accounts allow trusted services"
            } else {
                Add-Result "9.3.5" "Trusted services bypass" "FAIL" "One or more accounts block trusted services"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.5" "Trusted services bypass" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_6 {
    Invoke-Check "9.3.6" "Ensure minimum TLS version is TLS 1.2" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.6" "Storage TLS 1.2" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                $minTls = $sa.MinimumTlsVersion
                if ($minTls -in @("TLS1_2", "TLS1_3")) {
                    Write-Pass "Storage '$($sa.StorageAccountName)' min TLS: $minTls"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' min TLS: $minTls (should be TLS1_2+)"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.6" "Storage TLS 1.2" "PASS" "All accounts use TLS 1.2+"
            } else {
                Add-Result "9.3.6" "Storage TLS 1.2" "FAIL" "One or more accounts below TLS 1.2"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.6" "Storage TLS 1.2" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_7 {
    Invoke-Check "9.3.7" "Ensure cross tenant replication is disabled" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.7" "Cross tenant replication" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                if ($sa.AllowCrossTenantReplication -eq $false) {
                    Write-Pass "Storage '$($sa.StorageAccountName)' cross tenant replication disabled"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' cross tenant replication is enabled"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.7" "Cross tenant replication" "PASS" "All accounts have CTR disabled"
            } else {
                Add-Result "9.3.7" "Cross tenant replication" "FAIL" "One or more accounts allow CTR"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.7" "Cross tenant replication" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_8 {
    Invoke-Check "9.3.8" "Ensure blob anonymous access is disabled" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.8" "Blob anonymous access" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                if ($sa.AllowBlobPublicAccess -eq $false) {
                    Write-Pass "Storage '$($sa.StorageAccountName)' blob anonymous access disabled"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' allows blob anonymous access"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.8" "Blob anonymous access" "PASS" "All accounts block anonymous blob access"
            } else {
                Add-Result "9.3.8" "Blob anonymous access" "FAIL" "One or more accounts allow anonymous blob access"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.8" "Blob anonymous access" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}

function Check-9_3_11 {
    Invoke-Check "9.3.11" "Ensure geo-redundant storage (GRS) is configured" {
        try {
            $storageAccounts = @(Get-AzStorageAccount -ErrorAction SilentlyContinue)
            if ($storageAccounts.Count -eq 0) {
                Write-Info "No storage accounts found - check not applicable"
                Add-Result "9.3.11" "Geo-redundant storage" "INFO" "No storage accounts"
                return
            }
            $allGood = $true
            foreach ($sa in $storageAccounts) {
                $skuName = $sa.Sku.Name
                if ($skuName -match "GRS|GZRS|RAGRS|RAGZRS") {
                    Write-Pass "Storage '$($sa.StorageAccountName)' SKU: $skuName (geo-redundant)"
                } else {
                    Write-Fail "Storage '$($sa.StorageAccountName)' SKU: $skuName (NOT geo-redundant)"
                    $allGood = $false
                }
            }
            if ($allGood) {
                Add-Result "9.3.11" "Geo-redundant storage" "PASS" "All accounts use GRS"
            } else {
                Add-Result "9.3.11" "Geo-redundant storage" "FAIL" "One or more accounts lack GRS"
            }
        } catch {
            Write-Warn "Error: $($_.Exception.Message)"
            Add-Result "9.3.11" "Geo-redundant storage" "WARN" "Error: $($_.Exception.Message)"
        }
    }
}
# ===============================================================================
#  SUMMARY
# ===============================================================================
function Show-Summary {
    $total  = $Script:PassCount + $Script:FailCount + $Script:WarnCount
    $line82 = "=" * 82
    Write-Host ""
    Write-Host $line82 -ForegroundColor Cyan
    Write-Host "  CIS Microsoft Azure Foundations Benchmark v5.0.0 - RESULTS SUMMARY" -ForegroundColor Cyan
    Write-Host $line82 -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  {0,-12} {1,-50} {2}" -f "SECTION","TITLE","STATUS")
    Write-Host ("  {0,-12} {1,-50} {2}" -f ("-"*12),("-"*50),("-"*6))

    foreach ($r in $Script:Results) {
        $col = switch ($r.Status) { "PASS"{"Green"} "FAIL"{"Red"} default{"Magenta"} }
        $t   = if ($r.Title.Length -gt 50) { $r.Title.Substring(0,47) + "..." } else { $r.Title }
        Write-Host ("  {0,-12} {1,-50} " -f $r.Section, $t) -NoNewline
        Write-Host $r.Status -ForegroundColor $col
        if ($r.Status -ne "PASS" -and $r.Status -ne "INFO") {
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
Write-Host "|   CIS Microsoft Azure Foundations Benchmark v5.0.0 - 103 Checks (Auto + Manual)    |" -ForegroundColor Cyan
Write-Host "|   Subscription : $SubscriptionId                          |" -ForegroundColor Cyan
Write-Host "+==================================================================================+" -ForegroundColor Cyan

Connect-AllServices

# -- Cache NSGs once for Section 7 -----------------------------------------------
$Script:AllNSGs = @(Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue)

Write-Banner "SECTION 2 - Databricks"
Check-2_1_1;  Check-2_1_2;  Check-2_1_7; Check-2_1_8
Check-2_1_9;  Check-2_1_10; Check-2_1_11

Write-Banner "SECTION 5 - Identity / Entra ID"
Check-5_1_1;  Check-5_1_2;  Check-5_3_3
Check-5_4;    Check-5_14;   Check-5_15;  Check-5_16
Check-5_23;   Check-5_27

Write-Banner "SECTION 6 - Logging & Monitoring"
Check-6_1_1_1;  Check-6_1_1_2;  Check-6_1_1_3;  Check-6_1_1_4
Check-6_1_1_5;  Check-6_1_1_6;  Check-6_1_1_7
Check-6_1_1_8;  Check-6_1_1_9;  Check-6_1_1_10
Check-6_1_2_1;  Check-6_1_2_2;  Check-6_1_2_3;  Check-6_1_2_4;  Check-6_1_2_5
Check-6_1_2_6;  Check-6_1_2_7;  Check-6_1_2_8;  Check-6_1_2_9;  Check-6_1_2_10
Check-6_1_2_11; Check-6_1_3_1

Write-Banner "SECTION 7 - Networking"
Check-7_1  -NSGs $Script:AllNSGs
Check-7_2  -NSGs $Script:AllNSGs
Check-7_3  -NSGs $Script:AllNSGs
Check-7_4  -NSGs $Script:AllNSGs
Check-7_5;    Check-7_6;    Check-7_7;   Check-7_8;   Check-7_9
Check-7_10;   Check-7_11;   Check-7_12;  Check-7_13
Check-7_14;   Check-7_15;   Check-7_16

Write-Banner "SECTION 8 - Security (Defender, Key Vault, Bastion, DDoS)"
Check-8_1_1_1;  Check-8_1_2_1;  Check-8_1_3_1;  Check-8_1_3_3
Check-8_1_4_1;  Check-8_1_5_1;  Check-8_1_6_1
Check-8_1_7_1;  Check-8_1_7_2;  Check-8_1_7_3;  Check-8_1_7_4
Check-8_1_8_1;  Check-8_1_9_1
Check-8_1_10;   Check-8_1_12;   Check-8_1_13;   Check-8_1_14;   Check-8_1_15
Check-8_3_1;    Check-8_3_2;    Check-8_3_3;    Check-8_3_4
Check-8_3_5;    Check-8_3_6;    Check-8_3_7;    Check-8_3_8
Check-8_3_9;    Check-8_3_11
Check-8_4_1;    Check-8_5

Write-Banner "SECTION 9 - Storage"
Check-9_1_1;    Check-9_1_2;    Check-9_1_3
Check-9_2_1;    Check-9_2_2;    Check-9_2_3
Check-9_3_1_1;  Check-9_3_1_2;  Check-9_3_1_3
Check-9_3_2_1;  Check-9_3_2_2;  Check-9_3_2_3
Check-9_3_3_1;  Check-9_3_4;    Check-9_3_5;    Check-9_3_6
Check-9_3_7;    Check-9_3_8;    Check-9_3_11

Write-Banner "RESULTS SUMMARY"
Show-Summary

$elapsed = (Get-Date) - $StartTime
Write-Host "  Total runtime: $([Math]::Round($elapsed.TotalSeconds, 1))s" -ForegroundColor Gray

Disconnect-MgGraph -ErrorAction SilentlyContinue
Disconnect-AzAccount -ErrorAction SilentlyContinue
Write-Host "  All sessions disconnected." -ForegroundColor Gray
Write-Host ""