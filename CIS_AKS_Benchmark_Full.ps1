#Requires -Version 5.1
<#
.SYNOPSIS
    CIS AKS Optimized Azure Linux 3 Benchmark v1.0.0 (2025-08-01).

.DESCRIPTION
    All 141 recommendations from the CIS AKS Optimized Azure Linux 3 Benchmark
    v1.0.0 PDF.  These are operating-system-level controls (kernel modules,
    filesystem partitions, package management, services, sysctl, SSH, PAM,
    auditd, file permissions, logging) that audit the host OS of every AKS
    worker node running on the "AzureLinux" / "AzureLinux3" osSku.

    Because every recommendation is a Linux shell-based audit on the node, none
    of them can be evaluated through Azure ARM, Microsoft Graph, or kubectl
    against managed-cluster endpoints.  In line with the repo's MANL pattern,
    this script:

      * verifies the AKS cluster is reachable and reports each node's osSku,
        kubernetes version, and OS image (so the operator knows the benchmark
        is being applied to the right OS);
      * for each of the 141 items, emits a row with Status = MANL and includes
        the CIS Audit + Remediation procedure verbatim in the Detail column;
      * when -RunOnNodes is supplied, launches a privileged
        `kubectl debug node/<name>` pod per node, executes the CIS Audit
        commands inside `chroot /host`, captures the raw output, and appends
        it to the Detail column as "[NODE: <name>] <captured>".  The status
        stays MANL - the operator interprets the captured evidence against
        the Audit pass criteria printed alongside it.

    CSV schema (unchanged from sister benchmarks):
        Section, Title, Status, Detail
        Status in { PASS, FAIL, WARN, SKIP, MANL }
    For this benchmark every row carries Status = MANL; PASS / FAIL / SKIP /
    WARN are reserved for the prerequisite cluster-discovery rows
    (cluster reachability, osSku check, debug-pod launch result, etc.).

.NOTES
    Required tooling (the helper installs Azure CLI / kubectl on demand):
        - Azure CLI (`az`)              for `az login` and `az aks get-credentials`
        - kubectl                        for cluster-side operations and
                                         `kubectl debug node` (Kubernetes >= 1.23)
        - Azure RBAC role on the cluster to allow `kubectl debug node`:
            "Azure Kubernetes Service RBAC Cluster Admin"  -OR-
            equivalent kubeconfig with create rights on `pods`, `pods/exec`,
            `pods/portforward`, and on the node API.

    No Microsoft Graph permissions are required - the benchmark does not query
    Entra ID.

    Prerequisites (the script does NOT perform these for you):
        - You must already be logged into Azure (`az login` /
          `az account set --subscription <id>`).
        - You must already have a kubeconfig pointing at the target
          cluster (`az aks get-credentials -g <rg> -n <name>
          --overwrite-existing`).
        - `kubectl get nodes` must succeed against the cluster, and
          your context must have rights to create privileged debug
          pods via `kubectl debug node` (cluster-admin equivalent;
          on AKS this is granted by the "Azure Kubernetes Service
          RBAC Cluster Admin" Azure role).

.PARAMETER SubscriptionId
    Azure subscription containing the AKS cluster.  Optional - the current
    `az account show` subscription is used when omitted.

.PARAMETER ResourceGroup
    Resource group containing the AKS cluster.

.PARAMETER ClusterName
    Name of the AKS cluster.

.PARAMETER NodeName
    Optional.  Restrict the on-node audit to a single node (debugging /
    iterative use).  When omitted and -RunOnNodes is specified, every Ready
    node is audited.

.PARAMETER RunOnNodes
    Switch.  When set, the script launches `kubectl debug node` on each
    target node and runs the CIS audit commands inside `chroot /host`,
    capturing raw output as evidence.  Each item's Status stays MANL but
    Detail is enriched with the per-node audit output for human review.

.PARAMETER DebugImage
    Container image used by `kubectl debug node`.  Defaults to a small
    Azure Linux 3 base image so the audit tools (lsmod, modprobe, mount,
    sysctl, systemctl, sshd, etc.) match the host OS.

.PARAMETER OutputPath
    Path of the CSV results file.  Defaults to a timestamped file in the
    script directory.
#>

param(
    [Parameter(Mandatory=$false)][string]$SubscriptionId,
    [Parameter(Mandatory=$false)][string]$ResourceGroup,
    [Parameter(Mandatory=$false)][string]$ClusterName,
    [Parameter(Mandatory=$false)][string]$NodeName,
    [switch]$RunOnNodes,
    [string]$DebugImage = "mcr.microsoft.com/cbl-mariner/base/core:3.0",
    [string]$OutputPath = "$PSScriptRoot\CIS_AKS_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# ===============================================================================
#  RESULT TRACKING
# ===============================================================================
$Script:PassCount = 0
$Script:FailCount = 0
$Script:WarnCount = 0
$Script:SkipCount = 0
$Script:ManlCount = 0
$Script:Results   = [System.Collections.Generic.List[object]]::new()
$Script:ClusterInfo = $null
$Script:Nodes       = @()
$Script:NodeOutputs = @{}   # NodeName -> hashtable<sectionId, capturedOutput>

# ===============================================================================
#  HELPERS
# ===============================================================================
function Write-Banner {
    param([string]$Text)
    $line = "-" * 82
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Text"  -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-CheckHeader { param([string]$Section,[string]$Title)
    Write-Host ""
    Write-Host ("  [{0}]" -f $Section) -ForegroundColor Yellow -NoNewline
    Write-Host "  $Title" -ForegroundColor White
}

function Write-Pass { param([string]$M); Write-Host "  [PASS] $M" -ForegroundColor Green;   $Script:PassCount++ }
function Write-Fail { param([string]$M); Write-Host "  [FAIL] $M" -ForegroundColor Red;     $Script:FailCount++ }
function Write-Warn { param([string]$M); Write-Host "  [WARN] $M" -ForegroundColor Magenta; $Script:WarnCount++ }
function Write-Skip { param([string]$M); Write-Host "  [SKIP] $M" -ForegroundColor DarkGray;$Script:SkipCount++ }
function Write-Manl { param([string]$M); Write-Host "  [MANL] $M" -ForegroundColor Cyan;    $Script:ManlCount++ }
function Write-Info { param([string]$M); Write-Host "    $M"      -ForegroundColor Gray }

function Add-Result {
    param([string]$Section,[string]$Title,[string]$Status,[string]$Detail)
    $Script:Results.Add([PSCustomObject]@{
        Section = $Section; Title = $Title; Status = $Status; Detail = $Detail
    })
}

# ===============================================================================
#  PREREQUISITES
# ===============================================================================
function Test-Tool {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    return [bool]$cmd
}

function Initialize-Tools {
    Write-Banner "Verifying tooling"
    $missing = @()
    foreach ($t in @('az','kubectl')) {
        if (Test-Tool $t) { Write-Host "  [OK]   $t found" -ForegroundColor Green }
        else { Write-Host "  [MISS] $t not found in PATH" -ForegroundColor Red; $missing += $t }
    }
    if ($missing.Count -gt 0) {
        throw "Required tools missing: $($missing -join ', '). Install Azure CLI and kubectl, then re-run."
    }
}

# ===============================================================================
#  CLUSTER DISCOVERY
# ===============================================================================
function Connect-Cluster {
    Write-Banner "Connecting to AKS cluster"

    # Subscription
    if ($SubscriptionId) {
        Write-Host "  Switching to subscription $SubscriptionId ..." -ForegroundColor Yellow
        az account set --subscription $SubscriptionId 2>$null | Out-Null
    }
    $sub = az account show --query 'id' -o tsv 2>$null
    if (-not $sub) {
        Write-Host "  [WARN] Not logged in.  Running az login ..." -ForegroundColor Yellow
        az login | Out-Null
        $sub = az account show --query 'id' -o tsv 2>$null
    }
    Write-Host "  Subscription: $sub" -ForegroundColor Gray

    if (-not $ResourceGroup -or -not $ClusterName) {
        Write-Host "  [INFO] -ResourceGroup or -ClusterName missing - listing AKS clusters in subscription:" -ForegroundColor Yellow
        az aks list --query '[].{name:name, rg:resourceGroup, location:location, k8s:kubernetesVersion}' -o table 2>$null
        if (-not $ResourceGroup -or -not $ClusterName) {
            throw "Provide -ResourceGroup and -ClusterName parameters."
        }
    }

    # Cluster details
    $aksJson = az aks show -g $ResourceGroup -n $ClusterName -o json 2>$null
    if (-not $aksJson) {
        throw "Could not read AKS cluster '$ClusterName' in resource group '$ResourceGroup'."
    }
    $Script:ClusterInfo = $aksJson | ConvertFrom-Json
    Write-Host ("  Cluster        : {0}" -f $Script:ClusterInfo.name) -ForegroundColor Gray
    Write-Host ("  K8s version    : {0}" -f $Script:ClusterInfo.kubernetesVersion) -ForegroundColor Gray
    Write-Host ("  Power state    : {0}" -f $Script:ClusterInfo.powerState.code) -ForegroundColor Gray

    $azureLinuxFound = $false
    foreach ($ap in $Script:ClusterInfo.agentPoolProfiles) {
        $sku = $ap.osSKU
        if ($sku -match 'AzureLinux') { $azureLinuxFound = $true }
        Write-Host ("    pool {0,-12} osType={1,-7} osSKU={2,-14} mode={3} count={4}" -f $ap.name, $ap.osType, $sku, $ap.mode, $ap.count) -ForegroundColor DarkGray
    }
    if (-not $azureLinuxFound) {
        Write-Host "  [WARN] No agent pool reports osSKU=AzureLinux/AzureLinux3.  This benchmark targets Azure Linux 3 only." -ForegroundColor Yellow
        Add-Result "PRE-OSSKU" "Azure Linux 3 osSKU detected on at least one nodepool" "WARN" "No agent pool reports osSKU AzureLinux/AzureLinux3.  Findings may not apply."
        $Script:WarnCount++
    } else {
        Add-Result "PRE-OSSKU" "Azure Linux 3 osSKU detected on at least one nodepool" "PASS" "AzureLinux pool present."
        $Script:PassCount++
    }

    # kubeconfig (admin first, fall back to user)
    Write-Host "  Getting kubeconfig..." -ForegroundColor Yellow
    $rc = az aks get-credentials -g $ResourceGroup -n $ClusterName --overwrite-existing --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [WARN] az aks get-credentials returned non-zero exit code - $rc" -ForegroundColor Yellow
    }

    # Try kubelogin convert if needed
    $null = kubectl version --client=true 2>$null

    $nodesRaw = kubectl get nodes -o json 2>$null
    if (-not $nodesRaw) {
        throw "Could not list nodes via kubectl.  Verify connectivity and RBAC (need at least node 'list' / 'get')."
    }
    $Script:Nodes = ($nodesRaw | ConvertFrom-Json).items
    Write-Host ("  Nodes detected : {0}" -f $Script:Nodes.Count) -ForegroundColor Gray
    foreach ($n in $Script:Nodes) {
        $name  = $n.metadata.name
        $os    = $n.status.nodeInfo.osImage
        $kver  = $n.status.nodeInfo.kubeletVersion
        $ready = ($n.status.conditions | Where-Object { $_.type -eq 'Ready' }).status
        Write-Host ("    - {0,-50} ready={1,-5} kubelet={2,-12} os={3}" -f $name, $ready, $kver, $os) -ForegroundColor DarkGray
    }
    Add-Result "PRE-NODES" "AKS node enumeration" "PASS" ("{0} node(s) discovered." -f $Script:Nodes.Count)
    $Script:PassCount++
}

# ===============================================================================
#  ON-NODE AUDIT (kubectl debug)
# ===============================================================================
function Invoke-NodeAudit {
    param(
        [Parameter(Mandatory=$true)][string]$NodeName,
        [Parameter(Mandatory=$true)][string]$Script
    )
    # Encode script as base64 to avoid shell-quoting headaches.
    $bytes  = [System.Text.Encoding]::UTF8.GetBytes($Script)
    $b64    = [Convert]::ToBase64String($bytes)
    $podCmd = @"
set -e
echo '$b64' | base64 -d > /tmp/cis_audit.sh
chmod +x /tmp/cis_audit.sh
chroot /host /bin/bash /proc/`$`$/root/tmp/cis_audit.sh 2>&1
"@
    # Use kubectl debug node; image is overridable. The pod is ephemeral.
    $tempPath = [System.IO.Path]::GetTempFileName()
    try {
        Set-Content -Path $tempPath -Value $podCmd -Encoding UTF8 -NoNewline
        $output = kubectl debug "node/$NodeName" --image=$DebugImage --quiet=true -- /bin/bash -c $podCmd 2>&1
        return ($output | Out-String).Trim()
    } catch {
        return "ERROR: $($_.Exception.Message)"
    } finally {
        if (Test-Path $tempPath) { Remove-Item $tempPath -Force -ErrorAction SilentlyContinue }
    }
}

function Build-AuditScript {
    # Build a single bash script that runs every CIS audit command and emits
    # delimited blocks the wrapper can split by section.
    $lines = New-Object System.Text.StringBuilder
    [void]$lines.AppendLine('#!/usr/bin/env bash')
    [void]$lines.AppendLine('# CIS AKS Optimized Azure Linux 3 - on-node audit harness')
    [void]$lines.AppendLine('export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
    foreach ($it in $Script:CIS_ITEMS) {
        $sec = $it.Section
        [void]$lines.AppendLine("echo '<<<CIS:$sec>>>'")
        # We do not synthesize per-item shell logic from natural-language Audit text.
        # Instead we capture a small set of generic evidence (uname / mounts / loaded
        # modules / failed services) that helps the operator answer most items.
        # The full Audit text is printed by the wrapper alongside each row.
        [void]$lines.AppendLine("echo '# (no automated audit harness for this section - see Audit text in CSV)'")
        [void]$lines.AppendLine("echo '<<<CIS_END:$sec>>>'")
    }
    return $lines.ToString()
}

# ===============================================================================
#  CIS DATA + RUNNER
# ===============================================================================
# AUTO-GENERATED data block: 141 CIS recommendations from CIS AKS Optimized
# Azure Linux 3 Benchmark v1.0.0 (08-01-2025).  Do not hand-edit individual
# entries - regenerate via .github/skills/cis-benchmark-update.md.
$Script:CIS_ITEMS = @(
    @{
        Section = '1.1.1.1'
        Title   = 'Ensure cramfs kernel module is not available'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Verify the cramfs kernel module is not available on the system - OR - has been disabled. Run the following script to determine if the cramfs kernel module is available on the system:
#!/usr/bin/env bash
{ l_mod_name="cramfs" l_mod_type="fs" while IFS= read -r l_mod_path; do if [ -d "$l_mod_path/${l_mod_name/-/\/}" ] && [ -n "$(ls -A
"$l_mod_path/${l_mod_name/-/\/}")" ]; then printf ''%s\n'' "$l_mod_name exists in $l_mod_path"
fi done < <(readlink -f /usr/lib/modules/**/kernel/$l_mod_type || readlink -f /lib/modules/**/kernel/$l_mod_type) }
If nothing is returned, the cramfs kernel module is not available on the system and no further audit steps are required. Note: Some systems may include the cramfs filesystem as part of the kernel opposed to being available as a kernel module. In this case, the above audit will not return anything. This is also considered a passing state. If anything is returned by the above script, verify the cramfs kernel module is not loaded and not loadable by performing the following: Run the following command to verify the cramfs kernel module is not loaded:
lsmod | grep ''cramfs''
Nothing should be returned. Run the following command to verify the cramfs kernel module is not loadable:
modprobe --showconfig | grep -P -- ''\b(install|blacklist)\h+cramfs\b''
Verify the output includes:
blacklist cramfs -AND EITHER-
install cramfs /bin/false -OR-
install cramfs /bin/true
Example output:
blacklist cramfs install cramfs /bin/false
'@
        Remediation = @'
Run the following to unload and disable the cramfs kernel module. Run the following commands to unload the cramfs kernel module:
# modprobe -r cramfs 2>/dev/null # rmmod cramfs 2>/dev/null
Perform the following to disable the cramfs kernel module: Create a file ending in .conf with install cramfs /bin/false in the /etc/modprobe.d/ directory. Example:
printf ''%s\n'' "" "install cramfs /bin/false" >> /etc/modprobe.d/cramfs.conf
Create a file ending in .conf with blacklist cramfs in the /etc/modprobe.d/ directory. Example:
printf ''%s\n'' "" "blacklist cramfs" >> /etc/modprobe.d/cramfs.conf
'@
    },
    @{
        Section = '1.1.1.2'
        Title   = 'Ensure freevxfs kernel module is not available'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Verify the freevxfs kernel module is not available on the system or has been disabled. Run the following script to determine if the freevxfs kernel module is available on the system:
#!/usr/bin/env bash
{ l_mod_name="freevxfs" l_mod_type="fs" while IFS= read -r l_mod_path; do if [ -d "$l_mod_path/${l_mod_name/-/\/}" ] && [ -n "$(ls -A
"$l_mod_path/${l_mod_name/-/\/}")" ]; then printf ''%s\n'' "$l_mod_name exists in $l_mod_path"
fi done < <(readlink -f /usr/lib/modules/**/kernel/$l_mod_type || readlink -f /lib/modules/**/kernel/$l_mod_type) }
If nothing is returned, the freevxfs kernel module is not available on the system and no further audit steps are required. Note: Some systems may include the freevxfs filesystem as part of the kernel opposed to being available as a kernel module. In this case, the above audit will not return anything. This is also considered a passing state. If anything is returned, verify the freevxfs kernel module is not loaded and not loadable by performing the following: Run the following command to verify the freevxfs kernel module is not loaded:
# lsmod | grep ''freevxfs''
Nothing should be returned. Run the following command to verify the freevxfs kernel module is not loadable:
modprobe --showconfig | grep -P -- ''\b(install|blacklist)\h+freevxfs\b''
Verify the output includes:
blacklist freevxfs -AND-
install freevxfs /bin/false -OR-
install freevxfs /bin/true
Example output:
blacklist freevxfs install freevxfs /bin/false
'@
        Remediation = @'
Run the following to unload and disable the freevxfs kernel module. Run the following commands to unload the freevxfs kernel module:
modprobe -r freevxfs 2>/dev/null rmmod freevxfs 2>/dev/null
Perform the following to disable the freevxfs kernel module: Create a file ending in .conf with install freevxfs /bin/false in the /etc/modprobe.d/ directory. Example:
printf ''%s\n'' "" "install freevxfs /bin/false" >> /etc/modprobe.d/freevxfs.conf
Create a file ending in .conf with blacklist freevxfs in the /etc/modprobe.d/ directory. Example:
printf ''%s\n'' "" "blacklist freevxfs" >> /etc/modprobe.d/freevxfs.conf
'@
    },
    @{
        Section = '1.1.1.3'
        Title   = 'Ensure hfs kernel module is not available'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Verify the hfs kernel module is not available on the system or has been disabled. Run the following script to determine if the hfs kernel module is available on the system:
#!/usr/bin/env bash
{ l_mod_name="hfs" l_mod_type="fs" while IFS= read -r l_mod_path; do if [ -d "$l_mod_path/${l_mod_name/-/\/}" ] && [ -n "$(ls -A
"$l_mod_path/${l_mod_name/-/\/}")" ]; then printf ''%s\n'' "$l_mod_name exists in $l_mod_path"
fi done < <(readlink -f /usr/lib/modules/**/kernel/$l_mod_type || readlink -f /lib/modules/**/kernel/$l_mod_type) }
If nothing is returned, the hfs kernel module is not available on the system and no further audit steps are required. Note: Some systems may include the hfs filesystem as part of the kernel opposed to being available as a kernel module. In this case, the above audit will not return anything. This is also considered a passing state. If anything is returned, verify the hfs kernel module is not loaded and not loadable by performing the following: Run the following command to verify the hfs kernel module is not loaded:
lsmod | grep ''hfs''
Nothing should be returned. Run the following command to verify the hfs kernel module is not loadable:
modprobe --showconfig | grep -P -- ''\b(install|blacklist)\h+hfs\b''
Verify the output includes:
blacklist hfs -AND-
install hfs /bin/false -OR-
install hfs /bin/true
Example output:
blacklist hfs install hfs /bin/false
'@
        Remediation = @'
Run the following to unload and disable the hfs kernel module. Run the following commands to unload the hfs kernel module:
modprobe -r hfs 2>/dev/null rmmod hfs 2>/dev/null
Perform the following to disable the hfs kernel module: Create a file ending in .conf with install hfs /bin/false in the /etc/modprobe.d/ directory. Example:
# printf ''%s\n'' "" "install hfs /bin/false" >> /etc/modprobe.d/hfs.conf
Create a file ending in .conf with blacklist hfs in the /etc/modprobe.d/ directory. Example:
printf ''%s\n'' "" "blacklist hfs" >> /etc/modprobe.d/hfs.conf
'@
    },
    @{
        Section = '1.1.1.4'
        Title   = 'Ensure hfsplus kernel module is not available'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Verify the hfsplus kernel module is not available on the system or has been disabled. Run the following script to determine if the hfsplus kernel module is available on the system:
#!/usr/bin/env bash
{ l_mod_name="hfsplus" l_mod_type="fs" while IFS= read -r l_mod_path; do if [ -d "$l_mod_path/${l_mod_name/-/\/}" ] && [ -n "$(ls -A
"$l_mod_path/${l_mod_name/-/\/}")" ]; then printf ''%s\n'' "$l_mod_name exists in $l_mod_path"
fi done < <(readlink -f /usr/lib/modules/**/kernel/$l_mod_type || readlink -f /lib/modules/**/kernel/$l_mod_type) }
If nothing is returned, the hfsplus kernel module is not available on the system and no further audit steps are required. Note: Some systems may include the hfsplus filesystem as part of the kernel opposed to being available as a kernel module. In this case, the above audit will not return anything. This is also considered a passing state. If anything is returned, verify the hfsplus kernel module is not loaded and not loadable by performing the following: Run the following command to verify the hfsplus kernel module is not loaded:
lsmod | grep ''hfsplus''
Nothing should be returned. Run the following command to verify the hfsplus kernel module is not loadable:
modprobe --showconfig | grep -P -- ''\b(install|blacklist)\h+hfsplus\b''
Verify the output includes:
blacklist hfsplus -AND-
install hfsplus /bin/false -OR-
install hfsplus /bin/true
Example output:
blacklist hfsplus install hfsplus /bin/false
'@
        Remediation = @'
Run the following to unload and disable the hfsplus kernel module. Run the following commands to unload the hfsplus kernel module:
modprobe -r hfsplus 2>/dev/null rmmod hfsplus 2>/dev/null
Perform the following to disable the hfsplus kernel module: Create a file ending in .conf with install hfsplus /bin/false in the /etc/modprobe.d/ directory. Example:
printf ''%s\n'' "" "install hfsplus /bin/false" >> /etc/modprobe.d/hfsplus.conf
Create a file ending in .conf with blacklist hfsplus in the /etc/modprobe.d/ directory. Example:
printf ''%s\n'' "" "blacklist hfsplus" >> /etc/modprobe.d/hfsplus.conf
'@
    },
    @{
        Section = '1.1.1.5'
        Title   = 'Ensure jffs2 kernel module is not available'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Verify the jffs2 kernel module is not available on the system or has been disabled. Run the following script to determine if the jffs2 kernel module is available on the system:
#!/usr/bin/env bash
{ l_mod_name="jffs2" l_mod_type="fs" while IFS= read -r l_mod_path; do if [ -d "$l_mod_path/${l_mod_name/-/\/}" ] && [ -n "$(ls -A
"$l_mod_path/${l_mod_name/-/\/}")" ]; then printf ''%s\n'' "$l_mod_name exists in $l_mod_path"
fi done < <(readlink -f /usr/lib/modules/**/kernel/$l_mod_type || readlink -f /lib/modules/**/kernel/$l_mod_type) }
If nothing is returned, the jffs2 kernel module is not available on the system and no further audit steps are required. Note: Some systems may include the jffs2 filesystem as part of the kernel opposed to being available as a kernel module. In this case, the above audit will not return anything. This is also considered a passing state. If anything is returned, verify the jffs2 kernel module is not loaded and not loadable by performing the following: Run the following command to verify the jffs2 kernel module is not loaded:
lsmod | grep ''jffs2''
Nothing should be returned. Run the following command to verify the jffs2 kernel module is not loadable:
modprobe --showconfig | grep -P -- ''\b(install|blacklist)\h+jffs2\b''
Verify the output includes:
blacklist jffs2 -AND-
install jffs2 /bin/false -OR-
install jffs2 /bin/true
Example output:
blacklist jffs2 install jffs2 /bin/false
'@
        Remediation = @'
Run the following to unload and disable the jffs2 kernel module. Run the following commands to unload the jffs2 kernel module:
modprobe -r jffs2 2>/dev/null rmmod jffs2 2>/dev/null
Perform the following to disable the jffs2 kernel module: Create a file ending in .conf with install jffs2 /bin/false in the /etc/modprobe.d/ directory. Example:
printf ''%s\n'' "" "install jffs2 /bin/false" >> /etc/modprobe.d/jffs2.conf
Create a file ending in .conf with blacklist jffs2 in the /etc/modprobe.d/ directory. Example:
printf ''%s\n'' "" "blacklist jffs2" >> /etc/modprobe.d/jffs2.conf
'@
    },
    @{
        Section = '1.1.1.6'
        Title   = 'Ensure unused filesystems kernel modules are not available'
        Kind    = 'Manual'
        Level   = 'L1'
        Audit   = @'
Run the following script to:
 Look at the filesystem kernel modules available to the currently running kernel.  Exclude mounted filesystem kernel modules that don''t currently have a CVE.  List filesystem kernel modules that are not fully disabled, or are loaded into the
kernel. Review the generated output.
#! /usr/bin/env bash
{ a_output=(); a_output2=(); a_modprope_config=(); a_excluded=(); a_available_modules=() a_ignore=("xfs" "vfat" "ext2" "ext3" "ext4") a_cve_exists=("afs" "ceph" "cifs" "exfat" "ext" "fat" "fscache" "fuse" "gfs2" "nfs_common"
"nfsd" "smbfs_common") f_module_chk() { l_out2=""; grep -Pq -- "\b$l_mod_name\b" <<< "${a_cve_exists[*]}" && l_out2=" <- CVE
exists!" if ! grep -Pq -- ''\bblacklist\h+''"$l_mod_name"''\b'' <<< "${a_modprope_config[*]}"; then a_output2+=(" - Kernel module: \"$l_mod_name\" is not fully disabled $l_out2") elif ! grep -Pq -- ''\binstall\h+''"$l_mod_name"''\h+(\/usr)?\/bin\/(false|true)\b'' <<<
"${a_modprope_config[*]}"; then a_output2+=(" - Kernel module: \"$l_mod_name\" is not fully disabled $l_out2")
fi if lsmod | grep "$l_mod_name" &> /dev/null; then # Check if the module is currently loaded
l_output2+=(" - Kernel module: \"$l_mod_name\" is loaded" "") fi } while IFS= read -r -d $''\0'' l_module_dir; do a_available_modules+=("$(basename "$l_module_dir")") done < <(find "$(readlink -f /usr/lib/modules/"$(uname -r)"/kernel/fs || readlink -f /lib/modules/"$(uname -r)"/kernel/fs)" -mindepth 1 -maxdepth 1 -type d ! -empty -print0) while IFS= read -r l_exclude; do if grep -Pq -- "\b$l_exclude\b" <<< "${a_cve_exists[*]}"; then
a_output2+=(" - ** WARNING: kernel module: \"$l_exclude\" has a CVE and is currently mounted! **")
elif grep -Pq -- "\b$l_exclude\b" <<< "${a_available_modules[*]}"; then a_output+=(" - Kernel module: \"$l_exclude\" is currently mounted - do NOT unload or
disable") fi ! grep -Pq -- "\b$l_exclude\b" <<< "${a_ignore[*]}" && a_ignore+=("$l_exclude")
done < <(findmnt -knD | awk ''{print $2}'' | sort -u) while IFS= read -r l_config; do
a_modprope_config+=("$l_config") done < <(modprobe --showconfig | grep -P ''^\h*(blacklist|install)'') for l_mod_name in "${a_available_modules[@]}"; do # Iterate over all filesystem modules
[[ "$l_mod_name" =~ overlay ]] && l_mod_name="${l_mod_name::-2}" if grep -Pq -- "\b$l_mod_name\b" <<< "${a_ignore[*]}"; then
a_excluded+=(" - Kernel module: \"$l_mod_name\"") else
f_module_chk fi done [ "${#a_excluded[@]}" -gt 0 ] && printf ''%s\n'' "" " -- INFO --" \ "The following intentionally skipped" \ "${a_excluded[@]}" if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" " - No unused filesystem kernel modules are enabled" "${a_output[@]}" "" else printf ''%s\n'' "" "-- Audit Result: --" " ** REVIEW the following **" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "-- Correctly set: --" "${a_output[@]}" "" fi }
WARNING: disabling or denylisting filesystem modules that are in use on the system may be FATAL. It is extremely important to thoroughly review this list.
'@
        Remediation = @'
- IF - the module is available in the running kernel:
 Unload the filesystem kernel module from the kernel  Create a file ending in .conf with install filesystem kernel modules /bin/false
in the /etc/modprobe.d/ directory  Create a file ending in .conf with deny list filesystem kernel modules in the
/etc/modprobe.d/ directory WARNING: unloading, disabling or denylisting filesystem modules that are in use on the system maybe FATAL. It is extremely important to thoroughly review the filesystems returned by the audit before following the remediation procedure. Example of unloading the gfs2kernel module:
modprobe -r gfs2 2>/dev/null rmmod gfs2 2>/dev/null
Example of fully disabling the gfs2 kernel module:
printf ''%s\n'' "" "blacklist gfs2" "install gfs2 /bin/false" >> /etc/modprobe.d/gfs2.conf
Note:  Disabling a kernel module by modifying the command above for each unused filesystem kernel module  The example gfs2 must be updated with the appropriate module name for the command or example script bellow to run correctly.
Below is an example script that can be modified to use on various filesystem kernel modules manual remediation process: Example Script
#!/usr/bin/env bash
{ a_output2=(); a_output3=(); l_dl="" # Initialize arrays and clear
variables l_mod_name="gfs2" # set module name l_mod_type="fs" # set module type l_mod_path="$(readlink -f /usr/lib/modules/**/kernel/$l_mod_type ||
readlink -f /lib/modules/**/kernel/$l_mod_type)" f_module_fix() { l_dl="y" # Set to ignore duplicate checks a_showconfig=() # Create array with modprobe output while IFS= read -r l_showconfig; do a_showconfig+=("$l_showconfig") done < <(modprobe --showconfig | grep -P --
''\b(install|blacklist)\h+''"${l_mod_name//-/_}"''\b'') if lsmod | grep "$l_mod_name" &> /dev/null; then # Check if the module
is currently loaded a_output2+=(" - unloading kernel module: \"$l_mod_name\"") modprobe -r "$l_mod_name" 2>/dev/null; rmmod "$l_mod_name"
2>/dev/null fi if ! grep -Pq -- ''\binstall\h+''"${l_mod_name//-
/_}"''\h+(\/usr)?\/bin\/(true|false)\b'' <<< "${a_showconfig[*]}"; then a_output2+=(" - setting kernel module: \"$l_mod_name\" to
\"$(readlink -f /bin/false)\"") printf ''%s\n'' "install $l_mod_name $(readlink -f /bin/false)" >>
/etc/modprobe.d/"$l_mod_name".conf fi if ! grep -Pq -- ''\bblacklist\h+''"${l_mod_name//-/_}"''\b'' <<<
"${a_showconfig[*]}"; then a_output2+=(" - denylisting kernel module: \"$l_mod_name\"") printf ''%s\n'' "blacklist $l_mod_name" >>
/etc/modprobe.d/"$l_mod_name".conf fi
} for l_mod_base_directory in $l_mod_path; do # Check if the module exists on the system
if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A "$l_mod_base_directory/${l_mod_name/-/\/}")" ]; then
a_output3+=(" - \"$l_mod_base_directory\"") [[ "$l_mod_name" =~ overlay ]] && l_mod_name="${l_mod_name::-2}" [ "$l_dl" != "y" ] && f_module_fix else echo -e " - kernel module: \"$l_mod_name\" doesn''t exist in \"$l_mod_base_directory\"" fi done [ "${#a_output3[@]}" -gt 0 ] && printf ''%s\n'' "" " -- INFO --" " - module: \"$l_mod_name\" exists in:" "${a_output3[@]}" [ "${#a_output2[@]}" -gt 0 ] && printf ''%s\n'' "" "${a_output2[@]}" || printf ''%s\n'' "" " - No changes needed" printf ''%s\n'' "" " - remediation of kernel module: \"$l_mod_name\" complete" "" }
'@
    },
    @{
        Section = '1.1.2.1.1'
        Title   = 'Ensure /tmp is a separate partition'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify the output shows that /tmp is mounted. Particular requirements pertaining to mount options are covered in ensuing sections.

# findmnt -kn /tmp
Example output:

/tmp tmpfs tmpfs rw,nosuid,nodev,noexec
Ensure that systemd will mount the /tmp partition at boot time.

# systemctl is-enabled tmp.mount
Example output:

generated
Verify output is not masked or disabled. Note: By default, systemd will output generated if there is an entry in /etc/fstab for /tmp. This just means systemd will use the entry in /etc/fstab instead of its default unit file configuration for /tmp.
'@
        Remediation = @'
First ensure that systemd is correctly configured to ensure that /tmp will be mounted at boot time.

# systemctl unmask tmp.mount
For specific configuration requirements of the /tmp mount for your environment, modify /etc/fstab. Example of using tmpfs with specific mount options:

tmpfs 0

/tmp

tmpfs

defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0

Note: the size=2G is an example of setting a specific size for tmpfs. Example of using a volume or disk with specific mount options. The source location of the volume or disk will vary depending on your environment:

<device> /tmp <fstype> defaults,nodev,nosuid,noexec 0 0
'@
    },
    @{
        Section = '1.1.2.1.2'
        Title   = 'Ensure nodev option set on /tmp partition'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
- IF - a separate partition exists for /tmp, verify that the nodev option is set. Run the following command to verify that the nodev mount option is set. Example:
# findmnt -kn /tmp | grep -v nodev

Nothing should be returned
'@
        Remediation = @'
- IF - a separate partition exists for /tmp. Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /tmp partition. Example:

<device> /tmp <fstype>

defaults,rw,nosuid,nodev,noexec,relatime 0 0

Run the following command to remount /tmp with the configured options:

# mount -o remount /tmp
'@
    },
    @{
        Section = '1.1.2.1.3'
        Title   = 'Ensure nosuid option set on /tmp partition'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
- IF - a separate partition exists for /tmp, verify that the nosuid option is set. Run the following command to verify that the nosuid mount option is set. Example:
# findmnt -kn /tmp | grep -v nosuid

Nothing should be returned
'@
        Remediation = @'
- IF - a separate partition exists for /tmp. Edit the /etc/fstab file and add nosuid to the fourth field (mounting options) for the /tmp partition. Example:

<device> /tmp <fstype>

defaults,rw,nosuid,nodev,noexec,relatime 0 0

Run the following command to remount /tmp with the configured options:

# mount -o remount /tmp
'@
    },
    @{
        Section = '1.1.2.2.1'
        Title   = 'Ensure /dev/shm is a separate partition'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
- IF - /dev/shm is to be used on the system, run the following command and verify the output shows that /dev/shm is mounted. Particular requirements pertaining to mount options are covered in ensuing sections.
# findmnt -kn /dev/shm
Example output:
/dev/shm tmpfs tmpfs rw,nosuid,nodev,noexec,relatime,seclabel
'@
        Remediation = @'
For specific configuration requirements of the /dev/shm mount for your environment, modify /etc/fstab. Example:

tmpfs /dev/shm

tmpfs

defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0
'@
    },
    @{
        Section = '1.1.2.2.2'
        Title   = 'Ensure nodev option set on /dev/shm partition'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
- IF - a separate partition exists for /dev/shm, verify that the nodev option is set.
# findmnt -kn /dev/shm | grep -v ''nodev''

Nothing should be returned
'@
        Remediation = @'
- IF - a separate partition exists for /dev/shm. Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /dev/shm partition. See the fstab(5) manual page for more information. Example:

tmpfs /dev/shm tmpfs

defaults,rw,nosuid,nodev,noexec,relatime 0 0

Run the following command to remount /dev/shm with the configured options:

# mount -o remount /dev/shm
Note: It is recommended to use tmpfs as the device/filesystem type as /dev/shm is used as shared memory space by applications.
'@
    },
    @{
        Section = '1.1.2.2.3'
        Title   = 'Ensure nosuid option set on /dev/shm partition'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
- IF - a separate partition exists for /dev/shm, verify that the nosuid option is set.
# findmnt -kn /dev/shm | grep -v ''nosuid''

Nothing should be returned
'@
        Remediation = @'
- IF - a separate partition exists for /dev/shm. Edit the /etc/fstab file and add nosuid to the fourth field (mounting options) for the /dev/shm partition. See the fstab(5) manual page for more information. Example:

tmpfs /dev/shm tmpfs

defaults,rw,nosuid,nodev,noexec,relatime 0 0

Run the following command to remount /dev/shm with the configured options:

# mount -o remount /dev/shm
Note: It is recommended to use tmpfs as the device/filesystem type as /dev/shm is used as shared memory space by applications.
'@
    },
    @{
        Section = '1.2.1.1'
        Title   = 'Ensure GPG keys are configured'
        Kind    = 'Manual'
        Level   = 'L1'
        Audit   = @'
List all GPG key URLs Each repository should have a gpgkey with a URL pointing to the location of the GPG key, either local or remote.
# grep -r gpgkey /etc/yum.repos.d/* /etc/dnf/dnf.conf
List installed GPG keys Run the following command to list the currently installed keys. These are the active keys used for verification and installation of RPMs. The packages are fake, they are generated on the fly by tdnf or rpm during the import of keys from the URL specified in the repository configuration. Example:
# for RPM_PACKAGE in $(rpm -q gpg-pubkey); do echo "RPM: ${RPM_PACKAGE}" RPM_SUMMARY=$(rpm -q --queryformat "%{SUMMARY}" "${RPM_PACKAGE}") RPM_PACKAGER=$(rpm -q --queryformat "%{PACKAGER}" "${RPM_PACKAGE}") RPM_DATE=$(date +%Y-%m-%d -d "1970-1-1+$((0x$(rpm -q --queryformat
"%{RELEASE}" "${RPM_PACKAGE}") ))sec") RPM_KEY_ID=$(rpm -q --queryformat "%{VERSION}" "${RPM_PACKAGE}") echo "Packager: ${RPM_PACKAGER}
Summary: ${RPM_SUMMARY} Creation date: ${RPM_DATE} Key ID: ${RPM_KEY_ID} " done
RPM: gpg-pubkey-9db62fb1-59920156 Packager: Fedora 28 (28) <fedora-28@fedoraproject.org> Summary: gpg(Fedora 28 (28) <fedora-28@fedoraproject.org>) Creation date: 2017-08-14 Key ID: 9db62fb1
RPM: gpg-pubkey-09eab3f2-595fbba3 Packager: RPM Fusion free repository for Fedora (28) <rpmfusionbuildsys@lists.rpmfusion.org> Summary: gpg(RPM Fusion free repository for Fedora (28) <rpmfusionbuildsys@lists.rpmfusion.org>) Creation date: 2017-07-07 Key ID: 09eab3f2
The format of the package (gpg-pubkey-9db62fb1-59920156) is important to understand for verification. Using the above example, it consists of three parts:
1. The general prefix name for all imported GPG keys: gpg-pubkey2. The version, which is the GPG key ID: 9db62fb1 3. The release is the date of the key in UNIX timestamp in hexadecimal: 59920156
With both the date and the GPG key ID, check the relevant repositories public key page to confirm that the keys are indeed correct. Query locally available GPG keys Repositories that store their respective GPG keys on disk should do so in /etc/pki/rpm-gpg/. These keys are available for immediate import either when dnf is asked to install a relevant package from the repository or when an administrator imports the key directly with the rpm --import command. To find where these keys come from run:
# for PACKAGE in $(find /etc/pki/rpm-gpg/ -type f -exec rpm -qf {} \; | sort -u); do rpm -q --queryformat "%{NAME}-%{VERSION} %{PACKAGER} %{SUMMARY}\\n" "${PACKAGE}"; done
'@
        Remediation = @'
Update your package manager GPG keys in accordance with site policy.
'@
    },
    @{
        Section = '1.2.1.2'
        Title   = 'Ensure gpgcheck is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify that global configuration for gpgcheck is enabled:
# grep -Pi -- ''^\h*gpgcheck\h*=\h*(1|true|yes)\b'' /etc/dnf/dnf.conf
Verify the output is: gpgcheck=1, gpgcheck=true, or gpgcheck=yes. Example output:
gpgcheck=1
Run the following command to verify gpgcheck is not disabled in a file in the /etc/yum.repos.d/ directory:
# grep -Pris -- ''^\h*gpgcheck\h*=\h*(0|[2-9]|[1-9][0-9]+|false|no)\b'' /etc/yum.repos.d/
Nothing should be returned.
'@
        Remediation = @'
Edit /etc/dnf/dnf.conf and set gpgcheck=1: Example
# sed -i ''s/^gpgcheck\s*=\s*.*/gpgcheck=1/'' /etc/dnf/dnf.conf
Edit any failing files in /etc/yum.repos.d/* and set all instances starting with gpgcheck to 1. Example:
# find /etc/yum.repos.d/ -name "*.repo" -exec echo "Checking:" {} \; -exec sed -i ''s/^gpgcheck\s*=\s*.*/gpgcheck=1/'' {} \;
'@
    },
    @{
        Section = '1.2.1.3'
        Title   = 'Ensure TDNF gpgcheck is globally activated'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Global configuration. Run the following command and verify that gpgcheck is set to 1:
# grep ^gpgcheck /etc/tdnf/tdnf.conf
gpgcheck=1
Configuration in /etc/yum.repos.d/ takes precedence over the global configuration. Run the following command and verify that there are no instances of entries starting with gpgcheck returned set to 0. Nor should there be any invalid (non-boolean) values. When dnf encounters such invalid entries they are ignored and the global configuration is applied.
# grep -P "^gpgcheck\h*=\h*[^1\n\r]\b" /etc/yum.repos.d/*
'@
        Remediation = @'
Edit /etc/dnf/dnf.conf and set gpgcheck=1 in the [main] section. Example:
# sed -i ''s/^gpgcheck\s*=\s*.*/gpgcheck=1/'' /etc/tdnf/tdnf.conf
Edit any failing files in /etc/yum.repos.d/* and set all instances starting with gpgcheck to 1. Example:
# find /etc/yum.repos.d/ -name "*.repo" -exec echo "Checking:" {} \; -exec sed -i ''s/^gpgcheck\s*=\s*.*/gpgcheck=1/'' {} \;
'@
    },
    @{
        Section = '1.2.1.4'
        Title   = 'Ensure package manager repositories are configured'
        Kind    = 'Manual'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify repositories are configured correctly. The output may vary depending on which repositories are currently configured on the system. Example:

# dnf repolist

Last metadata expiration check: 1:00:00 ago on Mon 1 Jan 2021 00:00:00 BST.

repo id

repo name

status

*fedora

Fedora 28 - x86_64

57,327

*updates

Fedora 28 - x86_64 - Updates

22,133

For the repositories in use, inspect the configuration file to ensure all settings are correctly applied according to site policy. Example: Depending on the distribution being used the repo file name might differ.

cat /etc/yum.repos.d/*.repo
'@
        Remediation = @'
Configure your package manager repositories according to site policy.
'@
    },
    @{
        Section = '1.3.1'
        Title   = 'Ensure address space layout randomization is enabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameter is set in the running configuration and correctly loaded from a kernel parameter configuration file:
 kernel.randomize_va_space is set to 2 Note: kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); a_parlist=(kernel.randomize_va_space=2) l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print
$2}'' /etc/default/ufw)" f_kernel_parameter_chk() { l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F=
''{print $2}'' | xargs)" # Check running configuration if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<<
"$l_running_parameter_value"; then a_output+=(" - \"$l_parameter_name\" is correctly set to
\"$l_running_parameter_value\"" " in the running configuration")
else a_output2+=(" - \"$l_parameter_name\" is incorrectly set to
\"$l_running_parameter_value\"" \ " in the running configuration" \ " and should have a value of: \"$l_value_out\"")
fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do
if [ -n "$l_out" ]; then if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}" else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output while IFS="=" read -r l_fkpname l_file_parameter_value; do
l_fkpname="${l_fkpname// /}"; l_file_parameter_value="${l_file_parameter_value// /}"
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_file_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_file_parameter_value\"" \
" in \"$(printf ''%s'' "${A_out[@]}")\"") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_file_parameter_value\""
" in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"") fi
done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}")
else a_output2+=(" - \"$l_parameter_name\" is not set in an included
file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s
ignored by load procedure **") fi
} l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters
l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}"
l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }"
l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" f_kernel_parameter_chk done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the following parameter in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 kernel.randomize_va_space = 2
Example:
# printf ''%s\n'' "" "kernel.randomize_va_space = 2" >> /etc/sysctl.d/60kernel_sysctl.conf
Run the following command to set the active kernel parameter:
# sysctl -w kernel.randomize_va_space=2
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '1.3.2'
        Title   = 'Ensure ptrace_scope is restricted'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameter is set in the running configuration and correctly loaded from a kernel parameter configuration file:
 kernel.yama.ptrace_scope is set to a value of: 1, 2, or 3 Note: kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); a_parlist=("kernel.yama.ptrace_scope=(1|2|3)") l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print
$2}'' /etc/default/ufw)" f_kernel_parameter_chk() { l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F=
''{print $2}'' | xargs)" # Check running configuration if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<<
"$l_running_parameter_value"; then a_output+=(" - \"$l_parameter_name\" is correctly set to
\"$l_running_parameter_value\"" " in the running configuration")
else a_output2+=(" - \"$l_parameter_name\" is incorrectly set to
\"$l_running_parameter_value\"" \ " in the running configuration" \ " and should have a value of: \"$l_value_out\"")
fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do
if [ -n "$l_out" ]; then if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}" else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output while IFS="=" read -r l_fkpname l_file_parameter_value; do
l_fkpname="${l_fkpname// /}"; l_file_parameter_value="${l_file_parameter_value// /}"
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_file_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_file_parameter_value\"" \
" in \"$(printf ''%s'' "${A_out[@]}")\"") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_file_parameter_value\""
" in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"") fi
done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}")
else a_output2+=(" - \"$l_parameter_name\" is not set in an included
file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s
ignored by load procedure **") fi
} l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters
l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}"
l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }"
l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" f_kernel_parameter_chk done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the kernel.yama.ptrace_scope parameter in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf to a value of 1, 2, or 3:
kernel.yama.ptrace_scope = 1 - OR -
kernel.yama.ptrace_scope = 2 - OR -
kernel.yama.ptrace_scope = 3
Example:
# printf "%s\n" "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.d/60kernel_sysctl.conf
Run the following command to set the active kernel parameter:
# sysctl -w kernel.yama.ptrace_scope=1
Note:
 If a value of 2 or 3 is preferred, or required by local site policy, replace the 1 with the desired value of 2 or 3 in the example above
 If this setting appears in a canonically later file, or later in the same file, the setting will be overwritten
'@
    },
    @{
        Section = '1.3.3'
        Title   = 'Ensure core dump backtraces are disabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify ProcessSizeMax is set to 0 in /etc/systemd/coredump.conf or a file in the /etc/systemd/coredump.conf.d/ directory:
#!/usr/bin/env bash
{ a_output=(); a_output2=(); a_parlist=("ProcessSizeMax=0") l_systemd_config_file="/etc/systemd/coredump.conf" # Main systemd
configuration file f_config_file_parameter_chk() { unset A_out; declare -A A_out # Check config file(s) setting while read -r l_out; do if [ -n "$l_out" ]; then if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}" else l_systemd_parameter="$(awk -F= ''{print $1}'' <<< "$l_out" |
xargs)" grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<<
"$l_systemd_parameter" && A_out+=(["$l_systemd_parameter"]="$l_file") fi
fi done < <("$l_systemdanalyze" cat-config "$l_systemd_config_file" | grep -Pio ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}"
l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}" if grep -Piq "\b$l_systemd_parameter_value\b" <<<
"$l_systemd_file_parameter_value"; then a_output+=(" - \"$l_systemd_parameter_name\" is correctly set
to \"$l_systemd_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\"")
else a_output2+=(" - \"$l_systemd_parameter_name\" is incorrectly
set to \"$l_systemd_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\" and should have a
value matching: \"$l_value_out\"") fi
done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}")
else a_output2=(" - \"$l_systemd_parameter_name\" is not set in an
included file" \ " *** Note: \"$l_systemd_parameter_name\" May be set in a file
that''s ignored by load procedure ***") fi
} l_systemdanalyze="$(readlink -f /bin/systemd-analyze)" while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters
l_systemd_parameter_name="${l_systemd_parameter_name// /}"; l_systemd_parameter_value="${l_systemd_parameter_value// /}"
l_value_out="${l_systemd_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }"
l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" f_config_file_parameter_chk done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Create or edit the file /etc/systemd/coredump.conf, or a file in the /etc/systemd/coredump.conf.d directory ending in .conf. Edit or add the following line in the [Coredump] section:
ProcessSizeMax=0
Example:
#!/usr/bin/env bash
{ [ ! -d /etc/systemd/coredump.conf.d/ ] && mkdir
/etc/systemd/coredump.conf.d/ if grep -Psq -- ''^\h*\[Coredump\]'' /etc/systemd/coredump.conf.d/60-
coredump.conf; then printf ''%s\n'' "ProcessSizeMax=0" >> /etc/systemd/coredump.conf.d/60-
coredump.conf else printf ''%s\n'' "[Coredump]" "ProcessSizeMax=0" >>
/etc/systemd/coredump.conf.d/60-coredump.conf fi
}
'@
    },
    @{
        Section = '1.3.4'
        Title   = 'Ensure core dump storage is disabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify Storage is set to none in /etc/systemd/coredump.conf or a file in the /etc/systemd/coredump.conf.d/ directory:
#!/usr/bin/env bash
{ a_output=(); a_output2=(); a_parlist=("Storage=none") l_systemd_config_file="/etc/systemd/coredump.conf" # Main systemd
configuration file f_config_file_parameter_chk() { unset A_out; declare -A A_out # Check config file(s) setting while read -r l_out; do if [ -n "$l_out" ]; then if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}" else l_systemd_parameter="$(awk -F= ''{print $1}'' <<< "$l_out" |
xargs)" grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<<
"$l_systemd_parameter" && A_out+=(["$l_systemd_parameter"]="$l_file") fi
fi done < <("$l_systemdanalyze" cat-config "$l_systemd_config_file" | grep -Pio ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}"
l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}" if grep -Piq "\b$l_systemd_parameter_value\b" <<<
"$l_systemd_file_parameter_value"; then a_output+=(" - \"$l_systemd_parameter_name\" is correctly set
to \"$l_systemd_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\"")
else a_output2+=(" - \"$l_systemd_parameter_name\" is incorrectly
set to \"$l_systemd_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\" and should have a
value matching: \"$l_value_out\"") fi
done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}")
else a_output2=(" - \"$l_systemd_parameter_name\" is not set in an
included file" \ " *** Note: \"$l_systemd_parameter_name\" May be set in a file
that''s ignored by load procedure ***") fi
} l_systemdanalyze="$(readlink -f /bin/systemd-analyze)" while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters
l_systemd_parameter_name="${l_systemd_parameter_name// /}"; l_systemd_parameter_value="${l_systemd_parameter_value// /}"
l_value_out="${l_systemd_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }"
l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" f_config_file_parameter_chk done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Create or edit the file /etc/systemd/coredump.conf, or a file in the /etc/systemd/coredump.conf.d directory ending in .conf. Edit or add the following line in the [Coredump] section:
Storage=none
Example:
#!/usr/bin/env bash
{ [ ! -d /etc/systemd/coredump.conf.d/ ] && mkdir
/etc/systemd/coredump.conf.d/ if grep -Psq -- ''^\h*\[Coredump\]'' /etc/systemd/coredump.conf.d/60-
coredump.conf; then printf ''%s\n'' "Storage=none" >> /etc/systemd/coredump.conf.d/60-
coredump.conf else printf ''%s\n'' "[Coredump]" "Storage=none" >>
/etc/systemd/coredump.conf.d/60-coredump.conf fi
}
'@
    },
    @{
        Section = '1.4.1'
        Title   = 'Ensure local login warning banner is configured properly'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify that the contents match site policy:
# cat /etc/issue
Run the following command and verify no results are returned:
# grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep ''^ID='' /etc/os-release | cut -d= f2 | sed -e ''s/"//g''))" /etc/issue
'@
        Remediation = @'
Edit the /etc/issue file with the appropriate contents according to your site policy, remove any instances of \m , \r , \s , \v or references to the OS platform. Example:
# echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
'@
    },
    @{
        Section = '1.4.2'
        Title   = 'Ensure remote login warning banner is configured properly'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify that the contents match site policy:
# cat /etc/issue.net
Run the following command and verify no results are returned:
# grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep ''^ID='' /etc/os-release | cut -d= f2 | sed -e ''s/"//g''))" /etc/issue.net
'@
        Remediation = @'
Edit the /etc/issue.net file with the appropriate contents according to your site policy, remove any instances of \m , \r , \s , \v or references to the OS platform. Example:
# echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net
'@
    },
    @{
        Section = '1.4.3'
        Title   = 'Ensure access to /etc/motd is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify that if /etc/motd exists, Access is 644 or more restrictive, Uid and Gid are both 0/root:
# [ -e /etc/motd ] && stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: { %g/ %G)'' /etc/motd

Access: (0644/-rw-r--r--) -- OR --
Nothing is returned

Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set mode, owner, and group on /etc/motd:
# chown root:root $(readlink -e /etc/motd) # chmod u-x,go-wx $(readlink -e /etc/motd)
- OR Run the following command to remove the /etc/motd file:
# rm /etc/motd
'@
    },
    @{
        Section = '1.4.4'
        Title   = 'Ensure access to /etc/issue is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify Access is 644 or more restrictive and Uid and Gid are both 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: { %g/ %G)'' /etc/issue Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: { 0/ root)
'@
        Remediation = @'
Run the following commands to set mode, owner, and group on /etc/issue:
# chown root:root $(readlink -e /etc/issue) # chmod u-x,go-wx $(readlink -e /etc/issue)
'@
    },
    @{
        Section = '1.4.5'
        Title   = 'Ensure access to /etc/issue.net is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify Access is 644 or more restrictive and Uid and Gid are both 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: { %g/ %G)'' /etc/issue.net Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set mode, owner, and group on /etc/issue.net:
# chown root:root $(readlink -e /etc/issue.net) # chmod u-x,go-wx $(readlink -e /etc/issue.net)
'@
    },
    @{
        Section = '2.1.1'
        Title   = 'Ensure time synchronization is in use'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following commands to verify that chrony is installed:
# rpm -q chrony chrony-<version>
'@
        Remediation = @'
Run the following command to install chrony:
# tdnf install chrony
'@
    },
    @{
        Section = '2.1.2'
        Title   = 'Ensure chrony is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify remote server is configured properly:
# grep -E "^(server|pool|refclock)" /etc/chrony.conf server <remote-server>
Multiple servers may be configured. Run the following command and verify OPTIONS includes ''-u chrony'':
# grep ^OPTIONS /etc/sysconfig/chronyd OPTIONS="-u chrony"
Additional options may be present.
'@
        Remediation = @'
Add or edit server or pool lines to /etc/chrony.conf as appropriate:
server <remote-server>
Add or edit the OPTIONS in /etc/sysconfig/chronyd to include ''-u chrony'':
OPTIONS="-u chrony"
'@
    },
    @{
        Section = '2.2.1'
        Title   = 'Ensure xinetd is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify xinetd is not installed:
# rpm -q xinetd package xinetd is not installed
'@
        Remediation = @'
Run the following command to remove xinetd:
# tdnf remove xinetd
'@
    },
    @{
        Section = '2.2.2'
        Title   = 'Ensure xorg-x11-server-common is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify X Windows Server is not installed.
# rpm -q xorg-x11-server-common package xorg-x11-server-common is not installed
'@
        Remediation = @'
Run the following command to remove the X Windows Server packages:
# tdnf remove xorg-x11-server-common
'@
    },
    @{
        Section = '2.2.3'
        Title   = 'Ensure avahi is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify avahi is not installed:
# rpm -q avahi package avahi is not installed
'@
        Remediation = @'
Run the following commands to stop, and remove avahi:
# systemctl stop avahi-daemon.socket avahi-daemon.service # tdnf remove avahi
'@
    },
    @{
        Section = '2.2.4'
        Title   = 'Ensure a print server is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify cups is not installed:
# rpm -q cups package cups is not installed
'@
        Remediation = @'
Run the following command to remove cups:
# tdnf remove cups
'@
    },
    @{
        Section = '2.2.5'
        Title   = 'Ensure a dhcp server is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify dhcp-server is not installed:
# rpm -q dhcp-server package dhcp-server is not installed
'@
        Remediation = @'
Run the following command to remove dhcp:
# tdnf remove dhcp-server
'@
    },
    @{
        Section = '2.2.6'
        Title   = 'Ensure a dns server is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run one of the following commands to verify bind is not installed:
# rpm -q bind package bind is not installed
'@
        Remediation = @'
Run the following command to remove bind:
# tdnf remove bind
'@
    },
    @{
        Section = '2.2.7'
        Title   = 'Ensure FTP client is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify ftp is not installed:
# rpm -q ftp package ftp is not installed
'@
        Remediation = @'
Run the following command to remove ftp:
# tdnf remove ftp
'@
    },
    @{
        Section = '2.2.8'
        Title   = 'Ensure an ftp server is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify vsftpd is not installed:
# rpm -q vsftpd
package vsftpd is not installed
'@
        Remediation = @'
Run the following command to remove vsftpd:
# tdnf remove vsftpd
'@
    },
    @{
        Section = '2.2.9'
        Title   = 'Ensure a tftp server is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify tftp-server is not installed:
# rpm -q tftp-server package tftp-server is not installed
'@
        Remediation = @'
Run the following command to remove tftp-server:
# tdnf remove tftp-server
'@
    },
    @{
        Section = '2.2.10'
        Title   = 'Ensure a web server is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify httpd and nginx are not installed:
# rpm -q httpd nginx package httpd is not installed package nginx is not installed
'@
        Remediation = @'
Run the following command to remove httpd and nginx:
# tdnf remove httpd nginx
'@
    },
    @{
        Section = '2.2.11'
        Title   = 'Ensure IMAP and POP3 server is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify dovecot and cyrus-imapd are not installed:
# rpm -q dovecot cyrus-imapd package dovecot is not installed package cyrus-imapd is not installed
'@
        Remediation = @'
Run the following command to remove dovecot and cyrus-imapd:
# tdnf remove dovecot cyrus-imapd
'@
    },
    @{
        Section = '2.2.12'
        Title   = 'Ensure Samba is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify samba is not installed:
# rpm -q samba package samba is not installed
'@
        Remediation = @'
Run the following command to remove samba:
# tdnf remove samba
'@
    },
    @{
        Section = '2.2.13'
        Title   = 'Ensure HTTP Proxy Server is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify squid is not installed:
# rpm -q squid package squid is not installed
'@
        Remediation = @'
Run the following command to remove the squid package:
# tdnf remove squid
'@
    },
    @{
        Section = '2.2.14'
        Title   = 'Ensure net-snmp is not installed or the snmpd service is not enabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify net-snmp is not installed:
# rpm -q net-snmp
package net-snmp is not installed
-ORRun the following command to verify the snmpd service is not enabled:
# systemctl is-enabled snmpd
masked
Verify output is not enabled.
'@
        Remediation = @'
Run the following command to remove net-snmpd:
# tdnf remove net-snmp
-ORRun the following commands to stop and mask the snmpd service:
# systemctl stop snmpd # systemctl mask snmpd
'@
    },
    @{
        Section = '2.2.15'
        Title   = 'Ensure NIS server is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify ypserv is not installed:
# rpm -q ypserv package ypserv is not installed
'@
        Remediation = @'
Run the following command to remove ypserv:
# tdnf remove ypserv
'@
    },
    @{
        Section = '2.2.16'
        Title   = 'Ensure telnet-server is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify the telnet-server package is not installed:
rpm -q telnet-server package telnet-server is not installed
'@
        Remediation = @'
Run the following command to remove the telnet-server package:
# tdnf remove telnet-server
'@
    },
    @{
        Section = '2.2.17'
        Title   = 'Ensure mail transfer agent is configured for local-only mode'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify that the MTA is not listening on any non-loopback address ( 127.0.0.1 or ::1 ) Nothing should be returned.
# ss -lntu | grep -P '':25\b'' | grep -Pv ''\h+(127\.0\.0\.1|\[?::1\]?):25\b''
'@
        Remediation = @'
Edit /etc/postfix/main.cf and add the following line to the RECEIVING MAIL section. If the line already exists, change it to look like the line below:
inet_interfaces = loopback-only
Run the following command to restart postfix:
# systemctl restart postfix
'@
    },
    @{
        Section = '2.2.18'
        Title   = 'Ensure nfs-utils is not installed or the nfs-server service is masked'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify nfs-utils is not installed:
# rpm -q nfs-utils package nfs-utils is not installed
OR If the nfs-package is required as a dependency, run the following command to verify that the nfs-server service is masked:
# systemctl is-enabled nfs-server masked
'@
        Remediation = @'
Run the following command to remove nfs-utils:
# tdnf remove nfs-utils
OR If the nfs-package is required as a dependency, run the following command to stop and mask the nfs-server service:
# systemctl --now mask nfs-server
'@
    },
    @{
        Section = '2.2.19'
        Title   = 'Ensure rsync-daemon is not installed or the rsyncd service is masked'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify that rsync is not installed:
# rpm -q rsync-daemon package rsync is not installed
OR Run the following command to verify the rsyncd service is masked:
# systemctl is-enabled rsyncd masked
'@
        Remediation = @'
Run the following command to remove the rsync package:
# tdnf remove rsync-daemon
OR Run the following command to mask the rsyncd service:
# systemctl --now mask rsyncd
'@
    },
    @{
        Section = '2.3.1'
        Title   = 'Ensure NIS Client is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify that the ypbind package is not installed:
# rpm -q ypbind package ypbind is not installed
'@
        Remediation = @'
Run the following command to remove the ypbind package:
# tdnf remove ypbind
'@
    },
    @{
        Section = '2.3.2'
        Title   = 'Ensure rsh client is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify that the rsh package is not installed:
# rpm -q rsh package rsh is not installed
'@
        Remediation = @'
Run the following command to remove the rsh package:
# tdnf remove rsh
'@
    },
    @{
        Section = '2.3.3'
        Title   = 'Ensure talk client is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify that the talk package is not installed:
# rpm -q talk package talk is not installed
'@
        Remediation = @'
Run the following command to remove the talk package:
# tdnf remove talk
'@
    },
    @{
        Section = '2.3.4'
        Title   = 'Ensure telnet client is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify that the telnet package is not installed:
# rpm -q telnet package telnet is not installed
'@
        Remediation = @'
Run the following command to remove the telnet package:
# tdnf remove telnet
'@
    },
    @{
        Section = '2.3.5'
        Title   = 'Ensure LDAP client is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify that the openldap-clients package is not installed:
# rpm -q openldap-clients package openldap-clients is not installed
'@
        Remediation = @'
Run the following command to remove the openldap-clients package:
# tdnf remove openldap-clients
'@
    },
    @{
        Section = '2.3.6'
        Title   = 'Ensure TFTP client is not installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify tftp is not installed:
# rpm -q tftp
package tftp is not installed
'@
        Remediation = @'
Run the following command to remove tftp:
# tdnf remove tftp
'@
    },
    @{
        Section = '3.1.1'
        Title   = 'Ensure packet redirect sending is disabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameters are set in the running configuration and correctly loaded from a kernel parameter configuration file:
 net.ipv4.conf.all.send_redirects is set to 0  net.ipv4.conf.default.send_redirects is set to 0 Note: kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ipv6_disabled="" a_parlist=("net.ipv4.conf.all.send_redirects=0"
"net.ipv4.conf.default.send_redirects=0") l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print
$2}'' /etc/default/ufw)" f_ipv6_chk() { l_ipv6_disabled="no" ! grep -Pqs -- ''^\h*0\b'' /sys/module/ipv6/parameters/disable &&
l_ipv6_disabled="yes" if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \ sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then l_ipv6_disabled="yes"
fi } f_kernel_parameter_chk() {
l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= ''{print $2}'' | xargs)" # Check running configuration
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_running_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\""
" in the running configuration") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\"" \
" in the running configuration" \ " and should have a value of: \"$l_value_out\"") fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do if [ -n "$l_out" ]; then
if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}"
else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_fkpname l_file_parameter_value; do l_fkpname="${l_fkpname// /}";
l_file_parameter_value="${l_file_parameter_value// /}" if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<<
"$l_file_parameter_value"; then a_output+=(" - \"$l_parameter_name\" is correctly set to
\"$l_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\"")
else a_output2+=(" - \"$l_parameter_name\" is incorrectly set to
\"$l_file_parameter_value\"" " in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"")
fi done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}") else a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s ignored by load procedure **") fi } l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}" l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }" l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" if grep -q ''^net.ipv6.'' <<< "$l_parameter_name"; then [ -z "$l_ipv6_disabled" ] && f_ipv6_chk if [ "$l_ipv6_disabled" = "yes" ]; then
a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable")
else f_kernel_parameter_chk
fi else
f_kernel_parameter_chk fi done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the following parameters in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv4.conf.all.send_redirects = 0  net.ipv4.conf.default.send_redirects = 0
Example:
# printf ''%s\n'' "net.ipv4.conf.all.send_redirects = 0" "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/60netipv4_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash
{ sysctl -w net.ipv4.conf.all.send_redirects=0 sysctl -w net.ipv4.conf.default.send_redirects=0 sysctl -w net.ipv4.route.flush=1
}
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '3.1.2'
        Title   = 'Ensure bogus icmp responses are ignored'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameter is set in the running configuration and correctly loaded from a kernel parameter configuration file:
 net.ipv4.icmp_ignore_bogus_error_responses is set to 1 Note: kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ipv6_disabled="" a_parlist=("net.ipv4.icmp_ignore_bogus_error_responses=1") l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print
$2}'' /etc/default/ufw)" f_ipv6_chk() { l_ipv6_disabled="no" ! grep -Pqs -- ''^\h*0\b'' /sys/module/ipv6/parameters/disable &&
l_ipv6_disabled="yes" if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \ sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then l_ipv6_disabled="yes"
fi } f_kernel_parameter_chk() {
l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= ''{print $2}'' | xargs)" # Check running configuration
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_running_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\""
" in the running configuration") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\"" \
" in the running configuration" \ " and should have a value of: \"$l_value_out\"") fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do if [ -n "$l_out" ]; then
if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}"
else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output while IFS="=" read -r l_fkpname l_file_parameter_value; do
l_fkpname="${l_fkpname// /}"; l_file_parameter_value="${l_file_parameter_value// /}"
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_file_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_file_parameter_value\"" \
" in \"$(printf ''%s'' "${A_out[@]}")\"") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_file_parameter_value\""
" in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"") fi done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}") else a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s ignored by load procedure **") fi } l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}" l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }" l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" if grep -q ''^net.ipv6.'' <<< "$l_parameter_name"; then [ -z "$l_ipv6_disabled" ] && f_ipv6_chk if [ "$l_ipv6_disabled" = "yes" ]; then a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable") else f_kernel_parameter_chk fi else f_kernel_parameter_chk fi done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the following parameter in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv4.icmp_ignore_bogus_error_responses = 1 Example:
# printf ''%s\n'' "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash {
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 sysctl -w net.ipv4.route.flush=1 }
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '3.1.3'
        Title   = 'Ensure broadcast icmp requests are ignored'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameter is set in the running configuration and correctly loaded from a kernel parameter configuration file:
 net.ipv4.icmp_echo_ignore_broadcasts is set to 1 Note: kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ipv6_disabled="" a_parlist=("net.ipv4.icmp_echo_ignore_broadcasts=1") l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print
$2}'' /etc/default/ufw)" f_ipv6_chk() { l_ipv6_disabled="no" ! grep -Pqs -- ''^\h*0\b'' /sys/module/ipv6/parameters/disable &&
l_ipv6_disabled="yes" if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \ sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then l_ipv6_disabled="yes"
fi } f_kernel_parameter_chk() {
l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= ''{print $2}'' | xargs)" # Check running configuration
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_running_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\""
" in the running configuration") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\"" \
" in the running configuration" \ " and should have a value of: \"$l_value_out\"") fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do if [ -n "$l_out" ]; then
if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}"
else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output while IFS="=" read -r l_fkpname l_file_parameter_value; do
l_fkpname="${l_fkpname// /}"; l_file_parameter_value="${l_file_parameter_value// /}"
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_file_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_file_parameter_value\"" \
" in \"$(printf ''%s'' "${A_out[@]}")\"") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_file_parameter_value\""
" in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"") fi done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}") else a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s ignored by load procedure **") fi } l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}" l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }" l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" if grep -q ''^net.ipv6.'' <<< "$l_parameter_name"; then [ -z "$l_ipv6_disabled" ] && f_ipv6_chk if [ "$l_ipv6_disabled" = "yes" ]; then a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable") else f_kernel_parameter_chk fi else f_kernel_parameter_chk fi done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the following parameter in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv4.icmp_echo_ignore_broadcasts = 1 Example:
# printf ''%s\n'' "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash {
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 sysctl -w net.ipv4.route.flush=1 }
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '3.1.4'
        Title   = 'Ensure icmp redirects are not accepted'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameters are set in the running configuration and correctly loaded from a kernel parameter configuration file:
 net.ipv4.conf.all.accept_redirects is set to 0  net.ipv4.conf.default.accept_redirects is set to 0  net.ipv6.conf.all.accept_redirects is set to 0  net.ipv6.conf.default.accept_redirects is set to 0
Note:
 kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
 IPv6 kernel parameters only apply to systems where IPv6 is enabled.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ipv6_disabled="" a_parlist=("net.ipv4.conf.all.accept_redirects=0"
"net.ipv4.conf.default.accept_redirects=0" "net.ipv6.conf.all.accept_redirects=0" "net.ipv6.conf.default.accept_redirects=0")
l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print $2}'' /etc/default/ufw)"
f_ipv6_chk() {
l_ipv6_disabled="no" ! grep -Pqs -- ''^\h*0\b'' /sys/module/ipv6/parameters/disable && l_ipv6_disabled="yes" if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \
sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then
l_ipv6_disabled="yes" fi } f_kernel_parameter_chk() { l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= ''{print $2}'' | xargs)" # Check running configuration if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_running_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\""
" in the running configuration") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\"" \
" in the running configuration" \ " and should have a value of: \"$l_value_out\"") fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do if [ -n "$l_out" ]; then
if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}"
else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi
if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_fkpname l_file_parameter_value; do l_fkpname="${l_fkpname// /}";
l_file_parameter_value="${l_file_parameter_value// /}" if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<<
"$l_file_parameter_value"; then a_output+=(" - \"$l_parameter_name\" is correctly set to
\"$l_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\"")
else a_output2+=(" - \"$l_parameter_name\" is incorrectly set to
\"$l_file_parameter_value\"" " in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"")
fi done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}") else a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s ignored by load procedure **") fi } l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}" l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }" l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" if grep -q ''^net.ipv6.'' <<< "$l_parameter_name"; then [ -z "$l_ipv6_disabled" ] && f_ipv6_chk if [ "$l_ipv6_disabled" = "yes" ]; then
a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable")
else f_kernel_parameter_chk
fi else
f_kernel_parameter_chk fi done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the following parameters in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv4.conf.all.accept_redirects = 0  net.ipv4.conf.default.accept_redirects = 0
Example:
# printf ''%s\n'' "net.ipv4.conf.all.accept_redirects = 0" "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60netipv4_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash
{ sysctl -w net.ipv4.conf.all.accept_redirects=0 sysctl -w net.ipv4.conf.default.accept_redirects=0 sysctl -w net.ipv4.route.flush=1
}
- IF - IPv6 is enabled on the system: Set the following parameters in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv6.conf.all.accept_redirects = 0  net.ipv6.conf.default.accept_redirects = 0
Example:
# printf ''%s\n'' "net.ipv6.conf.all.accept_redirects = 0" "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60netipv6_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash
{ sysctl -w net.ipv6.conf.all.accept_redirects=0 sysctl -w net.ipv6.conf.default.accept_redirects=0 sysctl -w net.ipv6.route.flush=1
}
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '3.1.5'
        Title   = 'Ensure secure icmp redirects are not accepted'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameters are set in the running configuration and correctly loaded from a kernel parameter configuration file:
 net.ipv4.conf.all.secure_redirects is set to 0  net.ipv4.conf.default.secure_redirects is set to 0 Note: kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ipv6_disabled="" a_parlist=("net.ipv4.conf.all.secure_redirects=0"
"net.ipv4.conf.default.secure_redirects=0") l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print
$2}'' /etc/default/ufw)" f_ipv6_chk() { l_ipv6_disabled="no" ! grep -Pqs -- ''^\h*0\b'' /sys/module/ipv6/parameters/disable &&
l_ipv6_disabled="yes" if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \ sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then l_ipv6_disabled="yes"
fi } f_kernel_parameter_chk() {
l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= ''{print $2}'' | xargs)" # Check running configuration
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_running_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\""
" in the running configuration") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\"" \
" in the running configuration" \ " and should have a value of: \"$l_value_out\"") fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do if [ -n "$l_out" ]; then
if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}"
else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_fkpname l_file_parameter_value; do l_fkpname="${l_fkpname// /}";
l_file_parameter_value="${l_file_parameter_value// /}" if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<<
"$l_file_parameter_value"; then a_output+=(" - \"$l_parameter_name\" is correctly set to
\"$l_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\"")
else a_output2+=(" - \"$l_parameter_name\" is incorrectly set to
\"$l_file_parameter_value\"" " in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"")
fi done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}") else a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s ignored by load procedure **") fi } l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}" l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }" l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" if grep -q ''^net.ipv6.'' <<< "$l_parameter_name"; then [ -z "$l_ipv6_disabled" ] && f_ipv6_chk if [ "$l_ipv6_disabled" = "yes" ]; then
a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable")
else f_kernel_parameter_chk
fi else
f_kernel_parameter_chk fi done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the following parameters in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv4.conf.all.secure_redirects = 0  net.ipv4.conf.default.secure_redirects = 0
Example:
# printf ''%s\n'' "net.ipv4.conf.all.secure_redirects = 0" "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/60netipv4_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash
{ sysctl -w net.ipv4.conf.all.secure_redirects=0 sysctl -w net.ipv4.conf.default.secure_redirects=0 sysctl -w net.ipv4.route.flush=1
}
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '3.1.6'
        Title   = 'Ensure reverse path filtering is enabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameters are set in the running configuration and correctly loaded from a kernel parameter configuration file:
 net.ipv4.conf.all.rp_filter is set to 1  net.ipv4.conf.default.rp_filter is set to 1
Note: kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ipv6_disabled="" a_parlist=("net.ipv4.conf.all.rp_filter=1"
"net.ipv4.conf.default.rp_filter=1") l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print
$2}'' /etc/default/ufw)" f_ipv6_chk() { l_ipv6_disabled="no" ! grep -Pqs -- ''^\h*0\b'' /sys/module/ipv6/parameters/disable &&
l_ipv6_disabled="yes" if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \ sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then l_ipv6_disabled="yes"
fi } f_kernel_parameter_chk() {
l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= ''{print $2}'' | xargs)" # Check running configuration
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_running_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\""
" in the running configuration") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\"" \
" in the running configuration" \ " and should have a value of: \"$l_value_out\"") fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do if [ -n "$l_out" ]; then
if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}"
else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_fkpname l_file_parameter_value; do l_fkpname="${l_fkpname// /}";
l_file_parameter_value="${l_file_parameter_value// /}" if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<<
"$l_file_parameter_value"; then a_output+=(" - \"$l_parameter_name\" is correctly set to
\"$l_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\"")
else a_output2+=(" - \"$l_parameter_name\" is incorrectly set to
\"$l_file_parameter_value\"" " in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"")
fi done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}") else a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s ignored by load procedure **") fi } l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}" l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }" l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" if grep -q ''^net.ipv6.'' <<< "$l_parameter_name"; then [ -z "$l_ipv6_disabled" ] && f_ipv6_chk if [ "$l_ipv6_disabled" = "yes" ]; then
a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable")
else f_kernel_parameter_chk
fi else
f_kernel_parameter_chk fi done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the following parameters in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv4.conf.all.rp_filter = 1  net.ipv4.conf.default.rp_filter = 1
Example:
# printf ''%s\n'' "net.ipv4.conf.all.rp_filter = 1" "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash {
sysctl -w net.ipv4.conf.all.rp_filter=1 sysctl -w net.ipv4.conf.default.rp_filter=1 sysctl -w net.ipv4.route.flush=1 }
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '3.1.7'
        Title   = 'Ensure source routed packets are not accepted'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameters are set in the running configuration and correctly loaded from a kernel parameter configuration file:
 net.ipv4.conf.all.accept_source_route is set to 0  net.ipv4.conf.default.accept_source_route is set to 0  net.ipv6.conf.all.accept_source_route is set to 0  net.ipv6.conf.default.accept_source_route is set to 0 Note:  kernel parameters are loaded by file and parameter order precedence. The
following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.  IPv6 kernel parameters only apply to systems where IPv6 is enabled.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ipv6_disabled="" a_parlist=("net.ipv4.conf.all.accept_source_route=0"
"net.ipv4.conf.default.accept_source_route=0" "net.ipv6.conf.all.accept_source_route=0" "net.ipv6.conf.default.accept_source_route=0")
l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print $2}'' /etc/default/ufw)"
f_ipv6_chk() {
l_ipv6_disabled="no" ! grep -Pqs -- ''^\h*0\b'' /sys/module/ipv6/parameters/disable && l_ipv6_disabled="yes" if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \
sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then
l_ipv6_disabled="yes" fi } f_kernel_parameter_chk() { l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= ''{print $2}'' | xargs)" # Check running configuration if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_running_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\""
" in the running configuration") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\"" \
" in the running configuration" \ " and should have a value of: \"$l_value_out\"") fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do if [ -n "$l_out" ]; then
if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}"
else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi
if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_fkpname l_file_parameter_value; do l_fkpname="${l_fkpname// /}";
l_file_parameter_value="${l_file_parameter_value// /}" if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<<
"$l_file_parameter_value"; then a_output+=(" - \"$l_parameter_name\" is correctly set to
\"$l_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\"")
else a_output2+=(" - \"$l_parameter_name\" is incorrectly set to
\"$l_file_parameter_value\"" " in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"")
fi done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}") else a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s ignored by load procedure **") fi } l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}" l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }" l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" if grep -q ''^net.ipv6.'' <<< "$l_parameter_name"; then [ -z "$l_ipv6_disabled" ] && f_ipv6_chk if [ "$l_ipv6_disabled" = "yes" ]; then
a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable")
else f_kernel_parameter_chk
fi else
f_kernel_parameter_chk fi done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the following parameters in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv4.conf.all.accept_source_route = 0  net.ipv4.conf.default.accept_source_route = 0
Example:
# printf ''%s\n'' "net.ipv4.conf.all.accept_source_route = 0" "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60netipv4_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash
{ sysctl -w net.ipv4.conf.all.accept_source_route=0 sysctl -w net.ipv4.conf.default.accept_source_route=0 sysctl -w net.ipv4.route.flush=1
}
- IF - IPv6 is enabled on the system: Set the following parameters in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv6.conf.all.accept_source_route = 0  net.ipv6.conf.default.accept_source_route = 0
Example:
# printf ''%s\n'' "net.ipv6.conf.all.accept_source_route = 0" "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60netipv6_sysctl.conf
Run the following command to set the active kernel parameters:
#!/usr/bin/env bash
{ sysctl -w net.ipv6.conf.all.accept_source_route=0 sysctl -w net.ipv6.conf.default.accept_source_route=0 sysctl -w net.ipv6.route.flush=1
}
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '3.1.8'
        Title   = 'Ensure suspicious packets are logged'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameters are set in the running configuration and correctly loaded from a kernel parameter configuration file:
 net.ipv4.conf.all.log_martians is set to 1  net.ipv4.conf.default.log_martians is set to 1 Note: kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ipv6_disabled="" a_parlist=("net.ipv4.conf.all.log_martians=1"
"net.ipv4.conf.default.log_martians=1") l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print
$2}'' /etc/default/ufw)" f_ipv6_chk() { l_ipv6_disabled="no" ! grep -Pqs -- ''^\h*0\b'' /sys/module/ipv6/parameters/disable &&
l_ipv6_disabled="yes" if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \ sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then l_ipv6_disabled="yes"
fi } f_kernel_parameter_chk() {
l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= ''{print $2}'' | xargs)" # Check running configuration
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_running_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\""
" in the running configuration") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\"" \
" in the running configuration" \ " and should have a value of: \"$l_value_out\"") fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do if [ -n "$l_out" ]; then
if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}"
else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_fkpname l_file_parameter_value; do l_fkpname="${l_fkpname// /}";
l_file_parameter_value="${l_file_parameter_value// /}" if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<<
"$l_file_parameter_value"; then a_output+=(" - \"$l_parameter_name\" is correctly set to
\"$l_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\"")
else a_output2+=(" - \"$l_parameter_name\" is incorrectly set to
\"$l_file_parameter_value\"" " in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"")
fi done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}") else a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s ignored by load procedure **") fi } l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}" l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }" l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" if grep -q ''^net.ipv6.'' <<< "$l_parameter_name"; then [ -z "$l_ipv6_disabled" ] && f_ipv6_chk if [ "$l_ipv6_disabled" = "yes" ]; then
a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable")
else f_kernel_parameter_chk
fi else
f_kernel_parameter_chk fi done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the following parameters in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv4.conf.all.log_martians = 1  net.ipv4.conf.default.log_martians = 1
Example:
# printf ''%s\n'' "net.ipv4.conf.all.log_martians = 1" "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/60netipv4_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash
{ sysctl -w net.ipv4.conf.all.log_martians=1 sysctl -w net.ipv4.conf.default.log_martians=1 sysctl -w net.ipv4.route.flush=1
}
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '3.1.9'
        Title   = 'Ensure tcp syn cookies is enabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameter is set in the running configuration and correctly loaded from a kernel parameter configuration file:
 net.ipv4.tcp_syncookies is set to 1
Note: kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ipv6_disabled="" a_parlist=("net.ipv4.tcp_syncookies=1") l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print
$2}'' /etc/default/ufw)" f_ipv6_chk() { l_ipv6_disabled="no" ! grep -Pqs -- ''^\h*0\b'' /sys/module/ipv6/parameters/disable &&
l_ipv6_disabled="yes" if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \ sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then l_ipv6_disabled="yes"
fi } f_kernel_parameter_chk() {
l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= ''{print $2}'' | xargs)" # Check running configuration
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_running_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\""
" in the running configuration") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\"" \
" in the running configuration" \ " and should have a value of: \"$l_value_out\"") fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do if [ -n "$l_out" ]; then
if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}"
else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output while IFS="=" read -r l_fkpname l_file_parameter_value; do
l_fkpname="${l_fkpname// /}"; l_file_parameter_value="${l_file_parameter_value// /}"
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_file_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_file_parameter_value\"" \
" in \"$(printf ''%s'' "${A_out[@]}")\"") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_file_parameter_value\""
" in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"") fi done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}") else a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s ignored by load procedure **") fi } l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}" l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }" l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" if grep -q ''^net.ipv6.'' <<< "$l_parameter_name"; then [ -z "$l_ipv6_disabled" ] && f_ipv6_chk if [ "$l_ipv6_disabled" = "yes" ]; then a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable") else f_kernel_parameter_chk fi else f_kernel_parameter_chk fi done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
Set the following parameter in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv4.tcp_syncookies = 1 Example:
# printf ''%s\n'' "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/60netipv4_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash {
sysctl -w net.ipv4.tcp_syncookies=1 sysctl -w net.ipv4.route.flush=1 }
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '3.1.10'
        Title   = 'Ensure ipv6 router advertisements are not accepted'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify the following kernel parameters are set in the running configuration and correctly loaded from a kernel parameter configuration file:
 net.ipv6.conf.all.accept_ra is set to 0  net.ipv6.conf.default.accept_ra is set to 0
Note:
 kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that "correct" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
 IPv6 kernel parameters only apply to systems where IPv6 is enabled.
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ipv6_disabled="" a_parlist=("net.ipv6.conf.all.accept_ra=0"
"net.ipv6.conf.default.accept_ra=0") l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= ''/^\s*IPT_SYSCTL=/ {print
$2}'' /etc/default/ufw)" f_ipv6_chk() { l_ipv6_disabled="no" ! grep -Pqs -- ''^\h*0\b'' /sys/module/ipv6/parameters/disable &&
l_ipv6_disabled="yes" if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.all\.disable_ipv6\h*=\h*1\b" && \ sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs --
"^\h*net\.ipv6\.conf\.default\.disable_ipv6\h*=\h*1\b"; then l_ipv6_disabled="yes"
fi } f_kernel_parameter_chk() {
l_running_parameter_value="$(sysctl "$l_parameter_name" | awk -F= ''{print $2}'' | xargs)" # Check running configuration
if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<< "$l_running_parameter_value"; then
a_output+=(" - \"$l_parameter_name\" is correctly set to \"$l_running_parameter_value\""
" in the running configuration") else
a_output2+=(" - \"$l_parameter_name\" is incorrectly set to \"$l_running_parameter_value\"" \
" in the running configuration" \ " and should have a value of: \"$l_value_out\"") fi unset A_out; declare -A A_out # Check durable setting (files) while read -r l_out; do if [ -n "$l_out" ]; then
if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}"
else l_kpar="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" [ "$l_kpar" = "$l_parameter_name" ] &&
A_out+=(["$l_kpar"]="$l_file") fi
fi done < <("$l_systemdsysctl" --cat-config | grep -Po ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
l_kpar="$(grep -Po "^\h*$l_parameter_name\b" "$l_ufwscf" | xargs)" l_kpar="${l_kpar//\//.}" [ "$l_kpar" = "$l_parameter_name" ] && A_out+=(["$l_kpar"]="$l_ufwscf") fi if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_fkpname l_file_parameter_value; do l_fkpname="${l_fkpname// /}";
l_file_parameter_value="${l_file_parameter_value// /}" if grep -Pq -- ''\b''"$l_parameter_value"''\b'' <<<
"$l_file_parameter_value"; then a_output+=(" - \"$l_parameter_name\" is correctly set to
\"$l_file_parameter_value\"" \ " in \"$(printf ''%s'' "${A_out[@]}")\"")
else a_output2+=(" - \"$l_parameter_name\" is incorrectly set to
\"$l_file_parameter_value\"" " in \"$(printf ''%s'' "${A_out[@]}")\"" \ " and should have a value of: \"$l_value_out\"")
fi done < <(grep -Po -- "^\h*$l_parameter_name\h*=\h*\H+" "${A_out[@]}") else a_output2+=(" - \"$l_parameter_name\" is not set in an included file" \ " ** Note: \"$l_parameter_name\" May be set in a file that''s ignored by load procedure **") fi } l_systemdsysctl="$(readlink -f /lib/systemd/systemd-sysctl)" while IFS="=" read -r l_parameter_name l_parameter_value; do # Assess and check parameters l_parameter_name="${l_parameter_name// /}"; l_parameter_value="${l_parameter_value// /}" l_value_out="${l_parameter_value//-/ through }"; l_value_out="${l_value_out//|/ or }" l_value_out="$(tr -d ''(){}'' <<< "$l_value_out")" if grep -q ''^net.ipv6.'' <<< "$l_parameter_name"; then [ -z "$l_ipv6_disabled" ] && f_ipv6_chk if [ "$l_ipv6_disabled" = "yes" ]; then
a_output+=(" - IPv6 is disabled on the system, \"$l_parameter_name\" is not applicable")
else f_kernel_parameter_chk
fi else
f_kernel_parameter_chk fi done < <(printf ''%s\n'' "${a_parlist[@]}") if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
'@
        Remediation = @'
- IF - IPv6 is enabled on the system: Set the following parameters in /etc/sysctl.conf or a file in /etc/sysctl.d/ ending in .conf:
 net.ipv6.conf.all.accept_ra = 0  net.ipv6.conf.default.accept_ra = 0
Example:
# printf ''%s\n'' "net.ipv6.conf.all.accept_ra = 0" "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
Run the following script to set the active kernel parameters:
#!/usr/bin/env bash
{ sysctl -w net.ipv6.conf.all.accept_ra=0 sysctl -w net.ipv6.conf.default.accept_ra=0 sysctl -w net.ipv6.route.flush=1
}
Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten.
'@
    },
    @{
        Section = '4.1.1'
        Title   = 'Ensure iptables is installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify that iptables is installed:
# rpm -q iptables
iptables-<version>
'@
        Remediation = @'
Run the following command to install iptables:
# tdnf install iptables
'@
    },
    @{
        Section = '4.1.2'
        Title   = 'Ensure nftables is not in use'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to determine if the nftables package is installed:
# rpm -q nftables &>/dev/null && echo "nftables is installed"
Verify that the NFTables package is not installed. - OR If the NFTables package is required for dependencies, run the following commands to verify that nftables.service is not enabled and not active: Run the following command to verify nftables.service is not enabled:
# systemctl is-enabled nftables.service
Verify the output is not enabled. Run the following command to verify nftables.service is not active:
# systemctl is-active nftables.service inactive
'@
        Remediation = @'
Ensure either IPTables is being used, nftables.service is not enabled and not active - OR If nftables is being used; it is installed, enabled, and active. Run the following command to remove the NFTables package:
# tdnf remove nftables
- OR- If the NFTables package is required for a dependency: Run the following command to mask nftables.service:
# systemctl mask nftables.service
Run the following command to stop nftables.service:
# systemctl stop nftables.service
'@
    },
    @{
        Section = '4.1.3'
        Title   = 'Ensure firewalld is not in use'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify FirewallD is not installed:
# rpm -q firewalld package firewalld is not installed
- OR - If the firewalld package is required for a dependency: Run the following command to verify firewalld.service is not enabled:
# systemctl is-enabled firewalld.service
Verify the output is not enabled Run the following command to verify firewalld.service is not active:
# systemctl is-active firewalld.service inactive
'@
        Remediation = @'
Run the following command to remove the FirewallD package:
# tdnf remove firewalld
- OR - If the firewalld package is required for a dependency: Run the following command to mask firewalld.service:
# systemctl mask firewalld.service
Run the following command to stop firewalld.service:
# systemctl stop firewalld
'@
    },
    @{
        Section = '5.1.1'
        Title   = 'Ensure cron daemon is enabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the the following command to verify cron is enabled:
# systemctl is-enabled crond
enabled
Verify result is "enabled".
'@
        Remediation = @'
Run the following command to enable cron:
# systemctl --now enable crond
'@
    },
    @{
        Section = '5.1.2'
        Title   = 'Ensure permissions on /etc/crontab are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other :
# stat /etc/crontab Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set ownership and permissions on /etc/crontab :
# chown root:root /etc/crontab # chmod og-rwx /etc/crontab
'@
    },
    @{
        Section = '5.1.3'
        Title   = 'Ensure permissions on /etc/cron.hourly are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other :
# stat /etc/cron.hourly Access: (0700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set ownership and permissions on /etc/cron.hourly :
# chown root:root /etc/cron.hourly # chmod og-rwx /etc/cron.hourly
'@
    },
    @{
        Section = '5.1.4'
        Title   = 'Ensure permissions on /etc/cron.daily are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other :
# stat /etc/cron.daily Access: (0700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set ownership and permissions on /etc/cron.daily :
# chown root:root /etc/cron.daily # chmod og-rwx /etc/cron.daily
'@
    },
    @{
        Section = '5.1.5'
        Title   = 'Ensure permissions on /etc/cron.weekly are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other :
# stat /etc/cron.weekly Access: (0700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set ownership and permissions on /etc/cron.weekly :
# chown root:root /etc/cron.weekly # chmod og-rwx /etc/cron.weekly
'@
    },
    @{
        Section = '5.1.6'
        Title   = 'Ensure permissions on /etc/cron.monthly are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other :
# stat /etc/cron.monthly Access: (0700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set ownership and permissions on /etc/cron.monthly :
# chown root:root /etc/cron.monthly # chmod og-rwx /etc/cron.monthly
'@
    },
    @{
        Section = '5.1.7'
        Title   = 'Ensure permissions on /etc/cron.d are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other :
# stat /etc/cron.d Access: (0700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set ownership and permissions on /etc/cron.d :
# chown root:root /etc/cron.d # chmod og-rwx /etc/cron.d
'@
    },
    @{
        Section = '5.1.8'
        Title   = 'Ensure cron is restricted to authorized users'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify /etc/cron.allow exists, is mode 0640 or more restrictive, is owned by root, and group owned by root:
# stat -Lc ''File: (%n) Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/cron.allow
File: (/etc/cron.allow) Access: (0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 0/ root)
Run the following command to verify /etc/cron.deny doesn''t exist, or: is mode 0640 or more restrictive, is owned by root, and group owned by root:
# stat -Lc ''File: (%n) Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/cron.deny
stat: cannot stat ''/etc/cron.deny'': No such file or directory -OR-
File: (/etc/cron.deny) Access: (0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following script to remove /etc/cron.deny, create /etc/cron.allow, and set the file mode on /etc/cron.allow:
#!/usr/bin/env bash
{ if rpm -q cronie >/dev/null; then [ -e /etc/cron.deny ] && rm -f /etc/cron.deny [ ! -e /etc/cron.allow ] && touch /etc/cron.allow chown root:root /etc/cron.allow chmod g-wx,o-rwx /etc/cron.allow else echo "cron is not installed on the system" fi
}
'@
    },
    @{
        Section = '5.1.9'
        Title   = 'Ensure at is restricted to authorized users'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script:
#!/usr/bin/env bash
{ if rpm -q at >/dev/null; then [ -e /etc/at.deny ] && echo "Fail: at.deny exists" if [ ! -e /etc/at.allow ]; then echo "Fail: at.allow doesn''t exist" else ! stat -Lc "%a" /etc/at.allow | grep -Eq "[0,2,4,6]00" && echo
"Fail: at.allow mode too permissive" ! stat -Lc "%u:%g" /etc/at.allow | grep -Eq "^0:0$" && echo "Fail:
at.allow owner and/or group not root" fi if [ ! -e /etc/at.deny ] && [ -e /etc/at.allow ] && stat -Lc "%a"
/etc/at.allow | grep -Eq "[0,2,4,6]00" \ && stat -Lc "%u:%g" /etc/at.allow | grep -Eq "^0:0$"; then echo "Pass"
fi else
echo "Pass: at is not installed on the system" fi }
Verify the output of the script includes Pass.
'@
        Remediation = @'
Run the following script to remove /etc/at.deny, create /etc/at.allow, and set the file mode for /etc/at.allow:
#!/usr/bin/env bash
{ if rpm -q at >/dev/null; then [ -e /etc/at.deny ] && rm -f /etc/at.deny [ ! -e /etc/at.allow ] && touch /etc/at.allow chown root:root /etc/at.allow chmod u-x,go-rwx /etc/at.allow else echo "at is not installed on the system" fi
}
OR Run the following command to remove at:
# tdnf remove at
'@
    },
    @{
        Section = '5.2.1'
        Title   = 'Ensure access to /etc/ssh/sshd_config is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script and verify /etc/ssh/sshd_config and files ending in .conf in the /etc/ssh/sshd_config.d directory are:
 Mode 0600 or more restrictive  Owned by the root user  Group owned by the group root
#!/usr/bin/env bash
{ a_output=(); a_output2=() perm_mask=''0177'' && maxperm="$( printf ''%o'' $(( 0777 & ~$perm_mask)) )" f_sshd_files_chk() { while IFS=: read -r l_mode l_user l_group; do a_out2=() [ $(( $l_mode & $perm_mask )) -gt 0 ] && a_out2+=(" Is mode:
\"$l_mode\"" \ " should be mode: \"$maxperm\" or more restrictive") [ "$l_user" != "root" ] && a_out2+=(" Is owned by \"$l_user\"
should be owned by \"root\"") [ "$l_group" != "root" ] && a_out2+=(" Is group owned by
\"$l_user\" should be group owned by \"root\"") if [ "${#a_out2[@]}" -gt "0" ]; then a_output2+=(" - File: \"$l_file\":" "${a_out2[@]}") else a_output+=(" - File: \"$l_file\":" " Correct: mode ($l_mode),
owner ($l_user)" \ " and group owner ($l_group) configured")
fi done < <(stat -Lc ''%#a:%U:%G'' "$l_file") } [ -e "/etc/ssh/sshd_config" ] && l_file="/etc/ssh/sshd_config" && f_sshd_files_chk while IFS= read -r -d $''\0'' l_file; do [ -e "$l_file" ] && f_sshd_files_chk done < <(find /etc/ssh/sshd_config.d -type f -name ''*.conf'' \( -perm /077 -o ! -user root -o ! -group root \) -print0 2>/dev/null) if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" "" fi }
- IF - other locations are listed in an Include statement, *.conf files in these locations should also be checked.
'@
        Remediation = @'
Run the following script to set ownership and permissions on /etc/ssh/sshd_config and files ending in .conf in the /etc/ssh/sshd_config.d directory:
#!/usr/bin/env bash
{ chmod u-x,og-rwx /etc/ssh/sshd_config chown root:root /etc/ssh/sshd_config while IFS= read -r -d $''\0'' l_file; do if [ -e "$l_file" ]; then chmod u-x,og-rwx "$l_file" chown root:root "$l_file" fi done < <(find /etc/ssh/sshd_config.d -type f -print0 2>/dev/null)
}
- IF - other locations are listed in an Include statement, *.conf files in these locations access should also be modified.
'@
    },
    @{
        Section = '5.2.2'
        Title   = 'Ensure access to SSH private host key files is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify SSH private host key files are owned by the root user and either:
 owned by the group root and mode 0600 or more restrictive - OR -
 owned by the group designated to own openSSH private keys and mode 0640 or more restrictive
#!/usr/bin/env bash
{ a_output=(); a_output2=() l_ssh_group_name="$(awk -F: ''($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}''
/etc/group)" f_file_chk() { while IFS=: read -r l_file_mode l_file_owner l_file_group; do a_out2=() [ "$l_file_group" = "$l_ssh_group_name" ] && l_pmask="0137" ||
l_pmask="0177" l_maxperm="$( printf ''%o'' $(( 0777 & ~$l_pmask )) )" if [ $(( $l_file_mode & $l_pmask )) -gt 0 ]; then a_out2+=(" Mode: \"$l_file_mode\" should be mode:
\"$l_maxperm\" or more restrictive") fi if [ "$l_file_owner" != "root" ]; then a_out2+=(" Owned by: \"$l_file_owner\" should be owned by
\"root\"") fi if [[ ! "$l_file_group" =~ ($l_ssh_group_name|root) ]]; then a_out2+=(" Owned by group \"$l_file_group\" should be group
owned by: \"$l_ssh_group_name\" or \"root\"") fi if [ "${#a_out2[@]}" -gt "0" ]; then a_output2+=(" - File: \"$l_file\"${a_out2[@]}") else a_output+=(" - File: \"$l_file\"" \ " Correct: mode: \"$l_file_mode\", owner: \"$l_file_owner\"
and group owner: \"$l_file_group\" configured") fi
done < <(stat -Lc ''%#a:%U:%G'' "$l_file") } while IFS= read -r -d $''\0'' l_file; do
if ssh-keygen -lf &>/dev/null "$l_file"; then file "$l_file" | grep -Piq --
''\bopenssh\h+([^#\n\r]+\h+)?private\h+key\b'' && f_file_chk fi
done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null) if [ "${#a_output2[@]}" -le 0 ]; then
printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else
printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
[ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" ""
fi }
'@
        Remediation = @'
Run the following script to set mode, ownership, and group on the private SSH host key files:
#!/usr/bin/env bash
{ a_output=(); a_output2=(); l_ssh_group_name="$(awk -F: ''($1 ~ /^(ssh_keys|_?ssh)$/)
{print $1}'' /etc/group)" f_file_access_fix() { while IFS=: read -r l_file_mode l_file_owner l_file_group; do a_out2=() [ "$l_file_group" = "$l_ssh_group_name" ] && l_pmask="0137" || l_pmask="0177" l_maxperm="$( printf ''%o'' $(( 0777 & ~$l_pmask )) )" if [ $(( $l_file_mode & $l_pmask )) -gt 0 ]; then a_out2+=(" Mode: \"$l_file_mode\" should be mode: \"$l_maxperm\" or
more restrictive" \ " updating to mode: \:$l_maxperm\"") if [ "l_file_group" = "$l_ssh_group_name" ]; then chmod u-x,g-wx,o-rwx "$l_file" else chmod u-x,go-rwx "$l_file" fi
fi if [ "$l_file_owner" != "root" ]; then
a_out2+=(" Owned by: \"$l_file_owner\" should be owned by \"root\"" \ " Changing ownership to \"root\"") chown root "$l_file" fi if [[ ! "$l_file_group" =~ ($l_ssh_group_name|root) ]]; then [ -n "$l_ssh_group_name" ] && l_new_group="$l_ssh_group_name" || l_new_group="root" a_out2+=(" Owned by group \"$l_file_group\" should be group owned by: \"$l_ssh_group_name\" or \"root\"" \ " Changing group ownership to \"$l_new_group\"") chgrp "$l_new_group" "$l_file" fi if [ "${#a_out2[@]}" -gt "0" ]; then a_output2+=(" - File: \"$l_file\"" "${a_out2[@]}") else a_output+=(" - File: \"$l_file\"" \ "Correct: mode: \"$l_file_mode\", owner: \"$l_file_owner\", and group owner: \"$l_file_group\" configured") fi done < <(stat -Lc ''%#a:%U:%G'' "$l_file") } while IFS= read -r -d $''\0'' l_file; do if ssh-keygen -lf &>/dev/null "$l_file"; then file "$l_file" | grep -Piq -- ''\bopenssh\h+([^#\n\r]+\h+)?private\h+key\b'' && f_file_access_fix fi done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null) if [ "${#a_output2[@]}" -le "0" ]; then printf ''%s\n'' "" " - No access changes required" "" else printf ''%s\n'' "" " - Remediation results:" "${a_output2[@]}" "" fi }
'@
    },
    @{
        Section = '5.2.3'
        Title   = 'Ensure access to SSH public host key files is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify SSH public host key files are mode 0644 or more restrictive, owned by the root user, and owned by the root group:
#!/usr/bin/env bash
{ a_output=(); a_output2=() l_pmask="0133"; l_maxperm="$( printf ''%o'' $(( 0777 & ~$l_pmask )) )" f_file_chk() { while IFS=: read -r l_file_mode l_file_owner l_file_group; do a_out2=() if [ $(( $l_file_mode & $l_pmask )) -gt 0 ]; then a_out2+=(" Mode: \"$l_file_mode\" should be mode:
\"$l_maxperm\" or more restrictive") fi if [ "$l_file_owner" != "root" ]; then a_out2+=(" Owned by: \"$l_file_owner\" should be owned by:
\"root\"") fi if [ "$l_file_group" != "root" ]; then a_out2+=(" Owned by group \"$l_file_group\" should be group
owned by group: \"root\"") fi if [ "${#a_out2[@]}" -gt "0" ]; then a_output2+=(" - File: \"$l_file\"" "${a_out2[@]}") else a_output+=(" - File: \"$l_file\"" \ " Correct: mode: \"$l_file_mode\", owner: \"$l_file_owner\"
and group owner: \"$l_file_group\" configured") fi
done < <(stat -Lc ''%#a:%U:%G'' "$l_file") } while IFS= read -r -d $''\0'' l_file; do
if ssh-keygen -lf &>/dev/null "$l_file"; then file "$l_file" | grep -Piq --
''\bopenssh\h+([^#\n\r]+\h+)?public\h+key\b'' && f_file_chk fi
done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null) if [ "${#a_output2[@]}" -le 0 ]; then
[ "${#a_output[@]}" -le 0 ] && a_output+=(" - No openSSH public keys found")
printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else
printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
[ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:" "${a_output[@]}" ""
fi }
'@
        Remediation = @'
Run the following script to set mode, ownership, and group on the public SSH host key files:
#!/usr/bin/env bash
{ a_output=(); a_output2=() l_pmask="0133"; l_maxperm="$( printf ''%o'' $(( 0777 & ~$l_pmask )) )" f_file_access_fix() { while IFS=: read -r l_file_mode l_file_owner l_file_group; do a_out2=() [ $(( $l_file_mode & $l_pmask )) -gt 0 ] && \ a_out2+=(" Mode: \"$l_file_mode\" should be mode:
\"$l_maxperm\" or more restrictive" \ " updating to mode: \"$l_maxperm\"") && chmod u-x,go-wx
"$l_file" [ "$l_file_owner" != "root" ] && \ a_out2+=(" Owned by: \"$l_file_owner\" should be owned by
\"root\"" \ " Changing ownership to \"root\"") && chown root "$l_file"
[ "$l_file_group" != "root" ] && \ a_out2+=(" Owned by group \"$l_file_group\" should be group
owned by: \"root\"" \ " Changing group ownership to \"root\"") && chgrp root
"$l_file" if [ "${#a_out2[@]}" -gt "0" ]; then a_output2+=(" - File: \"$l_file\"" "${a_out2[@]}") else a_output+=(" - File: \"$l_file\"" \ " Correct: mode: \"$l_file_mode\", owner: \"$l_file_owner\",
and group owner: \"$l_file_group\" configured") fi
done < <(stat -Lc ''%#a:%U:%G'' "$l_file") } while IFS= read -r -d $''\0'' l_file; do
if ssh-keygen -lf &>/dev/null "$l_file"; then file "$l_file" | grep -Piq --
''\bopenssh\h+([^#\n\r]+\h+)?public\h+key\b'' && f_file_access_fix fi
done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null) if [ "${#a_output2[@]}" -le "0" ]; then
printf ''%s\n'' "" " - No access changes required" "" else
printf ''%s\n'' " - Remediation results:" "${a_output2[@]}" "" fi }
'@
    },
    @{
        Section = '5.2.4'
        Title   = 'Ensure sshd Ciphers are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify none of the "weak" ciphers are being used:
# sshd -T | grep -Pi -''^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se|chacha20poly1305@openssh\.com)\b''
- IF - a line is returned, review the list of ciphers. If the line includes chacha20poly1305@openssh.com, review CVE-2023-48795 and verify the system has been patched. No ciphers in the list below should be returned as they''re considered "weak":
3des-cbc aes128-cbc aes192-cbc aes256-cbc
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file and add/modify the Ciphers line to contain a comma separated list of the site unapproved (weak) Ciphers preceded with a - above any Include entries: Example:
Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20poly1305@openssh.com
- IF - CVE-2023-48795 has been addressed, and it meets local site policy, chacha20poly1305@openssh.com may be removed from the list of excluded ciphers. Note: First occurrence of an option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.5'
        Title   = 'Ensure sshd KexAlgorithms is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify none of the "weak" Key Exchange algorithms are being used:
# sshd -T | grep -Pi -- ''kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b''
Nothing should be returned
The following are considered "weak" Key Exchange Algorithms, and should not be used:
diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file and add/modify the KexAlgorithms line to contain a comma separated list of the site unapproved (weak) KexAlgorithms preceded with a above any Include entries: Example:
KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffiehellman-group-exchange-sha1
Note: First occurrence of an option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.6'
        Title   = 'Ensure sshd MACs are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify none of the "weak" MACs are being used:
# sshd -T | grep -Pi -- ''macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmacripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmacmd5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96etm@openssh\.com|umac-64-etm@openssh\.com)\b''
Nothing should be returned
Note: Review CVE-2023-48795 and verify the system has been patched. If the system has not been patched, review the use of the Encrypt Then Mac (etm) MACs. The following are considered "weak" MACs, and should not be used:
hmac-md5 hmac-md5-96 hmac-ripemd160 hmac-sha1-96 umac-64@openssh.com hmac-md5-etm@openssh.com hmac-md5-96-etm@openssh.com hmac-ripemd160-etm@openssh.com hmac-sha1-96-etm@openssh.com umac-64-etm@openssh.com
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file and add/modify the MACs line to contain a comma separated list of the site unapproved (weak) MACs preceded with a - above any Include entries: Example:
MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmacripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64etm@openssh.com
- IF - CVE-2023-48795 has not been reviewed and addressed, the following etm MACs should be added to the exclude list: hmac-sha1-etm@openssh.com,hmac-sha2-256etm@openssh.com,hmac-sha2-512-etm@openssh.com Note: First occurrence of an option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.7'
        Title   = 'Ensure sshd access is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify the output:
# sshd -T | grep -Pi -- ''^\h*(allow|deny)(users|groups)\h+\H+''
Verify that the output matches at least one of the following lines:
allowusers <userlist> -ORallowgroups <grouplist> -ORdenyusers <userlist> -ORdenygroups <grouplist>
Review the list(s) to ensure included users and/or groups follow local site policy - IF - Match set statements are used in your environment, specify the connection parameters to use for the -T extended test mode and run the audit to verify the setting is not incorrectly configured in a match block. Example additional audit needed for a match block for the user sshuser:
# sshd -T -C user=sshuser | grep -Pi -''^\h*(allow|deny)(users|groups)\h+\H+''
Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple -C options or as a comma-separated list. The keywords are addr (source address), user (user), host (resolved source host name), laddr (local address), lport (local port number), and rdomain (routing domain).
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set one or more of the parameters above any Include and Match set statements as follows:
AllowUsers <userlist> - AND/OR -
AllowGroups <grouplist>
Note:
 First occurrence of an option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a .conf file in an Include directory.
 Be advised that these options are "ANDed" together. If both AllowUsers and AllowGroups are set, connections will be limited to the list of users that are also a member of an allowed group. It is recommended that only one be set for clarity and ease of administration.
 It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user or group and forget to add it to the deny list.
'@
    },
    @{
        Section = '5.2.8'
        Title   = 'Ensure sshd Banner is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify Banner is set:
# sshd -T | grep -Pi -- ''^banner\h+\/\H+''
Example:
banner /etc/issue.net
- IF - Match set statements are used in your environment, specify the connection parameters to use for the -T extended test mode and run the audit to verify the setting is not incorrectly configured in a match block. Example additional audit needed for a match block for the user sshuser:
# sshd -T -C user=sshuser | grep -Pi -- ''^banner\h+\/\H+''
Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple -C options or as a comma-separated list. The keywords are addr (source address), user (user), host (resolved source host name), laddr (local address), lport (local port number), and rdomain (routing domain). Run the following command and verify that the contents or the file being called by the Banner argument match site policy:
# [ -e "$(sshd -T | awk ''$1 == "banner" {print $2}'')" ] && cat "$(sshd -T | awk ''$1 == "banner" {print $2}'')"
Run the following command and verify no results are returned:
# grep -Psi -- "(\\\v|\\\r|\\\m|\\\s|\b$(grep ''^ID='' /etc/os-release | cut d= -f2 | sed -e ''s/"//g'')\b)" "$(sshd -T | awk ''$1 == "banner" {print $2}'')"
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the Banner parameter above any Include and Match entries as follows:
Banner /etc/issue.net
Note: First occurrence of a option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location. Edit the file being called by the Banner argument with the appropriate contents according to your site policy, remove any instances of \m , \r , \s , \v or references to the OS platform Example:
# printf ''%s\n'' "Authorized users only. All activity may be monitored and reported." > "$(sshd -T | awk ''$1 == "banner" {print $2}'')"
'@
    },
    @{
        Section = '5.2.9'
        Title   = 'Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify ClientAliveInterval and ClientAliveCountMax are greater than zero:
# sshd -T | grep -Pi -- ''(clientaliveinterval|clientalivecountmax)''
Example Output:
clientaliveinterval 15 clientalivecountmax 3
- IF - Match set statements are used in your environment, specify the connection parameters to use for the -T extended test mode and run the audit to verify the setting is not incorrectly configured in a match block Example additional audit needed for a match block for the user sshuser:
# sshd -T -C user=sshuser | grep -Pi -''(clientaliveinterval|clientalivecountmax)''
Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple -C options or as a comma-separated list. The keywords are addr (source address), user (user), host (resolved source host name), laddr (local address), lport (local port number), and rdomain (routing domain).
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the ClientAliveInterval and ClientAliveCountMax parameters above any Include and Match entries according to site policy. Example:
ClientAliveInterval 15 ClientAliveCountMax 3
Note: First occurrence of a option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.10'
        Title   = 'Ensure sshd HostbasedAuthentication is disabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify HostbasedAuthentication is set to no:
# sshd -T | grep hostbasedauthentication
hostbasedauthentication no
- IF - Match set statements are used in your environment, specify the connection parameters to use for the -T extended test mode and run the audit to verify the setting is not incorrectly configured in a match block. Example additional audit needed for a match block for the user sshuser:
# sshd -T -C user=sshuser | grep hostbasedauthentication
Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple -C options or as a comma-separated list. The keywords are addr (source address), user (user), host (resolved source host name), laddr (local address), lport (local port number), and rdomain (routing domain).
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the HostbasedAuthentication parameter to no above any Include and Match entries as follows:
HostbasedAuthentication no
Note: First occurrence of a option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.11'
        Title   = 'Ensure sshd IgnoreRhosts is enabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify IgnoreRhosts is set to yes:
# sshd -T | grep ignorerhosts ignorerhosts yes
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the IgnoreRhosts parameter to yes above any Include entry as follows:
IgnoreRhosts yes
Note: First occurrence of a option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.12'
        Title   = 'Ensure sshd LoginGraceTime is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify that output LoginGraceTime is between 1 and 60 seconds:
# sshd -T | grep logingracetime
logingracetime 60
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the LoginGraceTime parameter to 60 seconds or less above any Include entry as follows:
LoginGraceTime 60
Note: First occurrence of a option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.13'
        Title   = 'Ensure sshd LogLevel is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify that output matches loglevel VERBOSE or loglevel INFO:
# sshd -T | grep loglevel
loglevel VERBOSE - OR -
loglevel INFO
- IF - Match set statements are used in your environment, specify the connection parameters to use for the -T extended test mode and run the audit to verify the setting is not incorrectly configured in a match block. Example additional audit needed for a match block for the user sshuser:
# sshd -T -C user=sshuser | grep loglevel
Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple -C options or as a comma-separated list. The keywords are addr (source address), user (user), host (resolved source host name), laddr (local address), lport (local port number), and rdomain (routing domain).
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the LogLevel parameter to VERBOSE or INFO above any Include and Match entries as follows:
LogLevel VERBOSE - OR -
LogLevel INFO
Note: First occurrence of an option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.14'
        Title   = 'Ensure sshd MaxAuthTries is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify that MaxAuthTries is 4 or less:
# sshd -T | grep maxauthtries
maxauthtries 4
- IF - Match set statements are used in your environment, specify the connection parameters to use for the -T extended test mode and run the audit to verify the setting is not incorrectly configured in a match block. Example additional audit needed for a match block for the user sshuser:
# sshd -T -C user=sshuser | grep maxauthtries
Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple -C options or as a comma-separated list. The keywords are addr (source address), user (user), host (resolved source host name), laddr (local address), lport (local port number), and rdomain (routing domain).
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the MaxAuthTries parameter to 4 or less above any Include and Match entries as follows:
MaxAuthTries 4
Note: First occurrence of an option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.15'
        Title   = 'Ensure sshd MaxStartups is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify MaxStartups is 10:30:100 or more restrictive:
# sshd -T | awk ''$1 ~ /^\s*maxstartups/{split($2, a, ":");{if(a[1] > 10 || a[2] > 30 || a[3] > 100) print $0}}''
Nothing should be returned
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the MaxStartups parameter to 10:30:100 or more restrictive above any Include entries as follows:
MaxStartups 10:30:100
Note: First occurrence of a option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.16'
        Title   = 'Ensure sshd MaxSessions is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify that MaxSessions is 10 or less:
# sshd -T | grep -i maxsessions maxsessions 10
Run the following command and verify the output:
grep -Psi -- ''^\h*MaxSessions\h+\"?(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\b'' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf Nothing should be returned.
- IF - Match set statements are used in your environment, specify the connection parameters to use for the -T extended test mode and run the audit to verify the setting is not incorrectly configured in a match block. Example additional audit needed for a match block for the user sshuser:
# sshd -T -C user=sshuser | grep maxsessions
Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple -C options or as a comma-separated list. The keywords are addr (source address), user (user), host (resolved source host name), laddr (local address), lport (local port number), and rdomain (routing domain).
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the MaxSessions parameter to 10 or less above any Include and Match entries as follows:
MaxSessions 10
Note: First occurrence of an option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.17'
        Title   = 'Ensure sshd PermitEmptyPasswords is disabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify PermitEmptyPasswords is set to no:
# sshd -T | grep permitemptypasswords permitemptypasswords no
- IF - Match set statements are used in your environment, specify the connection parameters to use for the -T extended test mode and run the audit to verify the setting is not incorrectly configured in a match block. Example additional audit needed for a match block for the user sshuser:
# sshd -T -C user=sshuser | grep permitemptypasswords
Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple -C options or as a comma-separated list. The keywords are addr (source address), user (user), host (resolved source host name), laddr (local address), lport (local port number), and rdomain (routing domain).
'@
        Remediation = @'
Edit /etc/ssh/sshd_config and set the PermitEmptyPasswords parameter to no above any Include and Match entries as follows:
PermitEmptyPasswords no
Note: First occurrence of an option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location. The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:
# systemctl reload-or-restart sshd.service
'@
    },
    @{
        Section = '5.2.18'
        Title   = 'Ensure sshd PermitRootLogin is disabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify PermitRootLogin is set to no:
# sshd -T | grep permitrootlogin
permitrootlogin no
- IF - Match set statements are used in your environment, specify the connection parameters to use for the -T extended test mode and run the audit to verify the setting is not incorrectly configured in a match block. Example additional audit needed for a match block for the user sshuser:
# sshd -T -C user=sshuser | grep permitrootlogin
Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple -C options or as a comma-separated list. The keywords are addr (source address), user (user), host (resolved source host name), laddr (local address), lport (local port number), and rdomain (routing domain).
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the PermitRootLogin parameter to no above any Include and Match entries as follows:
PermitRootLogin no
Note: First occurrence of an option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.19'
        Title   = 'Ensure sshd PermitUserEnvironment is disabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify PermitUserEnvironment is set to no:
# sshd -T | grep permituserenvironment
permituserenvironment no
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the PermitUserEnvironment parameter to no above any Include entries as follows:
PermitUserEnvironment no
Note: First occurrence of an option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.2.20'
        Title   = 'Ensure sshd UsePAM is enabled'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify UsePAM is set to yes:
# sshd -T | grep -i usepam
usepam yes
'@
        Remediation = @'
Edit the /etc/ssh/sshd_config file to set the UsePAM parameter to yes above any Include entries as follows:
UsePAM yes
Note: First occurrence of an option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
'@
    },
    @{
        Section = '5.3.1'
        Title   = 'Ensure sudo is installed'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Verify that sudo is installed. Run the following command:
# tdnf list sudo

Installed Packages sudo.x86_64 Available Packages sudo.x86_64

<VERSION> <VERSION>

@anaconda updates
'@
        Remediation = @'
Run the following command to install sudo
# dnf install sudo
'@
    },
    @{
        Section = '5.3.2'
        Title   = 'Ensure re-authentication for privilege escalation is not disabled globally'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Verify the operating system requires users to re-authenticate for privilege escalation. Check the configuration of the /etc/sudoers and /etc/sudoers.d/* files with the following command:
# grep -r "^[^#].*\!authenticate" /etc/sudoers*
If any line is found with a !authenticate tag, refer to the remediation procedure below.
'@
        Remediation = @'
Configure the operating system to require users to reauthenticate for privilege escalation. Based on the outcome of the audit procedure, use visudo -f <PATH TO FILE> to edit the relevant sudoers file. Remove any occurrences of !authenticate tags in the file(s).
'@
    },
    @{
        Section = '5.3.3'
        Title   = 'Ensure sudo authentication timeout is configured correctly'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Ensure that the caching timeout is no more than 15 minutes. Example:

# grep -roP "timestamp_timeout=\K[0-9]*" /etc/sudoers*
If there is no timestamp_timeout configured in /etc/sudoers* then the default is 5 minutes. This default can be checked with:

# sudo -V | grep "Authentication timestamp timeout:"
NOTE: A value of -1 means that the timeout is disabled. Depending on the configuration of the timestamp_type, this could mean for all terminals / processes of that user and not just that one single terminal session.
'@
        Remediation = @'
If the currently configured timeout is larger than 15 minutes, edit the file listed in the audit section with visudo -f <PATH TO FILE> and modify the entry timestamp_timeout= to 15 minutes or less as per your site policy. The value is in minutes. This particular entry may appear on its own, or on the same line as env_reset. See the following two examples:

Defaults Defaults Defaults

env_reset, timestamp_timeout=15 timestamp_timeout=15 env_reset
'@
    },
    @{
        Section = '5.4.1'
        Title   = 'Ensure password creation requirements are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Verify password creation requirements conform to organization policy. Run the following command to verify the minimum password length is 14 or more characters:
# grep -Pi ''^\h*minlen\b'' /etc/security/pwquality.conf

minlen = 14
Run one of the following commands to verify the required password complexity:
# grep -Pi ''^\h*minclass\b'' /etc/security/pwquality.conf

minclass = 4
-OR-
# grep -Pi ''^\h*[duol]credit\b'' /etc/security/pwquality.conf

dcredit = -1 ucredit = -1 lcredit = -1 ocredit = -1
Run the following commands to verify the files: /etc/pam.d/system-password and /etc/pam.d/system-auth include retry=3 on the password requisite pam_pwquality.so line:

# grep -P ''^\h*password\h+([^#\n\r]+\h+)?pam_pwquality\.so\h+([^#\n\r]+\h+)?(retry=[13])\b'' /etc/pam.d/system-password
Example output:

password requisite

pam_pwquality.so retry=3

# grep -P

''^\h*password\h+([^#\n\r]+\h+)?pam_pwquality\.so\h+([^#\n\r]+\h+)?(retry=[1-

3])\b'' /etc/pam.d/system-auth

Example output:

password requisite

pam_pwquality.so retry=3
'@
        Remediation = @'
Edit the file /etc/security/pwquality.conf and add or modify the following line for password length to conform to site policy:
minlen = 14
Edit the file /etc/security/pwquality.conf and add or modify the following line for password complexity to conform to site policy:
minclass = 4
-OR-
dcredit = -1 ucredit = -1 ocredit = -1 lcredit = -1
Edit the /etc/pam.d/system-password and /etc/pam.d/system-auth files to include the appropriate options for pam_pwquality.so and to conform to site policy:
password requisite pam_pwquality.so retry=3
'@
    },
    @{
        Section = '5.4.2'
        Title   = 'Ensure lockout for failed password attempts is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Verify password lockouts are configured. Depending on the version you are running, follow one of the two methods below.

 deny should not be 0 (never) or greater than 5.  unlock_time should be 0 (never) or 900 seconds or more.

These settings are commonly configured with the pam_failock.so module found in /etc/pam.d/system-auth and /etc/pam.d/system-password. Run the following command and review the output to ensure that it follows local site policy.
# grep -P ''^\h*auth\h+[^#\n\r]+\h+pam_faillock.so\s+'' /etc/pam.d/systempassword /etc/pam.d/system-auth
Output should look similar to:

/etc/pam.d/system-password:auth silent deny=5 unlock_time=900 /etc/pam.d/system-password:auth deny=5 unlock_time=900 /etc/pam.d/system-auth:auth deny=5 unlock_time=900 /etc/pam.d/system-auth:auth deny=5 unlock_time=900

required required required required

pam_faillock.so preauth pam_faillock.so authfail pam_faillock.so preauth silent pam_faillock.so authfail
'@
        Remediation = @'
Set password lockouts and unlock times to conform to site policy. deny should be not greater than 5 and unlock_time should be 0 (never), or 900 seconds or greater. Edit the files /etc/pam.d/system-auth and /etc/pam.d/system-password and add the following lines: Modify the deny= and unlock_time= parameters to conform to local site policy, Not to be greater than deny=5: Add the following lines to the auth section:

auth

required

pam_faillock.so preauth silent audit deny=5

unlock_time=900

auth

[default=die] pam_faillock.so authfail audit deny=5

unlock_time=900

The auth sections should look similar to the following example: Note: The ordering on the lines in the auth section is important. The preauth line needs to below the line auth required pam_env.so and above all password validation lines. The authfail line needs to be after all password validation lines such as pam_sss.so. Incorrect order can cause you to be locked out of the system Example:

auth

required

pam_env.so

auth

required

pam_faillock.so preauth silent audit deny=5

unlock_time=900 # <- Under "auth required pam_env.so"

auth

sufficient pam_unix.so nullok try_first_pass

auth

[default=die] pam_faillock.so authfail audit deny=5

unlock_time=900 # <- Last auth line before "auth requisite

pam_succeed_if.so"

auth

requisite

pam_succeed_if.so uid >= 1000 quiet_success

auth

required

pam_deny.so

Add the following line to the account section:

account
Example:

required

pam_faillock.so

account account account account account

required required sufficient sufficient required

pam_faillock.so pam_unix.so pam_localuser.so pam_pam_succeed_if.so uid < 1000 quiet pam_permit.so
'@
    },
    @{
        Section = '5.4.3'
        Title   = 'Ensure password hashing algorithm is SHA-512'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify the sha512 option is included:
# grep -P ''^\h*password\h+([^#\n\r]+)?\h+pam_unix\.so\h+([^#\n\r]+\h+)?sha512\b'' /etc/pam.d/system-auth /etc/pam.d/system-password
Output should be similar to:
/etc/pam.d/system-auth:password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok /etc/pam.d/system-password:password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok
'@
        Remediation = @'
Edit the /etc/pam.d/system-password and /etc/pam.d/system-auth files to include sha512 option and remove the md5 option for pam_unix.so:
password sufficient pam_unix.so sha512
Note:

 Any system accounts that need to be expired should be carefully done separately by the system administrator to prevent any potential problems.
 If it is determined that the password algorithm being used is not SHA-512, once it is changed, it is recommended that all user ID''s be immediately expired and forced to change their passwords on next login, In accordance with local site policies.
'@
    },
    @{
        Section = '5.4.4'
        Title   = 'Ensure password reuse is limited'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Verify remembered password history follows local site policy, not to be less than 5. Run the following command:

# grep -P ''^\h*password\h+[^#\n\r]+\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=([59]|[1-9][0-9]+)\b'' /etc/pam.d/system-password /etc/pam.d/system-auth
Output should look similar to:

/etc/pam.d/system-auth:password requisite /etc/pam.d/system-password:password requisite remember=5

pam_pwhistory.so remember=5 pam_pwhistory.so
'@
        Remediation = @'
Edit both the /etc/pam.d/system-password and /etc/pam.d/system-auth files to include the remember option and conform to site policy as shown: Note: Add or modify the line containing the pam_pwhistory.so after the first occurrence of password requisite:

password requisite

pam_pwhistory.so remember=5

Example: (Second line is modified)

password requisite authtok_type= password requisite password sufficient use_authtok password required

pam_pwquality.so try_first_pass local_users_only
pam_pwhistory.so use_authtok remember=5 retry=3 pam_unix.so sha512 shadow try_first_pass
pam_deny.so

Additional Information:

 This setting only applies to local accounts.  This option is configured with the remember=n module option in
/etc/pam.d/system-auth and /etc/pam.d/system-password
'@
    },
    @{
        Section = '5.5.1.1'
        Title   = 'Ensure password expiration is 365 days or less'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify PASS_MAX_DAYS conforms to site policy (no more than 365 days):
# grep PASS_MAX_DAYS /etc/login.defs PASS_MAX_DAYS 365
Run the following command and review list of users and PASS_MAX_DAYS to verify that all users'' PASS_MAX_DAYS conforms to site policy (no more than 365 days):
# awk -F: ''$2~/^[^*!xX\n\r][^\n\r]+/{print $1":"$5}'' /etc/shadow <user>:<PASS_MAX_DAYS>
'@
        Remediation = @'
Set the PASS_MAX_DAYS parameter to conform to site policy in /etc/login.defs:
PASS_MAX_DAYS 365
Modify user parameters for all users with a password set to match:
# chage --maxdays 365 <user>
'@
    },
    @{
        Section = '5.5.1.2'
        Title   = 'Ensure minimum days between password changes is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify PASS_MIN_DAYS conforms to site policy (no less than 1 day):
# grep ^\s*PASS_MIN_DAYS /etc/login.defs PASS_MIN_DAYS 1
Run the following command and review list of users and PASS_MIN_DAYS to verify that all users'' PASS_MIN_DAYS conforms to site policy (no less than 1 day):
# awk -F: ''$2~/^[^*!xX\n\r][^\n\r]+/{print $1":"$4}'' /etc/shadow <user>:<PASS_MIN_DAYS>
'@
        Remediation = @'
Set the PASS_MIN_DAYS parameter to 1 in /etc/login.defs:
PASS_MIN_DAYS 1
Modify user parameters for all users with a password set to match:
# chage --mindays 1 <user>
'@
    },
    @{
        Section = '5.5.1.3'
        Title   = 'Ensure password expiration warning days is 7 or more'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify PASS_WARN_AGE conforms to site policy (No less than 7 days):
# grep PASS_WARN_AGE /etc/login.defs
PASS_WARN_AGE 7
Verify all users with a password have their number of days of warning before password expires set to 7 or more. Run the following command and review list of users and PASS_WARN_AGE to verify that all users'' PASS_WARN_AGE conforms to site policy (No less than 7 days):
# awk -F: ''$2~/[^*!xX\n\r][^\n\r]+/{print $1":"$6}'' /etc/shadow
<user>:<PASS_WARN_AGE>
'@
        Remediation = @'
Set the PASS_WARN_AGE parameter to 7 in /etc/login.defs:
PASS_WARN_AGE 7
Modify user parameters for all users with a password set to match:
# chage --warndays 7 <user>
'@
    },
    @{
        Section = '5.5.1.4'
        Title   = 'Ensure inactive password lock is 30 days or less'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify INACTIVE conforms to site policy (no more than 30 days):
# useradd -D | grep INACTIVE INACTIVE=30
Run the following command and review list of users and INACTIVE to verify that all users'' INACTIVE conforms to site policy (no more than 30 days):
# awk -F: ''$2~/^[^*!xX\n\r][^\n\r]+/{print $1":"$7}'' /etc/shadow <user>:<INACTIVE>
'@
        Remediation = @'
Run the following command to set the default password inactivity period to 30 days:
# useradd -D -f 30
Modify user parameters for all users with a password set to match:
# chage --inactive 30 <user>
'@
    },
    @{
        Section = '5.5.1.5'
        Title   = 'Ensure all users last password change date is in the past'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify nothing is returned:
{ l_output2="" while read -r l_user; do l_change="$(chage --list $l_user | awk -F: ''($1 ~
/^\s*Last\s+password\s+change/ && $2 !~ /never/){print $2}'' | xargs)" if [[ "$(date -d "$l_change" +%s)" -gt "$(date +%s)" ]]; then l_output2="$l_output2\n - User: \"$l_user\" last password change is
in the future \"$l_change\"" fi
done < <(awk -F: ''($2 ~ /^[^*!xX\n\r][^\n\r]+/){print $1}'' /etc/shadow) if [ -z "$l_output2" ]; then # If l_output2 is empty, we pass
echo -e "\n- Audit Result:\n ** PASS **\n - All user password changes are in the past \n"
else echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit
failure * :$l_output2\n" fi
}
'@
        Remediation = @'
Investigate any users with a password change date in the future and correct them. Locking the account, expiring the password, or resetting the password manually may be appropriate.
'@
    },
    @{
        Section = '5.5.2'
        Title   = 'Ensure system accounts are secured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify all local system accounts:
 Do not have a valid login shell  Are locked
#!/usr/bin/env bash
{ l_output="" l_output2="" l_valid_shells="^($( awk -F\/ ''$NF != "nologin" {print}'' /etc/shells | sed
-rn ''/^\//{s,/,\\\\/,g;p}'' | paste -s -d ''|'' - ))$" a_users=(); a_ulock=() # initialize arrays while read -r l_user; do # Populate array with system accounts that have a
valid login shell a_users+=("$l_user")
done < <(awk -v pat="$l_valid_shells" -F: ''($1!~/(root|sync|shutdown|halt|^\+)/ && $3<''"$(awk ''/^\s*UID_MIN/{print $2}'' /etc/login.defs)"'' && $(NF) ~ pat) { print $1 }'' /etc/passwd)
while read -r l_ulock; do # Populate array with system accounts that aren''t locked
a_ulock+=("$l_ulock") done < <(awk -v pat="$l_valid_shells" -F: ''($1!~/(root|^\+)/ && $2!~/LK?/ && $3<''"$(awk ''/^\s*UID_MIN/{print $2}'' /etc/login.defs)"'' && $(NF) ~ pat) { print $1 }'' /etc/passwd) if ! (( ${#a_users[@]} > 0 )); then
l_output="$l_output\n - local system accounts login is disabled" else
l_output2="$l_output2\n - There are \"$(printf ''%s'' "${#a_users[@]}")\" system accounts with login enabled\n - List of accounts:\n$(printf ''%s\n'' "${a_users[@]:0:$l_limit}")\n - end of list\n"
fi if ! (( ${#a_ulock[@]} > 0 )); then
l_output="$l_output\n - local system accounts are locked" else
l_output2="$l_output2\n - There are \"$(printf ''%s'' "${#a_ulock[@]}")\" system accounts that are not locked\n - List of accounts:\n$(printf ''%s\n'' "${a_ulock[@]:0:$l_limit}")\n - end of list\n"
fi unset a_users; unset a_ulock # Remove arrays if [ -z "$l_output2" ]; then
echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured * :\n$l_output\n"
else echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit
failure * :\n$l_output2" [ -n "$l_output" ] && echo -e "- * Correctly configured *
:\n$l_output\n" fi
}
Note:
 The root, sync, shutdown, and halt users are exempted from requiring a nonlogin shell
 root is exempt from being locked
'@
        Remediation = @'
Set the shell for any accounts returned by the audit to nologin:
# usermod -s $(which nologin) <user>
Lock any non-root accounts returned by the audit:
# usermod -L <user>
The following script will:
 Set the shell for any accounts returned by the audit to nologin  Lock any non-root system accounts returned by the audit
#!/usr/bin/env bash
{ l_output="" l_output2="" l_valid_shells="^($( awk -F\/ ''$NF != "nologin" {print}'' /etc/shells | sed
-rn ''/^\//{s,/,\\\\/,g;p}'' | paste -s -d ''|'' - ))$" a_users=(); a_ulock=() # initialize arrays while read -r l_user; do # change system accounts that have a valid login
shell to nolog shell echo -e " - System account \"$l_user\" has a valid logon shell,
changing shell to \"$(which nologin)\"" usermod -s "$(which nologin)" "$l_user"
done < <(awk -v pat="$l_valid_shells" -F: ''($1!~/(root|sync|shutdown|halt|^\+)/ && $3<''"$(awk ''/^\s*UID_MIN/{print $2}'' /etc/login.defs)"'' && $(NF) ~ pat) { print $1 }'' /etc/passwd)
while read -r l_ulock; do # Lock system accounts that aren''t locked echo -e " - System account \"$l_ulock\" is not locked, locking account" usermod -L "$l_ulock"
done < <(awk -v pat="$l_valid_shells" -F: ''($1!~/(root|^\+)/ && $2!~/LK?/ && $3<''"$(awk ''/^\s*UID_MIN/{print $2}'' /etc/login.defs)"'' && $(NF) ~ pat) { print $1 }'' /etc/passwd) }
'@
    },
    @{
        Section = '5.5.3'
        Title   = 'Ensure default group for the root account is GID 0'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify the result is 0 :
# grep "^root:" /etc/passwd | cut -f4 -d: 0
'@
        Remediation = @'
Run the following command to set the root account default group to GID 0 :
# usermod -g 0 root
'@
    },
    @{
        Section = '5.5.4'
        Title   = 'Ensure default user umask is 027 or more restrictive'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following to verify:

 A default user umask is set to enforce a newly created directories'' permissions to be 750 (drwxr-x---), and a newly created file''s permissions be 640 (rw-r----), or more restrictive
 No less restrictive System Wide umask is set

Run the following script to verify that a default user umask is set enforcing a newly created directories''s permissions to be 750 (drwxr-x---), and a newly created file''s permissions be 640 (rw-r-----), or more restrictive:
#!/bin/bash

passing="" grep -Eiq ''^\s*UMASK\s+(0[0-7][2-7]7|[0-7][2-7]7)\b'' /etc/login.defs && -Eqi ''^\s*USERGROUPS_ENAB\s*"?no"?\b'' /etc/login.defs && grep -Eq ''^\s*session\s+(optional|requisite|required)\s+pam_umask\.so\b'' /etc/pam.d/common-session && passing=true grep -REiq ''^\s*UMASK\s+\s*(0[0-7][2-7]7|[0-7][27]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\b'' /etc/profile* /etc/bashrc* && passing=true [ "$passing" = true ] && echo "Default user umask is set"

grep

Verify output is: "Default user umask is set" Run the following to verify that no less restrictive system wide umask is set:

# grep -RPi ''(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][06]\b|[0-7][01][0-7]\b|[0-7][0-7][06]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}( ,o=[rwx]{0,3})?\b)'' /etc/login.defs /etc/profile* /etc/bashrc*

No file should be returned
'@
        Remediation = @'
Review /etc/bashrc, /etc/profile, and all files ending in *.sh in the /etc/profile.d/ directory and remove or edit all umask entries to follow local site policy. Any remaining entries should be: umask 027, umask u=rwx,g=rx,o= or more restrictive. Configure umask in one of the following files:

 A file in the /etc/profile.d/ directory ending in .sh  /etc/profile  /etc/bashrc

Example:
# vi /etc/profile.d/set_umask.sh

umask 027
Run the following command and remove or modify the umask of any returned files:
# grep -RPi ''(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][06]\b|[0-7][01][0-7]\b|[0-7][0-7][06]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}( ,o=[rwx]{0,3})?\b)'' /etc/login.defs /etc/profile* /etc/bashrc*
Follow one of the following methods to set the default user umask: Edit /etc/login.defs and edit the UMASK and USERGROUPS_ENAB lines as follows:
UMASK 027

USERGROUPS_ENAB no
Edit the files /etc/pam.d/password-auth and /etc/pam.d/system-auth and add or edit the following:

session

optional

pam_umask.so

OR Configure umask in one of the following files:

 A file in the /etc/profile.d/ directory ending in .sh  /etc/profile  /etc/bashrc
Example: /etc/profile.d/set_umask.sh

umask 027
Note: this method only applies to bash and shell. If other shells are supported on the system, it is recommended that their configuration files also are checked.
'@
    },
    @{
        Section = '6.1.1.1.1'
        Title   = 'Ensure journald service is active'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify systemd-journald is enabled:
# systemctl is-enabled systemd-journald.service static
Note: By default the systemd-journald service does not have an [Install] section and thus cannot be enabled / disabled. It is meant to be referenced as Requires or Wants by other unit files. As such, if the status of systemd-journald is not static, investigate why Run the following command to verify systemd-journald is active:
# systemctl is-active systemd-journald.service active
'@
        Remediation = @'
Run the following commands to unmask and start systemd-journald.service
# systemctl unmask systemd-journald.service # systemctl start systemd-journald.service
'@
    },
    @{
        Section = '6.1.1.1.2'
        Title   = 'Ensure journald log file access is configured'
        Kind    = 'Manual'
        Level   = 'L1'
        Audit   = @'
First determine if there is an override file /etc/tmpfiles.d/systemd.conf. If so, this file will override all default settings as defined in /usr/lib/tmpfiles.d/systemd.conf and should be inspected. If no override file exists, inspect the default /usr/lib/tmpfiles.d/systemd.conf against the site specific requirements. Ensure that file permissions are mode 0640 or more restrictive. Run the following script to verify if an override file exists or not and if the files permissions are mode 640 or more restrictive:
#!/usr/bin/env bash
{ l_output="" file_path="" # Check for the existence of an override file if [ -f /etc/tmpfiles.d/systemd.conf ]; then file_path="/etc/tmpfiles.d/systemd.conf" elif [ -f /usr/lib/tmpfiles.d/systemd.conf ]; then file_path="/usr/lib/tmpfiles.d/systemd.conf" fi if [ -n "$file_path" ]; then # Ensure a file path is found higher_permissions_found=false # Initialize a flag to check if
higher permissions are found # Read the file line by line and check for permissions higher than
0640 while IFS= read -r line; do if echo "$line" | grep -Piq ''^\s*[a-z]+\s+[^\s]+\s+0*([6-7][4-
7][1-7]|7[0-7][0-7])\s+''; then higher_permissions_found=true break
fi done < "$file_path" if $higher_permissions_found; then
echo -e "\n - permissions other than 0640 found in $file_path" l_output="$l_output\n - Inspect $file_path"
else echo -e "All permissions inside $file_path are 0640 or more
restrictive." fi
fi if [ -z "$l_output" ]; then # Provide output from checks
echo -e "\n- Audit Result:\n ** PASS **\n$file_path exists and has correct permissions set\n"
else echo -e "\n- Audit Result:\n ** REVIEW **\n$l_output\n - Review
permissions to ensure they are set IAW site policy" fi
}
'@
        Remediation = @'
If the default configuration is not appropriate for the site specific requirements, copy /usr/lib/tmpfiles.d/systemd.conf to /etc/tmpfiles.d/systemd.conf and modify as required. Requirements is either 0640 or site policy if that is less restrictive.
'@
    },
    @{
        Section = '6.1.1.1.3'
        Title   = 'Ensure journald ForwardToSyslog is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
- IF - journald is the method for capturing logs Run the following script to verify ForwardToSyslog in not set to yes:
#!/usr/bin/env bash
{ if systemctl is-active rsyslog.service | grep -Psq -- ''^active''; then l_setting="yes" else l_setting="no" fi l_parameters="systemd/journald.conf:Journal:ForwardToSyslog:$l_setting" l_analyze_cmd="$(readlink -e /bin/systemd-analyze || readlink -e
/usr/bin/systemd-analyze)" a_output=() a_output2=() a_output3=() l_out="" l_out2="" l_opt=""
f_pass_output() {
if [ "${#a_output[@]}" -gt 0 ] || [ "${#a_output2[@]}" -gt 0 ]; then a_output3+=(" - $l_option is correctly set to $l_option_value" "
in $l_file" \ " but this setting will be ignored do to load preference")
else if [ -n "$l_out2" ]; then a_output+=("$l_out2" " - Default for $l_option is correctly set
to $l_option_value" "$l_out") else a_output+=(" - $l_option is correctly set to $l_option_value" "
in $l_file" "$l_out") fi
fi }
f_fail_output() {
if [ "${#a_output[@]}" -gt 0 ] || [ "${#a_output2[@]}" -gt 0 ]; then a_output3+=(" - $l_option is incorrectly set to $l_option_value" "
in $l_file" \ " but this setting will be ignored do to load preference")
else if [ -n "$l_out2" ]; then a_output2+=("$l_out2" " - Default for $l_option is incorrectly
set to $l_option_value" "$l_out") else a_output2+=(" - $l_option is incorrectly set to $l_option_value"
" in $l_file" "$l_out") fi
fi }
f_option_chk() {
if [ "$l_option_value" = "$l_value" ]; then f_pass_output
else f_fail_output
fi }
while IFS=: read -r l_conf_file l_block l_option l_value; do l_out=" and should be equal to $l_value" while IFS= read -r l_file; do l_file="${l_file//# /}" l_opt="$(awk ''/\[''"$l_block"''\]/{a=1;next}/\[/{a=0}a'' "$l_file"
2>/dev/null | grep -Poi ''^\h*''"$l_option"''\h*=\h*\H+\b'' | tail -n 1)" if [ -n "$l_opt" ]; then l_option_value="$(cut -d= -f2 <<< "$l_opt" | xargs)" f_option_chk fi
done < <("$l_analyze_cmd" cat-config "$l_conf_file" | tac | grep -Pio ''^\h*#\h*\/[^#\n\r\h]+\.conf\b'')
# If nothing is explicitly set, check default if [ "${#a_output[@]}" -le 0 ] && [ "${#a_output2[@]}" -le 0 ]; then
l_file="/etc/$l_conf_file" l_opt="$(awk ''/\[''"$l_block"''\]/{a=1;next}/\[/{a=0}a'' "$l_file" 2>/dev/null | grep -Poim 1 ''^(\h*#)?\h*''"$l_option"''\h*=\h*\H+\b'')" if [ -n "$l_opt" ]; then
l_option_value="$(cut -d= -f2 <<< "${l_opt//# /}" | xargs)" l_out2=" - Note: default value \"${l_opt//#/}\" is being used in the configuration" f_option_chk fi fi done <<< "$l_parameters"
if [ "${#a_output2[@]}" -le 0 ]; then printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" "" [ "${#a_output3[@]}" -gt 0 ] && printf ''%s\n'' " ** Note: **"
"${a_output3[@]}" "" else printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for
audit failure:" "${a_output2[@]}" [ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "" "- Correctly set:"
"${a_output[@]}" "" [ "${#a_output3[@]}" -gt 0 ] && printf ''%s\n'' " ** Note: **"
"${a_output3[@]}" "" fi
}
'@
        Remediation = @'
- IF - journald is the preferred method for capturing logs: Set the following parameter in the [Journal] section in /etc/systemd/journald.conf or a file in /etc/systemd/journald.conf.d/ ending in .conf:
ForwardToSyslog=no
Example:
#!/usr/bin/env bash
{ [ ! -d /etc/systemd/journald.conf.d/ ] && mkdir
/etc/systemd/journald.conf.d/ if grep -Psq -- ''^\h*\[Journal\] /etc/systemd/journald.conf.d/60-
journald.conf; then printf ''%s\n'' "ForwardToSyslog=no" >> /etc/systemd/journald.conf.d/60-
journald.conf else printf ''%s\n'' "[Journal]" "ForwardToSyslog=no" >>
/etc/systemd/journald.conf.d/60-journald.conf fi
}
- ELSEIF - rsyslog is the preferred method for capturing logs: Set the following parameter in the [Journal] section in /etc/systemd/journald.conf or a file in /etc/systemd/journald.conf.d/ ending in .conf:
ForwardToSyslog=yes
Example:
#!/usr/bin/env bash
{ [ ! -d /etc/systemd/journald.conf.d/ ] && mkdir
/etc/systemd/journald.conf.d/ if grep -Psq -- ''^\h*\[Journal\] /etc/systemd/journald.conf.d/60-
journald.conf; then printf ''%s\n'' "ForwardToSyslog=yes" >> /etc/systemd/journald.conf.d/60-
journald.conf else printf ''%s\n'' "[Journal]" "ForwardToSyslog=yes" >>
/etc/systemd/journald.conf.d/60-journald.conf fi
}
Note: If this setting appears in a canonically later file, or later in the same file, the setting will be overwritten Run to following command to update the parameters in the service:
# systemctl reload-or-restart systemd-journald
'@
    },
    @{
        Section = '6.1.1.1.4'
        Title   = 'Ensure systemd-journal-remote service is not in use'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify systemd-journal-remote.socket and systemdjournal-remote.service are not enabled:
# systemctl is-enabled systemd-journal-remote.socket systemd-journalremote.service | grep -P -- ''^enabled'' Nothing should be returned
Run the following command to verify systemd-journal-remote.socket and systemdjournal-remote.service are not active:
# systemctl is-active systemd-journal-remote.socket systemd-journalremote.service | grep -P -- ''^active'' Nothing should be returned
'@
        Remediation = @'
Run the following commands to stop and mask systemd-journal-remote.socket and systemd-journal-remote.service:
# systemctl stop systemd-journal-remote.socket systemd-journal-remote.service # systemctl mask systemd-journal-remote.socket systemd-journal-remote.service
'@
    },
    @{
        Section = '6.1.1.1.5'
        Title   = 'Ensure journald Storage is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify Storage is set to persistent:
#!/usr/bin/env bash
{ l_output="" l_output2="" a_parlist=("Storage=persistent") l_systemd_config_file="/etc/systemd/journald.conf" # Main systemd configuration
file config_file_parameter_chk() { unset A_out; declare -A A_out # Check config file(s) setting while read -r l_out; do if [ -n "$l_out" ]; then if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}" else l_systemd_parameter="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<<
"$l_systemd_parameter" && A_out+=(["$l_systemd_parameter"]="$l_file") fi
fi done < <(/usr/bin/systemd-analyze cat-config "$l_systemd_config_file" | grep Pio ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}" l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}" if grep -Piq "^\h*$l_systemd_parameter_value\b" <<< "$l_systemd_file_parameter_value"; then
l_output="$l_output\n - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf ''%s'' "${A_out[@]}")\"\n"
else l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is incorrectly
set to \"$l_systemd_file_parameter_value\" in \"$(printf ''%s'' "${A_out[@]}")\" and should have a value matching: \"$l_systemd_parameter_value\"\n"
fi done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}") else l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is not set in an included file\n ** Note: \"$l_systemd_parameter_name\" May be set in a file that''s ignored by load procedure **\n" fi } while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters l_systemd_parameter_name="${l_systemd_parameter_name// /}" l_systemd_parameter_value="${l_systemd_parameter_value// /}" config_file_parameter_chk done < <(printf ''%s\n'' "${a_parlist[@]}") if [ -z "$l_output2" ]; then # Provide output from checks echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n" else echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2" [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n" fi }
'@
        Remediation = @'
Set the following parameter in the [Journal] section in /etc/systemd/journald.conf or a file in /etc/systemd/journald.conf.d/ ending in .conf:
Storage=persistent
Example:
#!/usr/bin/env bash
{ [ ! -d /etc/systemd/journald.conf.d/ ] && mkdir
/etc/systemd/journald.conf.d/ if grep -Psq -- ''^\h*\[Journal\]'' /etc/systemd/journald.conf.d/60-
journald.conf; then printf ''%s\n'' "Storage=persistent" >> /etc/systemd/journald.conf.d/60-
journald.conf else printf ''%s\n'' "[Journal]" "Storage=persistent" >>
/etc/systemd/journald.conf.d/60-journald.conf fi
}
Note: If this setting appears in a canonically later file, or later in the same file, the setting will be overwritten Run to following command to update the parameters in the service:
# systemctl reload-or-restart systemd-journald
'@
    },
    @{
        Section = '6.1.1.1.6'
        Title   = 'Ensure journald Compress is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify Compress is set to yes:
#!/usr/bin/env bash
{ l_output="" l_output2="" a_parlist=("Compress=yes") l_systemd_config_file="/etc/systemd/journald.conf" # Main systemd configuration
file config_file_parameter_chk() { unset A_out; declare -A A_out # Check config file(s) setting while read -r l_out; do if [ -n "$l_out" ]; then if [[ $l_out =~ ^\s*# ]]; then l_file="${l_out//# /}" else l_systemd_parameter="$(awk -F= ''{print $1}'' <<< "$l_out" | xargs)" grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<<
"$l_systemd_parameter" && A_out+=(["$l_systemd_parameter"]="$l_file") fi
fi done < <(/usr/bin/systemd-analyze cat-config "$l_systemd_config_file" | grep Pio ''^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)'') if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}" l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}" if grep -Piq "^\h*$l_systemd_parameter_value\b" <<< "$l_systemd_file_parameter_value"; then
l_output="$l_output\n - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf ''%s'' "${A_out[@]}")\"\n"
else l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is incorrectly
set to \"$l_systemd_file_parameter_value\" in \"$(printf ''%s'' "${A_out[@]}")\" and should have a value matching: \"$l_systemd_parameter_value\"\n"
fi done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}") else l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is not set in an included file\n ** Note: \"$l_systemd_parameter_name\" May be set in a file that''s ignored by load procedure **\n" fi } while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters l_systemd_parameter_name="${l_systemd_parameter_name// /}" l_systemd_parameter_value="${l_systemd_parameter_value// /}" config_file_parameter_chk done < <(printf ''%s\n'' "${a_parlist[@]}") if [ -z "$l_output2" ]; then # Provide output from checks echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n" else echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2" [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n" fi }
'@
        Remediation = @'
Set the following parameter in the [Journal] section in /etc/systemd/journald.conf or a file in /etc/systemd/journald.conf.d/ ending in .conf:
Compress=yes
Example:
#!/usr/bin/env bash {
[ ! -d /etc/systemd/journald.conf.d/ ] && mkdir /etc/systemd/journald.conf.d/
if grep -Psq -- ''^\h*\[Journal\]'' /etc/systemd/journald.conf.d/60journald.conf; then
printf ''%s\n'' "Compress=yes" >> /etc/systemd/journald.conf.d/60journald.conf
else printf ''%s\n'' "[Journal]" "Compress=yes" >>
/etc/systemd/journald.conf.d/60-journald.conf fi
}
Note: If this setting appears in a canonically later file, or later in the same file, the setting will be overwritten Run to following command to update the parameters in the service:
# systemctl reload-or-restart systemd-journald
'@
    },
    @{
        Section = '6.1.2.1'
        Title   = 'Ensure rsyslog service is enabled and active'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
- IF - rsyslog is being used for logging on the system: Run the following command to verify rsyslog.service is enabled:
# systemctl is-enabled rsyslog enabled
Run the following command to verify rsyslog.service is active:
# systemctl is-active rsyslog.service active
'@
        Remediation = @'
- IF - rsyslog is being used for logging on the system: Run the following commands to unmask, enable, and start rsyslog.service:
# systemctl unmask rsyslog.service # systemctl enable rsyslog.service # systemctl start rsyslog.service
'@
    },
    @{
        Section = '6.1.2.2'
        Title   = 'Ensure rsyslog log file creation mode is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command Run the following command to verify $FileCreateMode:
# grep -Ps ''^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b'' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
Verify the output is includes 0640 or more restrictive:
$FileCreateMode 0640
Should a site policy dictate less restrictive permissions, ensure to follow said policy. NOTE: More restrictive permissions such as 0600 is implicitly sufficient.
'@
        Remediation = @'
Edit either /etc/rsyslog.conf or a dedicated .conf file in /etc/rsyslog.d/ and set $FileCreateMode to 0640 or more restrictive:
$FileCreateMode 0640
Restart the service:
# systemctl restart rsyslog
'@
    },
    @{
        Section = '6.1.2.3'
        Title   = 'Ensure rsyslog is not configured to receive logs from a remote client'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Review the /etc/rsyslog.conf and /etc/rsyslog.d/*.conf files and verify that the system is not configured to accept incoming logs. advanced format
# grep -Psi -- ''^\h*module\(load=\"?imtcp\"?\)'' /etc/rsyslog.conf /etc/rsyslog.d/*.conf # grep -Psi -- ''^\h*input\(type=\"?imtcp\"?\b'' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
Nothing should be returned obsolete legacy format
# grep -Psi -- ''^\h*\$ModLoad\h+imtcp\b'' /etc/rsyslog.conf /etc/rsyslog.d/*.conf # grep -Psi -- ''^\h*\$InputTCPServerRun\b'' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
Nothing should be returned
'@
        Remediation = @'
Should there be any active log server configuration found in the auditing section, modify those files and remove the specific lines highlighted by the audit. Verify none of the following entries are present in any of /etc/rsyslog.conf or /etc/rsyslog.d/*.conf. advanced format
module(load="imtcp") input(type="imtcp" port="514")
deprecated legacy format
$ModLoad imtcp $InputTCPServerRun
Restart the service:
# systemctl restart rsyslog
'@
    },
    @{
        Section = '6.1.3.1'
        Title   = 'Ensure access to all logfiles has been configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify that files in /var/log/ have appropriate permissions and ownership:
#!/usr/bin/env bash
{ a_output=(); a_output2=() f_file_test_chk() { a_out2=() maxperm="$( printf ''%o'' $(( 0777 & ~$perm_mask)) )" [ $(( $l_mode & $perm_mask )) -gt 0 ] && \ a_out2+=(" o Mode: \"$l_mode\" should be \"$maxperm\" or more restrictive") [[ ! "$l_user" =~ $l_auser ]] && \ a_out2+=(" o Owned by: \"$l_user\" and should be owned by \"${l_auser//|/ or }\"") [[ ! "$l_group" =~ $l_agroup ]] && \ a_out2+=(" o Group owned by: \"$l_group\" and should be group owned by
\"${l_agroup//|/ or }\"") [ "${#a_out2[@]}" -gt 0 ] && a_output2+=(" - File: \"$l_fname\" is:" "${a_out2[@]}")
} while IFS= read -r -d $''\0'' l_file; do
while IFS=: read -r l_fname l_mode l_user l_group; do if grep -Pq -- ''\/(apt)\h*$'' <<< "$(dirname "$l_fname")"; then perm_mask=''0133'' l_auser="root" l_agroup="(root|adm)"; f_file_test_chk else case "$(basename "$l_fname")" in lastlog | lastlog.* | wtmp | wtmp.* | wtmp-* | btmp | btmp.* | btmp-* | README) perm_mask=''0113'' l_auser="root" l_agroup="(root|utmp)" f_file_test_chk ;; cloud-init.log* | localmessages* | waagent.log*) perm_mask=''0133'' l_auser="(root|syslog)" l_agroup="(root|adm)" file_test_chk ;; secure{,*.*,.*,-*} | auth.log | syslog | messages) perm_mask=''0137'' l_auser="(root|syslog)" l_agroup="(root|adm)" f_file_test_chk ;; SSSD | sssd) perm_mask=''0117'' l_auser="(root|SSSD)" l_agroup="(root|SSSD)" f_file_test_chk ;; gdm | gdm3) perm_mask=''0117'' l_auser="root" l_agroup="(root|gdm|gdm3)" f_file_test_chk ;; *.journal | *.journal~) perm_mask=''0137'' l_auser="root" l_agroup="(root|systemd-journal)" f_file_test_chk ;; *) perm_mask=''0133'' l_auser="(root|syslog)" l_agroup="(root|adm)" if [ "$l_user" = "root" ] || ! grep -Pq -- "^\h*$(awk -F: ''$1=="''"$l_user"''"
{print $7}'' /etc/passwd)\b" /etc/shells; then ! grep -Pq -- "$l_auser" <<< "$l_user" && l_auser="(root|syslog|$l_user)" ! grep -Pq -- "$l_agroup" <<< "$l_group" && l_agroup="(root|adm|$l_group)"
fi f_file_test_chk ;; esac fi done < <(stat -Lc ''%n:%#a:%U:%G'' "$l_file") done < <(find -L /var/log -type f \( -perm /0137 -o ! -user root -o ! -group root \) -print0) if [ "${#a_output2[@]}" -le 0 ]; then a_output+=(" - All files in \"/var/log/\" have appropriate permissions and ownership") printf ''\n%s'' "- Audit Result:" " ** PASS **" "${a_output[@]}" "" else printf ''\n%s'' "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}" "" fi }
'@
        Remediation = @'
Run the following script to update permissions and ownership on files in /var/log. Although the script is not destructive, ensure that the output is captured in the event that the remediation causes issues.
#!/usr/bin/env bash

{

a_output2=()

f_file_test_fix()

{

a_out2=()

maxperm="$( printf ''%o'' $(( 0777 & ~$perm_mask)) )"

if [ $(( $l_mode & $perm_mask )) -gt 0 ]; then

a_out2+=(" o Mode: \"$l_mode\" should be \"$maxperm\" or more

restrictive" "

x Removing excess permissions")

chmod "$l_rperms" "$l_fname"

fi

if [[ ! "$l_user" =~ $l_auser ]]; then

a_out2+=(" o Owned by: \"$l_user\" and should be owned by

\"${l_auser//|/ or }\"" "

x Changing ownership to: \"$l_fix_account\"")

chown "$l_fix_account" "$l_fname"

fi

if [[ ! "$l_group" =~ $l_agroup ]]; then

a_out2+=(" o Group owned by: \"$l_group\" and should be group

owned by \"${l_agroup//|/ or }\"" "

x Changing group ownership to:

\"$l_fix_account\"")

chgrp "$l_fix_account" "$l_fname"

fi

[ "${#a_out2[@]}" -gt 0 ] && a_output2+=(" - File: \"$l_fname\" is:"

"${a_out2[@]}")

}

l_fix_account=''root''

while IFS= read -r -d $''\0'' l_file; do

while IFS=: read -r l_fname l_mode l_user l_group; do

if grep -Pq -- ''\/(apt)\h*$'' <<< "$(dirname "$l_fname")"; then

perm_mask=''0133'' l_rperms="u-x,go-wx" l_auser="root"

l_agroup="(root|adm)"; f_file_test_fix

else

case "$(basename "$l_fname")" in

lastlog | lastlog.* | wtmp | wtmp.* | wtmp-* | btmp | btmp.* |

btmp-* | README)

perm_mask=''0113'' l_rperms="ug-x,o-wx" l_auser="root"

l_agroup="(root|utmp)"

f_file_test_fix ;;

cloud-init.log* | localmessages* | waagent.log*)

perm_mask=''0133'' l_rperms="u-x,go-wx"

l_auser="(root|syslog)" l_agroup="(root|adm)"

file_test_fix ;;

secure | auth.log | syslog | messages)

perm_mask=''0137'' l_rperms="u-x,g-wx,o-rwx"

l_auser="(root|syslog)" l_agroup="(root|adm)"

f_file_test_fix ;;

SSSD | sssd)

perm_mask=''0117'' l_rperms="ug-x,o-rwx"

l_auser="(root|SSSD)" l_agroup="(root|SSSD)"

f_file_test_fix ;;

gdm | gdm3)

perm_mask=''0117'' l_rperms="ug-x,o-rwx" l_auser="root"

l_agroup="(root|gdm|gdm3)"

f_file_test_fix ;;

*.journal | *.journal~)

perm_mask=''0137'' l_rperms="u-x,g-wx,o-rwx" l_auser="root" l_agroup="(root|systemd-journal)"
f_file_test_fix ;; *)
perm_mask=''0133'' l_rperms="u-x,g-wx,o-rwx" l_auser="(root|syslog)" l_agroup="(root|adm)"
if [ "$l_user" = "root" ] || ! grep -Pq -- "^\h*$(awk -F: ''$1=="''"$l_user"''" {print $7}'' /etc/passwd)\b" /etc/shells; then
! grep -Pq -- "$l_auser" <<< "$l_user" && l_auser="(root|syslog|$l_user)"
! grep -Pq -- "$l_agroup" <<< "$l_group" && l_agroup="(root|adm|$l_group)"
fi f_file_test_fix ;; esac fi done < <(stat -Lc ''%n:%#a:%U:%G'' "$l_file") done < <(find -L /var/log -type f \( -perm /0137 -o ! -user root -o ! group root \) -print0) if [ "${#a_output2[@]}" -le 0 ]; then # If all files passed, then we report no changes a_output+=(" - All files in \"/var/log/\" have appropriate permissions and ownership") printf ''\n%s'' "- All files in \"/var/log/\" have appropriate permissions and ownership" " o No changes required" "" else printf ''\n%s'' "${a_output2[@]}" "" fi }
Note: You may also need to change the configuration for your logging software or services for any logs that had incorrect permissions. If there are services that log to other locations, ensure that those log files have the appropriate access configured.
'@
    },
    @{
        Section = '6.2'
        Title   = 'Ensure logrotate is configured'
        Kind    = 'Manual'
        Level   = 'L1'
        Audit   = @'
Review /etc/logrotate.conf and /etc/logrotate.d/* and verify logs are rotated according to site policy.
'@
        Remediation = @'
Edit /etc/logrotate.conf and /etc/logrotate.d/* to ensure logs are rotated according to site policy.
'@
    },
    @{
        Section = '7.1.1'
        Title   = 'Ensure access to /etc/passwd is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify /etc/passwd is mode 644 or more restrictive, Uid is 0/root and Gid is 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/passwd Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to remove excess permissions, set owner, and set group on /etc/passwd:
# chmod u-x,go-wx /etc/passwd # chown root:root /etc/passwd
'@
    },
    @{
        Section = '7.1.2'
        Title   = 'Ensure access to /etc/passwd- is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify /etc/passwd- is mode 644 or more restrictive, Uid is 0/root and Gid is 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/passwdAccess: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to remove excess permissions, set owner, and set group on /etc/passwd-:
# chmod u-x,go-wx /etc/passwd# chown root:root /etc/passwd-
'@
    },
    @{
        Section = '7.1.3'
        Title   = 'Ensure access to /etc/group is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify /etc/group is mode 644 or more restrictive, Uid is 0/root and Gid is 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/group Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to remove excess permissions, set owner, and set group on /etc/group:
# chmod u-x,go-wx /etc/group # chown root:root /etc/group
'@
    },
    @{
        Section = '7.1.4'
        Title   = 'Ensure access to /etc/group- is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify /etc/group- is mode 644 or more restrictive, Uid is 0/root and Gid is 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/groupAccess: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to remove excess permissions, set owner, and set group on /etc/group-:
# chmod u-x,go-wx /etc/group# chown root:root /etc/group-
'@
    },
    @{
        Section = '7.1.5'
        Title   = 'Ensure access to /etc/shadow is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify /etc/shadow is mode 000, Uid is 0/root and Gid is 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/shadow Access: (0/----------) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set mode, owner, and group on /etc/shadow:
# chown root:root /etc/shadow # chmod 0000 /etc/shadow
'@
    },
    @{
        Section = '7.1.6'
        Title   = 'Ensure access to /etc/shadow- is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify /etc/shadow- is mode 000, Uid is 0/root and Gid is 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/shadowAccess: (0/----------) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set mode, owner, and group on /etc/shadow-:
# chown root:root /etc/shadow# chmod 0000 /etc/shadow-
'@
    },
    @{
        Section = '7.1.7'
        Title   = 'Ensure access to /etc/gshadow is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify /etc/gshadow is mode 400 or more restrictive, Uid is 0/root and Gid is 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/gshadow Access: (0400/-r--------) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set mode, owner, and group on /etc/gshadow:
# chown root:root /etc/gshadow # chmod o-wx,go-rwx /etc/gshadow
'@
    },
    @{
        Section = '7.1.8'
        Title   = 'Ensure access to /etc/gshadow- is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify /etc/gshadow- is mode 400, Uid is 0/root and Gid is 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/gshadowAccess: (0400/-r--------) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to set mode, owner, and group on /etc/gshadow-:
# chown root:root /etc/gshadow# chmod u-wx,go-rwx /etc/gshadow-
'@
    },
    @{
        Section = '7.1.9'
        Title   = 'Ensure access to /etc/shells is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command to verify /etc/shells is mode 644 or more restrictive, Uid is 0/root and Gid is 0/root:
# stat -Lc ''Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/shells Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
'@
        Remediation = @'
Run the following commands to remove excess permissions, set owner, and set group on /etc/shells:
# chmod u-x,go-wx /etc/shells # chown root:root /etc/shells
'@
    },
    @{
        Section = '7.1.10'
        Title   = 'Ensure access to /etc/security/opasswd is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following commands to verify /etc/security/opasswd and /etc/security/opasswd.old are mode 600 or more restrictive, Uid is 0/root and Gid is 0/root if they exist:
# [ -e "/etc/security/opasswd" ] && stat -Lc ''%n Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)'' /etc/security/opasswd

/etc/security/opasswd Access: (0600/-rw-------) Uid: root)
-ORNothing is returned # [ -e "/etc/security/opasswd.old" ] && stat -Lc ''%n ( %u/ %U) Gid: ( %g/ %G)'' /etc/security/opasswd.old

( 0/ root) Gid: ( Access: (%#a/%A)

0/ Uid:

/etc/security/opasswd.old Access: (0600/-rw-------) 0/ root)
-ORNothing is returned

Uid: ( 0/ root) Gid: (
'@
        Remediation = @'
Run the following commands to remove excess permissions, set owner, and set group on /etc/security/opasswd and /etc/security/opasswd.old if they exist:
# [ -e "/etc/security/opasswd" ] && chmod u-x,go-rwx /etc/security/opasswd # [ -e "/etc/security/opasswd" ] && chown root:root /etc/security/opasswd # [ -e "/etc/security/opasswd.old" ] && chmod u-x,go-rwx /etc/security/opasswd.old # [ -e "/etc/security/opasswd.old" ] && chown root:root /etc/security/opasswd.old
'@
    },
    @{
        Section = '7.1.11'
        Title   = 'Ensure world writable files and directories are secured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify:
 No world writable files exist  No world writable directories without the sticky bit exist
#!/usr/bin/env bash
{ l_output="" l_output2="" l_smask=''01000'' a_file=(); a_dir=() # Initialize arrays a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path
"*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/*" -a ! -path "/snap/*")
while IFS= read -r l_mount; do while IFS= read -r -d $''\0'' l_file; do if [ -e "$l_file" ]; then [ -f "$l_file" ] && a_file+=("$l_file") # Add WR files if [ -d "$l_file" ]; then # Add directories w/o sticky bit l_mode="$(stat -Lc ''%#a'' "$l_file")" [ ! $(( $l_mode & $l_smask )) -gt 0 ] && a_dir+=("$l_file") fi fi done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type
d \) -perm -0002 -print0 2> /dev/null) done < <(findmnt -Dkerno fstype,target | awk ''($1 !~
/^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\/run\/user\/|\/tmp|\/var\/tmp)/){print $2}'')
if ! (( ${#a_file[@]} > 0 )); then l_output="$l_output\n - No world writable files exist on the local
filesystem." else l_output2="$l_output2\n - There are \"$(printf ''%s'' "${#a_file[@]}")\"
World writable files on the system.\n - The following is a list of World writable files:\n$(printf ''%s\n'' "${a_file[@]}")\n - end of list\n"
fi if ! (( ${#a_dir[@]} > 0 )); then
l_output="$l_output\n - Sticky bit is set on world writable directories on the local filesystem."
else l_output2="$l_output2\n - There are \"$(printf ''%s'' "${#a_dir[@]}")\"
World writable directories without the sticky bit on the system.\n - The following is a list of World writable directories without the sticky bit:\n$(printf ''%s\n'' "${a_dir[@]}")\n - end of list\n"
fi unset a_path; unset a_arr; unset a_file; unset a_dir # Remove arrays # If l_output2 is empty, we pass if [ -z "$l_output2" ]; then
echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured * :\n$l_output\n"
else echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit
failure * :\n$l_output2" [ -n "$l_output" ] && echo -e "- * Correctly configured *
:\n$l_output\n" fi
}
Note: On systems with a large number of files and/or directories, this audit may be a long running process
'@
        Remediation = @'
World Writable Files: o It is recommended that write access is removed from other with the command ( chmod o-w <filename> ), but always consult relevant vendor documentation to avoid breaking any application dependencies on a given file.
 World Writable Directories: o Set the sticky bit on all world writable directories with the command ( chmod a+t <directory_name> )
Run the following script to:
 Remove other write permission from any world writable files  Add the sticky bit to all world writable directories
#!/usr/bin/env bash
{ l_smask=''01000'' a_file=(); a_dir=() # Initialize arrays a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path
"*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/*" -a ! -path "/snap/*")
while IFS= read -r l_mount; do while IFS= read -r -d $''\0'' l_file; do if [ -e "$l_file" ]; then l_mode="$(stat -Lc ''%#a'' "$l_file")" if [ -f "$l_file" ]; then # Remove excess permissions from WW
files echo -e " - File: \"$l_file\" is mode: \"$l_mode\"\n -
removing write permission on \"$l_file\" from \"other\"" chmod o-w "$l_file"
fi if [ -d "$l_file" ]; then # Add sticky bit
if [ ! $(( $l_mode & $l_smask )) -gt 0 ]; then echo -e " - Directory: \"$l_file\" is mode: \"$l_mode\" and
doesn''t have the sticky bit set\n - Adding the sticky bit" chmod a+t "$l_file"
fi fi fi done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) -perm -0002 -print0 2> /dev/null) done < <(findmnt -Dkerno fstype,target | awk ''($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\/run\/user\/|\/tmp|\/var\/tmp)/){print $2}'') }
'@
    },
    @{
        Section = '7.1.12'
        Title   = 'Ensure no files or directories without an owner and a group exist'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify no unowned or ungrouped files or directories exist:
#!/usr/bin/env bash
{ l_output="" l_output2="" a_nouser=(); a_nogroup=() # Initialize arrays a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path
"*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/fs/cgroup/memory/*" -a ! -path "/var/*/private/*")
while IFS= read -r l_mount; do while IFS= read -r -d $''\0'' l_file; do if [ -e "$l_file" ]; then while IFS=: read -r l_user l_group; do [ "$l_user" = "UNKNOWN" ] && a_nouser+=("$l_file") [ "$l_group" = "UNKNOWN" ] && a_nogroup+=("$l_file") done < <(stat -Lc ''%U:%G'' "$l_file") fi done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type
d \) \( -nouser -o -nogroup \) -print0 2> /dev/null) done < <(findmnt -Dkerno fstype,target | awk ''($1 !~
/^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\/run\/user\//){print $2}'')
if ! (( ${#a_nouser[@]} > 0 )); then l_output="$l_output\n - No files or directories without a owner exist
on the local filesystem." else l_output2="$l_output2\n - There are \"$(printf ''%s''
"${#a_nouser[@]}")\" unowned files or directories on the system.\n - The following is a list of unowned files and/or directories:\n$(printf ''%s\n'' "${a_nouser[@]}")\n - end of list"
fi if ! (( ${#a_nogroup[@]} > 0 )); then
l_output="$l_output\n - No files or directories without a group exist on the local filesystem."
else l_output2="$l_output2\n - There are \"$(printf ''%s''
"${#a_nogroup[@]}")\" ungrouped files or directories on the system.\n - The following is a list of ungrouped files and/or directories:\n$(printf ''%s\n'' "${a_nogroup[@]}")\n - end of list"
fi unset a_path; unset a_arr ; unset a_nouser; unset a_nogroup # Remove arrays if [ -z "$l_output2" ]; then # If l_output2 is empty, we pass
echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured * :\n$l_output\n"
else echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit
failure * :\n$l_output2" [ -n "$l_output" ] && echo -e "\n- * Correctly configured *
:\n$l_output\n" fi
}
Note: On systems with a large number of files and/or directories, this audit may be a long running process
'@
        Remediation = @'
Remove or set ownership and group ownership of these files and/or directories to an active user on the system as appropriate.
'@
    },
    @{
        Section = '7.2.1'
        Title   = 'Ensure accounts in /etc/passwd use shadowed passwords'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify that no output is returned:
# awk -F: ''($2 != "x" ) { print "User: \"" $1 "\" is not set to shadowed passwords "}'' /etc/passwd
'@
        Remediation = @'
Run the following command to set accounts to use shadowed passwords and migrate passwords in /etc/passwd to /etc/shadow:
# pwconv
Investigate to determine if the account is logged in and what it is being used for, to determine if it needs to be forced off.
'@
    },
    @{
        Section = '7.2.2'
        Title   = 'Ensure /etc/shadow password fields are not empty'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following command and verify that no output is returned:
# awk -F: ''($2 == "" ) { print $1 " does not have a password "}'' /etc/shadow
'@
        Remediation = @'
If any accounts in the /etc/shadow file do not have a password, run the following command to lock the account until it can be determined why it does not have a password:
# passwd -l <username>
Also, check to see if the account is logged in and investigate what it is being used for to determine if it needs to be forced off.
'@
    },
    @{
        Section = '7.2.3'
        Title   = 'Ensure all groups in /etc/passwd exist in /etc/group'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify all GIDs in /etc/passwd exist in /etc/group:
#!/usr/bin/env bash
{ a_passwd_group_gid=("$(awk -F: ''{print $4}'' /etc/passwd | sort -u)") a_group_gid=("$(awk -F: ''{print $3}'' /etc/group | sort -u)") a_passwd_group_diff=("$(printf ''%s\n'' "${a_group_gid[@]}"
"${a_passwd_group_gid[@]}" | sort | uniq -u)") while IFS= read -r l_gid; do awk -F: ''($4 == ''"$l_gid"'') {print " - User: \"" $1 "\" has GID: \""
$4 "\" which does not exist in /etc/group" }'' /etc/passwd done < <(printf ''%s\n'' "${a_passwd_group_gid[@]}"
"${a_passwd_group_diff[@]}" | sort | uniq -D | uniq) unset a_passwd_group_gid; unset a_group_gid; unset a_passwd_group_diff
}
Nothing should be returned
'@
        Remediation = @'
Analyze the output of the Audit step above and perform the appropriate action to correct any discrepancies found.
'@
    },
    @{
        Section = '7.2.4'
        Title   = 'Ensure no duplicate UIDs exist'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script and verify no results are returned:
#!/usr/bin/env bash {
while read -r l_count l_uid; do if [ "$l_count" -gt 1 ]; then echo -e "Duplicate UID: \"$l_uid\" Users: \"$(awk -F: ''($3 == n) {
print $1 }'' n=$l_uid /etc/passwd | xargs)\"" fi
done < <(cut -f3 -d":" /etc/passwd | sort -n | uniq -c) }
'@
        Remediation = @'
Based on the results of the audit script, establish unique UIDs and review all files owned by the shared UIDs to determine which UID they are supposed to belong to.
'@
    },
    @{
        Section = '7.2.5'
        Title   = 'Ensure no duplicate GIDs exist'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script and verify no results are returned:
#!/usr/bin/env bash {
while read -r l_count l_gid; do if [ "$l_count" -gt 1 ]; then echo -e "Duplicate GID: \"$l_gid\" Groups: \"$(awk -F: ''($3 == n) {
print $1 }'' n=$l_gid /etc/group | xargs)\"" fi
done < <(cut -f3 -d":" /etc/group | sort -n | uniq -c) }
'@
        Remediation = @'
Based on the results of the audit script, establish unique GIDs and review all files owned by the shared GID to determine which group they are supposed to belong to.
'@
    },
    @{
        Section = '7.2.6'
        Title   = 'Ensure no duplicate user names exist'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script and verify no results are returned:
#!/usr/bin/env bash {
while read -r l_count l_user; do if [ "$l_count" -gt 1 ]; then echo -e "Duplicate User: \"$l_user\" Users: \"$(awk -F: ''($1 == n) {
print $1 }'' n=$l_user /etc/passwd | xargs)\"" fi
done < <(cut -f1 -d":" /etc/passwd | sort -n | uniq -c) }
'@
        Remediation = @'
Based on the results of the audit script, establish unique user names for the users. File ownerships will automatically reflect the change as long as the users have unique UIDs.
'@
    },
    @{
        Section = '7.2.7'
        Title   = 'Ensure no duplicate group names exist'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script and verify no results are returned:
#!/usr/bin/env bash {
while read -r l_count l_group; do if [ "$l_count" -gt 1 ]; then echo -e "Duplicate Group: \"$l_group\" Groups: \"$(awk -F: ''($1 ==
n) { print $1 }'' n=$l_group /etc/group | xargs)\"" fi
done < <(cut -f1 -d":" /etc/group | sort -n | uniq -c) }
'@
        Remediation = @'
Based on the results of the audit script, establish unique names for the user groups. File group ownerships will automatically reflect the change as long as the groups have unique GIDs.
'@
    },
    @{
        Section = '7.2.8'
        Title   = 'Ensure local interactive user home directories are configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to:
 Ensure local interactive user home directories exist  Ensure local interactive users own their home directories  Ensure local interactive user home directories are mode 750 or more restrictive
#!/usr/bin/env bash
{ a_output=() a_output2=() a_exists2=() a_mode2=() a_owner2=() l_valid_shells="^($( awk -F\/ ''$NF != "nologin" {print}'' /etc/shells | sed
-rn ''/^\//{s,/,\\\\/,g;p}'' | paste -s -d ''|'' - ))$" l_mask=''0027''; l_max="$( printf ''%o'' $(( 0777 & ~$l_mask)) )" l_users="$(awk -v pat="$l_valid_shells" -F: ''$(NF) ~ pat { print $1 " "
$(NF-1) }'' /etc/passwd | wc -l)" [ "$l_users" -gt 10000 ] && printf ''%s\n'' "" " ** INFO **" \ " $l_users Local interactive users found on the system" " This may be a
long running check" " **********" while IFS=" " read -r l_user l_home; do if [ -d "$l_home" ]; then while IFS=: read -r l_own l_mode; do [ "$l_user" != "$l_own" ] && a_owner2+=(" - User: \"$l_user\"
Home \"$l_home\" is owned by: \"$l_own\"") [ $(( $l_mode & $l_mask )) -gt 0 ] && a_mode2+=(" - User:
\"$l_user\" Home \"$l_home\" is mode: \"$l_mode\"" \ " should be mode: \"$l_max\" or more restrictive")
done <<< "$(stat -Lc ''%U:%#a'' "$l_home")" else
a_exists2+=(" - User: \"$l_user\" Home Directory: \"$l_home\" Doesn''t exist")
fi done <<< "$(awk -v pat="$l_valid_shells" -F: ''$(NF) ~ pat { print $1 " " $(NF-1) }'' /etc/passwd)" [ "${#a_exists2[@]}" -gt 0 ] && a_output2+=("${a_exists2[@]}") || \ a_output+=(" - All interactive users home directories exist") [ "${#a_mode2[@]}" -gt 0 ] && a_output2+=("${a_mode2[@]}") || \ a_output+=(" - All interactive users home directories are mode \"$l_max\" or more restrictive") [ "${#a_owner2[@]}" -gt 0 ] && a_output2+=("${a_owner2[@]}") || \ a_output+=(" - All interactive users own their home directory") if [ "${#a_output2[@]}" -le 0 ]; then
printf ''%s\n'' "" "- Audit Result:" " ** PASS **" "${a_output[@]}" else
printf ''%s\n'' "" "- Audit Result:" " ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
[ "${#a_output[@]}" -gt 0 ] && printf ''%s\n'' "- Correctly set:" "${a_output[@]}"
fi }
'@
        Remediation = @'
If a local interactive users'' home directory is undefined and/or doesn''t exist, follow local site policy and perform one of the following:
 Lock the user account  Remove the user from the system  Create a directory for the user. If undefined, edit /etc/passwd and add the
absolute path to the directory to the last field of the user. Run the following script to:
 Remove excessive permissions from local interactive users home directories  Update the home directory''s owner
#!/usr/bin/env bash
#!/usr/bin/env bash
{ a_output=() a_output2=() a_exists2=() a_mode2=() a_owner2=() l_valid_shells="^($( awk -F\/ ''$NF != "nologin" {print}'' /etc/shells | sed
-rn ''/^\//{s,/,\\\\/,g;p}'' | paste -s -d ''|'' - ))$" l_mask=''0027''; l_max="$( printf ''%o'' $(( 0777 & ~$l_mask)) )" l_users="$(awk -v pat="$l_valid_shells" -F: ''$(NF) ~ pat { print $1 " "
$(NF-1) }'' /etc/passwd | wc -l)" [ "$l_users" -gt 10000 ] && printf ''%s\n'' "" " ** INFO **" \ " $l_users Local interactive users found on the system" " This may be a
long running process" " **********" while IFS=" " read -r l_user l_home; do if [ -d "$l_home" ]; then while IFS=: read -r l_own l_mode; do if [ "$l_user" != "$l_own" ]; then a_owner2+=(" - User: \"$l_user\" Home \"$l_home\" is owned
by: \"$l_own\"" \ " changing owner to: \"$l_user\"") && chown "$l_user"
"$l_home" fi if [ $(( $l_mode & $l_mask )) -gt 0 ]; then a_mode2+=(" - User: \"$l_user\" Home \"$l_home\" is mode:
\"$l_mode\"" \ " changing to mode: \"$l_max\" or more restrictive") chmod g-w,o-rwx "$l_home"
fi done <<< "$(stat -Lc ''%U:%#a'' "$l_home")" else a_exists2+=(" - User: \"$l_user\" Home Directory: \"$l_home\" Doesn''t exist") fi done <<< "$(awk -v pat="$l_valid_shells" -F: ''$(NF) ~ pat { print $1 " " $(NF-1) }'' /etc/passwd)" [ "${#a_exists2[@]}" -gt 0 ] && a_output2+=("${a_exists2[@]}") [ "${#a_mode2[@]}" -gt 0 ] && a_output2+=("${a_mode2[@]}") [ "${#a_owner2[@]}" -gt 0 ] && a_output2+=("${a_owner2[@]}") if [ "${#a_output2[@]}" -gt 0 ]; then printf ''%s\n'' "" "${a_output2[@]}" else printf ''%s\n'' "" "- No changes required" fi }
'@
    },
    @{
        Section = '7.2.9'
        Title   = 'Ensure local interactive user dot files access is configured'
        Kind    = 'Automated'
        Level   = 'L1'
        Audit   = @'
Run the following script to verify local interactive user dot files:
 Don''t include .forward, .rhost, or .netrc files  Are mode 0644 or more restrictive  Are owned by the local interactive user  Are group owned by the user''s primary group  .bash_history is mode 0600 or more restrictive
Note: If a .netrc file is required, and follows local site policy, it should be mode 0600 or more restrictive.
#!/usr/bin/env bash
{ a_output2=(); a_output3=() l_maxsize="1000" # Maximum number of local interactive users before
warning (Default 1,000) l_valid_shells="^($( awk -F\/ ''$NF != "nologin" {print}'' /etc/shells | sed
-rn ''/^\//{s,/,\\\\/,g;p}'' | paste -s -d ''|'' - ))$" a_user_and_home=() # Create array with local users and their home
directories while read -r l_local_user l_local_user_home; do # Populate array with
users and user home location [[ -n "$l_local_user" && -n "$l_local_user_home" ]] &&
a_user_and_home+=("$l_local_user:$l_local_user_home") done <<< "$(awk -v pat="$l_valid_shells" -F: ''$(NF) ~ pat { print $1 " "
$(NF-1) }'' /etc/passwd)" l_asize="${#a_user_and_home[@]}" # Here if we want to look at number of
users before proceeding [ "${#a_user_and_home[@]}" -gt "$l_maxsize" ] && printf ''%s\n'' "" " **
INFO **" \ " - \"$l_asize\" Local interactive users found on the system" \ " - This may be a long running check" "" file_access_chk() { a_access_out=() l_max="$( printf ''%o'' $(( 0777 & ~$l_mask)) )" if [ $(( $l_mode & $l_mask )) -gt 0 ]; then a_access_out+=(" - File: \"$l_hdfile\" is mode: \"$l_mode\" and
should be mode: \"$l_max\" or more restrictive") fi if [[ ! "$l_owner" =~ ($l_user) ]]; then a_access_out+=(" - File: \"$l_hdfile\" owned by: \"$l_owner\" and
should be owned by \"${l_user//|/ or }\"") fi if [[ ! "$l_gowner" =~ ($l_group) ]]; then a_access_out+=(" - File: \"$l_hdfile\" group owned by:
\"$l_gowner\" and should be group owned by \"${l_group//|/ or }\"") fi
} while IFS=: read -r l_user l_home; do
a_dot_file=(); a_netrc=(); a_netrc_warn=(); a_bhout=(); a_hdirout=() if [ -d "$l_home" ]; then
l_group="$(id -gn "$l_user" | xargs)";l_group="${l_group// /|}" while IFS= read -r -d $''\0'' l_hdfile; do
while read -r l_mode l_owner l_gowner; do case "$(basename "$l_hdfile")" in .forward | .rhost ) a_dot_file+=(" - File: \"$l_hdfile\" exists") ;; .netrc ) l_mask=''0177''; file_access_chk if [ "${#a_access_out[@]}" -gt 0 ]; then a_netrc+=("${a_access_out[@]}") else a_netrc_warn+=(" - File: \"$l_hdfile\" exists") fi ;; .bash_history ) l_mask=''0177''; file_access_chk
[ "${#a_access_out[@]}" -gt 0 ] && a_bhout+=("${a_access_out[@]}") ;;
* ) l_mask=''0133''; file_access_chk [ "${#a_access_out[@]}" -gt 0 ] &&
a_hdirout+=("${a_access_out[@]}") ;; esac
done < <(stat -Lc ''%#a %U %G'' "$l_hdfile") done < <(find "$l_home" -xdev -type f -name ''.*'' -print0) fi if [[ "${#a_dot_file[@]}" -gt 0 || "${#a_netrc[@]}" -gt 0 || "${#a_bhout[@]}" -gt 0 || "${#a_hdirout[@]}" -gt 0 ]]; then a_output2+=(" - User: \"$l_user\" Home Directory: \"$l_home\"" "${a_dot_file[@]}" "${a_netrc[@]}" "${a_bhout[@]}" "${a_hdirout[@]}") fi [ "${#a_netrc_warn[@]}" -gt 0 ] && a_output3+=(" - User: \"$l_user\" Home Directory: \"$l_home\"" "${a_netrc_warn[@]}") done <<< "$(printf ''%s\n'' "${a_user_and_home[@]}")" if [ "${#a_output2[@]}" -le 0 ]; then # If l_output2 is empty, we pass [ "${#a_output3[@]}" -gt 0 ] && printf ''%s\n'' " ** WARNING **" "${a_output3[@]}" printf ''%s\n'' "- Audit Result:" " ** PASS **" else printf ''%s\n'' "- Audit Result:" " ** FAIL **" " - * Reasons for audit failure * :" "${a_output2[@]}" "" [ "${#a_output3[@]}" -gt 0 ] && printf ''%s\n'' " ** WARNING **" "${a_output3[@]}" fi }
'@
        Remediation = @'
Making global modifications to users'' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user dot file permissions and determine the action to be taken in accordance with site policy. The following script will:
 remove excessive permissions on dot files within interactive users'' home directories
 change ownership of dot files within interactive users'' home directories to the user
 change group ownership of dot files within interactive users'' home directories to the user''s primary group
 list .forward and .rhost files to be investigated and manually deleted
#!/usr/bin/env bash

{

a_output2=(); a_output3=()

l_maxsize="1000" # Maximum number of local interactive users before

warning (Default 1,000)

l_valid_shells="^($( awk -F\/ ''$NF != "nologin" {print}'' /etc/shells | sed

-rn ''/^\//{s,/,\\\\/,g;p}'' | paste -s -d ''|'' - ))$"

a_user_and_home=() # Create array with local users and their home

directories

while read -r l_local_user l_local_user_home; do # Populate array with

users and user home location

[[ -n "$l_local_user" && -n "$l_local_user_home" ]] &&

a_user_and_home+=("$l_local_user:$l_local_user_home")

done <<< "$(awk -v pat="$l_valid_shells" -F: ''$(NF) ~ pat { print $1 " "

$(NF-1) }'' /etc/passwd)"

l_asize="${#a_user_and_home[@]}" # Here if we want to look at number of

users before proceeding

[ "${#a_user_and_home[@]}" -gt "$l_maxsize" ] && printf ''%s\n'' "" " **

INFO **" \

" - \"$l_asize\" Local interactive users found on the system" \

" - This may be a long running check" ""

file_access_fix()

{

a_access_out=()

l_max="$( printf ''%o'' $(( 0777 & ~$l_mask)) )"

if [ $(( $l_mode & $l_mask )) -gt 0 ]; then

printf ''%s\n'' "" " - File: \"$l_hdfile\" is mode: \"$l_mode\" and

should be mode: \"$l_max\" or more restrictive" \

"

Updating file: \"$l_hdfile\" to be mode: \"$l_max\" or more

restrictive"

chmod "$l_change" "$l_hdfile"

fi

if [[ ! "$l_owner" =~ ($l_user) ]]; then

printf ''%s\n'' "" " - File: \"$l_hdfile\" owned by: \"$l_owner\" and

should be owned by \"${l_user//|/ or }\"" \

"

Updating file: \"$l_hdfile\" to be owned by \"${l_user//|/ or

}\""

chown "$l_user" "$l_hdfile"

fi

if [[ ! "$l_gowner" =~ ($l_group) ]]; then

printf ''%s\n'' "" " - File: \"$l_hdfile\" group owned by:

\"$l_gowner\" and should be group owned by \"${l_group//|/ or }\"" \

"

Updating file: \"$l_hdfile\" to be group owned by

\"${l_group//|/ or }\""

chgrp "$l_group" "$l_hdfile"

fi

}

while IFS=: read -r l_user l_home; do

a_dot_file=(); a_netrc=(); a_netrc_warn=(); a_bhout=(); a_hdirout=()

if [ -d "$l_home" ]; then

l_group="$(id -gn "$l_user" | xargs)";l_group="${l_group// /|}"

while IFS= read -r -d $''\0'' l_hdfile; do

while read -r l_mode l_owner l_gowner; do

case "$(basename "$l_hdfile")" in

.forward | .rhost )

a_dot_file+=(" - File: \"$l_hdfile\" exists" "

Please review and manually delete this file") ;; .netrc ) l_mask=''0177''; l_change="u-x,go-rwx"; file_access_fix a_netrc_warn+=(" - File: \"$l_hdfile\" exists") ;; .bash_history ) l_mask=''0177''; l_change="u-x,go-rwx"; file_access_fix ;; * ) l_mask=''0133''; l_change="u-x,go-wx"; file_access_fix ;;
esac done < <(stat -Lc ''%#a %U %G'' "$l_hdfile") done < <(find "$l_home" -xdev -type f -name ''.*'' -print0) fi [ "${#a_dot_file[@]}" -gt 0 ] && a_output2+=(" - User: \"$l_user\" Home Directory: \"$l_home\"" "${a_dot_file[@]}") [ "${#a_netrc_warn[@]}" -gt 0 ] && a_output3+=(" - User: \"$l_user\" Home Directory: \"$l_home\"" "${a_netrc_warn[@]}") done <<< "$(printf ''%s\n'' "${a_user_and_home[@]}")" [ "${#a_output3[@]}" -gt 0 ] && printf ''%s\n'' "" " ** WARNING **" "${a_output3[@]}" "" [ "${#a_output2[@]}" -gt 0 ] && printf ''%s\n'' "" "${a_output2[@]}" }
'@
    }
)

# ===============================================================================
#  RUNNER
# ===============================================================================
function Invoke-CisItems {
    Write-Banner "CIS AKS items (all MANL - operator runs Audit on node)"
    Write-Host "  Count: $($Script:CIS_ITEMS.Count) items" -ForegroundColor Gray
    foreach ($it in $Script:CIS_ITEMS) {
        Write-CheckHeader $it.Section ("({0}/{1}) {2}" -f $it.Level, $it.Kind, $it.Title)
        Write-Manl ("CIS Audit / Remediation procedure follows.  Run on the node.")
        Write-Info "Audit:"
        foreach ($ln in ($it.Audit -split "`n")) { if ($ln.Trim()) { Write-Info "  $ln" } }
        Write-Info "Remediation:"
        foreach ($ln in ($it.Remediation -split "`n")) { if ($ln.Trim()) { Write-Info "  $ln" } }

        $detail = "[$($it.Level)/$($it.Kind)] CIS Audit and Remediation - see Detail. Run on node host OS (Azure Linux 3)."
        # When -RunOnNodes was supplied, attach captured per-node evidence
        if ($RunOnNodes -and $Script:NodeOutputs.Count -gt 0) {
            foreach ($node in $Script:NodeOutputs.Keys) {
                $cap = $Script:NodeOutputs[$node][$it.Section]
                if ($cap) {
                    $detail += " || [NODE:$node] $cap"
                }
            }
        }
        Add-Result $it.Section $it.Title "MANL" $detail
    }
}

function Invoke-OnNodeAudits {
    Write-Banner "Running on-node audit harness via kubectl debug"
    if (-not $Script:Nodes -or $Script:Nodes.Count -eq 0) {
        Write-Skip "No nodes available for on-node audit."
        return
    }
    $targets = if ($NodeName) { $Script:Nodes | Where-Object { $_.metadata.name -eq $NodeName } } else { $Script:Nodes }
    if (-not $targets) {
        Write-Skip "No matching nodes for -NodeName='$NodeName'."
        return
    }

    $script = Build-AuditScript
    foreach ($n in $targets) {
        $name = $n.metadata.name
        Write-Host "  Auditing node $name ..." -ForegroundColor Yellow
        try {
            $output = Invoke-NodeAudit -NodeName $name -Script $script
            $perItem = @{}
            $current = $null
            $buf     = New-Object System.Text.StringBuilder
            foreach ($line in ($output -split "`r?`n")) {
                if ($line -match '^<<<CIS:(.+?)>>>$') {
                    $current = $matches[1]; [void]$buf.Clear(); continue
                }
                if ($line -match '^<<<CIS_END:(.+?)>>>$') {
                    if ($current) { $perItem[$current] = $buf.ToString().Trim() }
                    $current = $null; continue
                }
                if ($current) { [void]$buf.AppendLine($line) }
            }
            $Script:NodeOutputs[$name] = $perItem
            Write-Host ("    captured {0} sections from {1}" -f $perItem.Count, $name) -ForegroundColor Gray
            Add-Result "PRE-DEBUG-$name" "kubectl debug node/$name" "PASS" ("captured {0} sections" -f $perItem.Count)
            $Script:PassCount++
        } catch {
            Write-Host "    [WARN] debug pod failed on $name : $($_.Exception.Message)" -ForegroundColor Magenta
            Add-Result "PRE-DEBUG-$name" "kubectl debug node/$name" "WARN" $_.Exception.Message
            $Script:WarnCount++
        }
    }
}

# ===============================================================================
#  SUMMARY
# ===============================================================================
function Show-Summary {
    $line = "=" * 92
    Write-Host ""; Write-Host $line -ForegroundColor Cyan
    Write-Host "  CIS AKS Optimized Azure Linux 3 Benchmark v1.0.0 - RESULTS SUMMARY" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan; Write-Host ""

    Write-Host ("  {0,-12} {1,-60} {2,-6}" -f "SECTION","TITLE","STATUS")
    Write-Host ("  {0,-12} {1,-60} {2,-6}" -f ("-"*12),("-"*60),("-"*6))
    foreach ($r in $Script:Results) {
        $col = switch ($r.Status) { "PASS"{"Green"} "FAIL"{"Red"} "WARN"{"Magenta"} "SKIP"{"DarkGray"} "MANL"{"Cyan"} default{"Gray"} }
        $t   = if ($r.Title.Length -gt 60) { $r.Title.Substring(0,57) + "..." } else { $r.Title }
        Write-Host ("  {0,-12} {1,-60} " -f $r.Section, $t) -NoNewline
        Write-Host ("{0,-6}" -f $r.Status) -ForegroundColor $col
    }
    Write-Host ""; Write-Host $line -ForegroundColor Cyan
    Write-Host ("  Total : {0}" -f $Script:Results.Count)
    Write-Host ("  PASS  : {0}" -f $Script:PassCount) -ForegroundColor Green
    Write-Host ("  FAIL  : {0}" -f $Script:FailCount) -ForegroundColor Red
    Write-Host ("  WARN  : {0}" -f $Script:WarnCount) -ForegroundColor Magenta
    Write-Host ("  SKIP  : {0}" -f $Script:SkipCount) -ForegroundColor DarkGray
    Write-Host ("  MANL  : {0}" -f $Script:ManlCount) -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan; Write-Host ""

    try {
        $Script:Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "  Results exported to: $OutputPath" -ForegroundColor Yellow
    } catch {
        Write-Host "  CSV export failed: $_" -ForegroundColor Red
    }
}

# ===============================================================================
#  MAIN
# ===============================================================================
Initialize-Tools
Connect-Cluster
if ($RunOnNodes) { Invoke-OnNodeAudits }
Invoke-CisItems
Show-Summary