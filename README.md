# CIS Benchmark Automation

Automated scripts to audit your **Microsoft Azure**, **Microsoft 365**, and **PostgreSQL** environments against the **CIS (Center for Internet Security) Benchmarks**. The Microsoft benchmarks are PowerShell scripts, each with a full audit script and a permissions-setup helper. The PostgreSQL benchmark is a single self-contained SQL script run from inside a `psql` session.

## Benchmarks

| Benchmark | Version | Automated Checks | Manual Checks | Script | Permissions Helper |
|-----------|---------|------------------:|--------------:|--------|--------------------|
| CIS Microsoft Azure Foundations | v5.0.0 | 103 | 62 | `CIS_Azure_Benchmark_Full.ps1` | `CIS_Azure_Permissions.ps1` |
| CIS Microsoft 365 Foundations | v6.0.1 | 129 | 11 | `CIS_M365_Benchmark_Full.ps1` | `CIS_M365_Permissions.ps1` |
| CIS Microsoft Dynamics 365 / Power Platform Foundations | v1.0.0 | 16¹ | 16 | `CIS_Power_Platform_Benchmark_Full.ps1` | `CIS_Power_Platform_Permissions.ps1` |
| CIS AKS Optimized Azure Linux 3 | v1.0.0 | 136² | 5 | `CIS_AKS_Benchmark_Full.ps1` | _(none — operator's existing kubeconfig)_ |
| CIS PostgreSQL 18 | v1.0.0 | 37³ | 35 | `CIS_PostgreSQL18_Benchmark.sql` | _(none — operator's existing psql session)_ |

> **Manual (MANL) checks** cover CIS items that cannot be fully verified via
> API. The scripts still surface them in a dedicated `SECTION MANL` block,
> print the portal path, audit steps, and remediation, and — where possible —
> pull diagnostic context from Graph / Exchange / Teams to help the operator
> answer the item. MANL results are recorded in the CSV with `Status = MANL`.
>
> ¹ **Power Platform note:** all 16 items are classified Manual by CIS, but
> `CIS_Power_Platform_Benchmark_Full.ps1` derives an automated verdict from the
> BAP / Graph / Dataverse APIs wherever possible and promotes that verdict to
> the row's `Status` (PASS / FAIL / SKIP). Only items that genuinely require
> human review (no API signal) keep `Status = MANL`. The raw automated verdict
> is always preserved in the `Detail` column as an `[AUTO: ...]` prefix.
>
> ² **AKS Azure Linux 3 note:** every item in the CIS AKS Optimized Azure
> Linux 3 Benchmark is a Linux OS-level audit (kernel modules, partitions,
> sysctl, SSH, PAM, auditd, file permissions). None can be evaluated
> through Azure ARM, Microsoft Graph, or kubectl against managed-cluster
> endpoints, so the script collects evidence by running a privileged
> `kubectl debug node` pod (chrooted to `/host`) on each Ready node **by
> default** (pass `-SkipOnNodeAudit` to disable). All **136 CIS items
> classified Automated** in the benchmark ship with on-node evaluators
> that derive a real PASS / FAIL / SKIP verdict from the captured host
> output. The remaining **5 CIS Manual** items stay `Status = MANL`,
> and still print the verbatim Audit and Remediation procedure in the
> `Detail` column for human review together with the per-node captured
> output.
>
> ³ **PostgreSQL 18 note:** unlike the four Microsoft benchmarks, this is a
> pure **SQL** script (`CIS_PostgreSQL18_Benchmark.sql`) executed from inside
> an already-connected `psql` session — there is no PowerShell, no login
> logic, and no permissions helper. Of the **72** CIS recommendations, **37**
> can be evaluated directly from SQL (server parameters, roles, `pg_hba`
> rules, extensions, TLS, replication, WAL archiving) and produce a real
> PASS / FAIL / WARN / SKIP verdict. The other **35** are reported as `MANL`:
> **21** are operating-system items that `psql` cannot reach (file
> ownership/permissions, `umask`, systemd, shell profiles, `sudoers`,
> pgBackRest, …) and **14** are CIS *Manual* items that have no single fixed
> correct value and require human review against site policy (e.g. the
> Postmaster / SIGHUP / Superuser / User runtime-parameter inventories in
> 6.3–6.6, excessive-privilege review in 4.3, RLS design in 4.7). Every MANL
> row names the matching CIS section so the operator can look up the manual
> Audit / Remediation procedure in the benchmark PDF. (Item 7.2 is `PASS`
> when replication-command logging is on and `MANL` otherwise, so a typical
> run shows ~36 MANL rows.)

---

## 1 — CIS Azure Foundations Benchmark v5.0.0

### Sections Covered

| Section | Area | Checks |
|---------|------|-------:|
| 2 | Databricks | 7 automated + 5 manual |
| 3 | Virtual Machines | 1 manual |
| 5 | Identity / Entra ID | 9 automated + 34 manual |
| 6 | Logging & Monitoring | 22 automated + 9 manual |
| 7 | Networking | 17 automated + 3 manual |
| 8 | Security (Defender, Key Vault, Bastion, DDoS) | 30 automated + 8 manual |
| 9 | Storage | 18 automated + 2 manual |
| MANL | Manual checks (CIS items marked _Manual_) | 62 total, grouped by origin section |

> **Multi-resource coverage:** checks that target resource types which can exist more than once
> (Databricks workspaces, NSGs, VNets, Bastion hosts, VPN Gateways, App Services, Public IPs, Storage
> accounts, etc.) iterate **every** instance in the subscription and report per-resource results.
> For example, Bastion coverage is validated per VNet that hosts VMs (same VNet or peered), and NSG
> and VNet flow logs are verified for every NSG/VNet — not just the first one found.

### Prerequisites

- **Azure CLI (`az`)** — required by `CIS_Azure_Permissions.ps1` to create the App Registration,
  Service Principal, RBAC role assignments, and Graph permission grants.
  Install from <https://learn.microsoft.com/cli/azure/install-azure-cli> (or `winget install Microsoft.AzureCLI`),
  then sign in with `az login --tenant <tenant-guid>`.

```powershell
Install-Module Az               -Scope CurrentUser -Force
Install-Module Microsoft.Graph   -Scope CurrentUser -Force
```

> Or let `CIS_Azure_Permissions.ps1` install them for you. It installs the required sub-modules
> (`Az.Accounts`, `Az.Resources`, `Az.Security`, `Az.Network`, `Az.Monitor`, `Az.KeyVault`,
> `Az.Storage`, `Az.Websites`, `Az.ApplicationInsights`, `Az.Compute`, plus
> `Microsoft.Graph.Identity.SignIns` and `Microsoft.Graph.Identity.DirectoryManagement`).

### Permissions Setup

Run the helper first to create an App Registration with the required RBAC roles and Graph permissions:

```powershell
.\CIS_Azure_Permissions.ps1 -TenantId "<tenant-guid>" -SubscriptionId "<sub-guid>"
```

The script assigns:
- **Azure RBAC**: Reader, Security Reader, Key Vault Reader (subscription scope)
- **Microsoft Graph**: Directory.Read.All, Policy.Read.All, User.Read.All, RoleManagement.Read.All, Organization.Read.All

### Running the Audit

**Interactive login:**

```powershell
.\CIS_Azure_Benchmark_Full.ps1
```

**Service-principal (non-interactive):**

```powershell
.\CIS_Azure_Benchmark_Full.ps1 `
    -TenantId       "<tenant-guid>" `
    -SubscriptionId "<sub-guid>" `
    -ClientId       "<app-id>" `
    -ClientSecret   "<secret>"
```

> At the end of `CIS_Azure_Permissions.ps1` the generated client secret is printed and the ready-to-run
> command line is displayed. You are also prompted **"Run benchmark now? [Y/N]"** — answering `Y` will
> launch `CIS_Azure_Benchmark_Full.ps1` immediately with the newly created credentials.

Results are saved to a timestamped CSV file: `CIS_Azure_Results_<date>.csv`

---

## 2 — CIS Microsoft 365 Foundations Benchmark v6.0.1

### Sections Covered

| Section | Area | Key Topics |
|---------|------|------------|
| 1 | Microsoft 365 Admin Center | Licensing, groups, calendar sharing, customer lockbox, third-party storage |
| 2 | Microsoft 365 Defender | Email & collaboration, DMARC, anti-phishing |
| 3 | Compliance | DLP, information protection, sensitivity labels |
| 4 | Intune / Device Management | Device enrollment, compliance policies |
| 5 | Microsoft Entra ID | Identity, MFA, conditional access, PIM, access reviews |
| 6 | Exchange Online | Transport rules, mailbox auditing |
| 7 | SharePoint Online & OneDrive | Sharing policies, access controls |
| 8 | Microsoft Teams | Meeting policies, external access, guest access |
| 9 | Power BI / Fabric | Tenant settings, admin configuration |
| MANL | Manual checks (CIS items marked _Manual_) | Break-glass accounts, Sway sharing, MDCA configuration, Entra portal restrictions, SSPR, SharePoint security-group sharing, Teams app permission policies, password hash sync |

### Prerequisites

- **Azure CLI (`az`)** — required by `CIS_M365_Benchmark_Full.ps1` to create the App Registration,
  Service Principal, RBAC role assignments, and Graph permission grants.
  Install from <https://learn.microsoft.com/cli/azure/install-azure-cli> (or `winget install Microsoft.AzureCLI`),
  then sign in with `az login --tenant <tenant-guid>`.
- **PowerShell modules:**

```powershell
Install-Module Microsoft.Graph                          -Scope CurrentUser -Force
Install-Module ExchangeOnlineManagement                 -Scope CurrentUser -Force
Install-Module MicrosoftTeams                           -Scope CurrentUser -Force
Install-Module Microsoft.Online.SharePoint.PowerShell   -Scope CurrentUser -Force
```

> **Tenants without an Azure subscription** (Microsoft 365 / Office 365-only): sign in with
> `az login --tenant <tenant-guid> --allow-no-subscriptions`. The M365 permissions helper only
> needs Microsoft Graph access and does not require an Azure subscription.

### Permissions Setup

Run the helper to create an App Registration with all required Graph, Exchange, and Power BI permissions:

```powershell
.\CIS_M365_Permissions.ps1 -TenantId "<tenant-guid>"
```

Options:
- `-AppName "CIS-M365-Benchmark-Audit"` — custom app registration name
- `-AppId "<existing-app-guid>"` — reuse an existing app registration
- `-NoSecret` — skip client-secret creation on this run (by default every run mints
  a fresh secret so the printed benchmark command is ready to copy-paste)
- `-IncludeExchange` — add Exchange.ManageAsApp permission
- `-SkipDirectoryRoles` — skip Entra directory role assignments
- `-AutoLogin` — auto-login if Azure CLI is signed into a different tenant

The script configures:
- **Microsoft Graph**: Directory.Read.All, Policy.Read.All, User.Read.All, Group.Read.All, RoleManagement.Read.All, and many more
- **Entra Directory Roles**: Fabric Administrator, Intune Administrator
- **Exchange Online** (optional): Exchange.ManageAsApp + View-Only Organization Management role

### Running the Audit

**Service-principal (non-interactive):**

```powershell
.\CIS_M365_Benchmark_Full.ps1 `
    -TenantId           "<tenant-guid>" `
    -AppId              "<app-id>" `
    -AppSecret          "<secret>" `
    -SharePointAdminUrl "https://<tenant>-admin.sharepoint.com" `
    -TenantDomain       "<tenant>.onmicrosoft.com"
```

**Graph-only mode** (skip EXO/SPO/Teams interactive prompts):

```powershell
.\CIS_M365_Benchmark_Full.ps1 `
    -TenantId "<tenant-guid>" `
    -AppId    "<app-id>" `
    -AppSecret "<secret>" `
    -GraphOnlyMode
```

Results are saved to a timestamped CSV file: `CIS_M365_Results_<date>.csv`

---

## 3 — CIS Microsoft Dynamics 365 / Power Platform Foundations Benchmark v1.0.0

### Sections Covered

| Section | Area | Checks |
|---------|------|-------:|
| 1 | Accounts and Authentication | 4 manual |
| 2 | Permissions | 5 manual |
| 3 | Data Management | 4 manual |
| 4 | Logging and Auditing | 3 manual |

> All 16 recommendations in the CIS Power Platform benchmark are classified
> **Manual** by CIS. The script runs each as a `Check-MANL-<section>`
> function that prints the portal path, audit steps, remediation, and
> references, and — where APIs allow — pulls live diagnostic context from
> Microsoft Graph (admin accounts, Conditional Access policies for MFA
> and location restrictions), the Power Platform BAP API
> (environments, tenant settings, DLP policies, tenant isolation), and
> the Dataverse Web API (per-environment session timeouts, blocked
> attachments, public queues, security roles, audit flags).
>
> **Note on Dataverse:** items 1.2, 2.3, 3.2, 3.3, 4.1, and 4.2 audit
> settings that only exist *inside* a Dataverse environment (Dynamics 365
> apps, model-driven apps). Power Apps canvas-only or Power Automate-only
> environments don't have those settings at all — the benchmark reports
> them as Not Applicable for those envs. There is no non-Dataverse
> alternative for these specific items because they are Dynamics 365 /
> Dataverse features by definition. Dataverse-driven checks require the
> service principal to be added as an Application User with the System
> Administrator role in each environment. Before that you must also
> self-elevate your own account to Dataverse System Administrator in the
> environment (Power Platform Admin Center → **Manage** → **Environments**
> → pick env → **Membership** → **Add me**). The permissions helper prints
> step-by-step instructions for both steps.
>
> **Status mapping:** unlike the Azure and M365 benchmarks (where every
> Manual CIS item is reported as `Status = MANL`), the Power Platform script
> promotes the automated verdict to the CSV `Status`:
> `PASS → PASS`, `FAIL → FAIL`, `WARN → WARN`, `N/A → SKIP`,
> `UNKNOWN → MANL`. Items appear as `MANL` only when the script could not
> derive a definitive verdict from the APIs and human review is genuinely
> required. The raw verdict is always written to the `Detail` column with an
> `[AUTO: ...]` prefix so consumers can still aggregate by automated
> assessment.

### Prerequisites

- **Azure CLI (`az`)** — required by `CIS_Power_Platform_Permissions.ps1`
  to create the App Registration, Service Principal, secret, Graph permission
  grants, and the **Power Platform Administrator** directory role assignment.
- **PowerShell modules:**

```powershell
Install-Module Microsoft.Graph                                  -Scope CurrentUser -Force
Install-Module Microsoft.PowerApps.Administration.PowerShell    -Scope CurrentUser -Force
```

> The Power Platform BAP API only accepts service-principal tokens AFTER
> the SP has been registered as a Power Platform Management App. This is
> a one-time interactive step that an admin must perform:
>
> ```powershell
> Add-PowerAppsAccount
> New-PowerAppManagementApp -ApplicationId '<app-id>'
> ```
>
> `CIS_Power_Platform_Permissions.ps1 -RegisterAsPowerAppMgmtApp` will do
> this for you (it prompts for the interactive admin sign-in). If you skip
> this step, the benchmark still runs, but the BAP-driven enrichment for
> sections 1.1, 2.1, 2.5, 3.1, 3.4, 4.1, 4.2 is skipped and those MANL
> checks fall back to CIS guidance only.

### Permissions Setup

```powershell
.\CIS_Power_Platform_Permissions.ps1 -TenantId "<tenant-guid>" -RegisterAsPowerAppMgmtApp
```

Options:
- `-AppName "CIS-PowerPlatform-Benchmark-Audit"` — custom app registration name
- `-AppId "<existing-app-guid>"` — reuse an existing app registration
- `-NoSecret` — skip client-secret creation (by default every run mints a fresh secret)
- `-SkipDirectoryRoles` — skip the Power Platform Administrator role assignment
- `-RegisterAsPowerAppMgmtApp` — also call `New-PowerAppManagementApp` (interactive)
- `-AutoLogin` — auto-login if Azure CLI is signed into a different tenant

The script configures:
- **Microsoft Graph (Application)**: Directory.Read.All, User.Read.All, Group.Read.All, RoleManagement.Read.All, Organization.Read.All, Policy.Read.All, AuditLog.Read.All
- **Entra Directory Role**: Power Platform Administrator (falls back to Dynamics 365 Administrator if unavailable)
- **Power Platform**: Management App registration (with `-RegisterAsPowerAppMgmtApp`)

### Running the Audit

**Service-principal (non-interactive):**

```powershell
.\CIS_Power_Platform_Benchmark_Full.ps1 `
    -TenantId     "<tenant-guid>" `
    -AppId        "<app-id>" `
    -AppSecret    "<secret>" `
    -TenantDomain "<tenant>.onmicrosoft.com"
```

**Graph-only mode** (skip Power Platform BAP API enrichment):

```powershell
.\CIS_Power_Platform_Benchmark_Full.ps1 `
    -TenantId  "<tenant-guid>" `
    -AppId     "<app-id>" `
    -AppSecret "<secret>" `
    -GraphOnlyMode
```

Results are saved to a timestamped CSV file: `CIS_PowerPlatform_Results_<date>.csv`

---

## 4 — CIS AKS Optimized Azure Linux 3 Benchmark v1.0.0

### Sections Covered

| Section | Area | Checks |
|---------|------|-------:|
| 1 | Initial Setup (filesystem, package management, process hardening, banners) | 25 |
| 2 | Services (time sync, special-purpose services, service clients) | 27 |
| 3 | Network (kernel parameters) | 10 |
| 4 | Host Based Firewall (iptables / nftables / firewalld) | 3 |
| 5 | Access, Authentication and Authorization (cron, SSH, sudo, PAM, accounts) | 44 |
| 6 | Logging and Auditing (journald, rsyslog, auditd) | 11 |
| 7 | System Maintenance (file permissions and user / group integrity) | 21 |

> The benchmark targets the **node host OS** of AKS node pools running on
> Azure Linux 3 (`osSKU = AzureLinux`). It does not audit the Kubernetes
> control plane or workloads — it audits the nodes the way a host-OS CIS
> Benchmark would, just delivered through the AKS managed surface.
> Every recommendation is a Linux shell-based audit; the script collects
> evidence from each node via `kubectl debug node` (privileged debug pod
> chrooted to `/host`).

### Prerequisites

> **You must already be logged into the cluster, and `kubectl` must be
> working against it before you run the benchmark.** The script does not
> perform `az login` or `az aks get-credentials` for you — it assumes
> you have a working kubeconfig (the current context must point at the
> cluster you want to audit) and that `kubectl get nodes` succeeds.
>
> Quick check on Linux / WSL or Windows:
>
> ```bash
> az account set --subscription "<sub-guid>"
> az aks get-credentials --resource-group "<aks-rg>" --name "<aks-cluster-name>" --overwrite-existing
> kubectl get nodes      # must return your node list with STATUS=Ready
> ```

- **Azure CLI (`az`)** — used to read cluster metadata (`az aks show`,
  `az aks list`).
- **`kubectl`** — used to list nodes and to launch the privileged debug
  pods that perform the on-node audit. Kubernetes ≥ 1.23 is required for
  `kubectl debug node`.
- **Cluster permissions** — your current `kubectl` context needs to be
  able to (a) `get` and `list` `nodes` and (b) create privileged pods
  via `kubectl debug node` (i.e. cluster-admin equivalent). On AKS this
  is typically granted via the **Azure Kubernetes Service RBAC Cluster
  Admin** Azure role, but any kubeconfig with equivalent rights works.

> **No SSH is used.** The script audits each node by launching a
> privileged debug pod via `kubectl debug node/<name>` (the pod runs on
> that node with `hostPID` / `hostNetwork` and chroots to `/host` to
> read the host filesystem). The pod is ephemeral and is removed by
> Kubernetes when the audit completes.

> No Microsoft Graph permissions are required — the AKS benchmark does not
> query Entra ID.

### Running the Audit

Once `kubectl get nodes` works against your cluster:

```powershell
.\CIS_AKS_Benchmark_Full.ps1 `
    -SubscriptionId "<sub-guid>" `
    -ResourceGroup  "<aks-rg>" `
    -ClusterName    "<aks-cluster-name>"
```

By **default** the script launches a privileged `kubectl debug node` pod
on each Ready node (chrooted to `/host`), runs the CIS audit commands,
and aggregates per-node output into a real PASS / FAIL / SKIP verdict
for the ~75 items that ship with on-node evaluators. The remaining ~66
items stay `MANL` (CIS audit logic too item-specific to encode
generically) — those rows still print the verbatim CIS Audit and
Remediation procedure plus the captured per-node output for human
review.

Pass `-SkipOnNodeAudit` to disable the on-node harness (every item
becomes `MANL`, no node evidence collected). The legacy `-RunOnNodes`
switch is accepted as a no-op for backward compatibility.

Results are saved to a timestamped CSV file: `CIS_AKS_Results_<date>.csv`

---

## 5 — CIS PostgreSQL 18 Benchmark v1.0.0

> **Source:** CIS PostgreSQL 18 Benchmark, **v1.0.0 — 03-27-2026**.

Unlike the four Microsoft benchmarks above, this one is a single, self-contained
**SQL** script — `CIS_PostgreSQL18_Benchmark.sql` — that you run from **inside an
already-connected `psql` session**. There is no PowerShell, no `az`/Graph
dependency, no service principal, and no permissions helper. The script connects
to nothing on its own: it audits the database you are already attached to, using
the privileges of the role you are already logged in as.

### Sections Covered

| Section | Area | Checks |
|---------|------|-------:|
| 1 | Installation and Patches | 7 manual (OS) |
| 2 | Directory and File Permissions | 4 manual (OS) |
| 3 | Logging, Monitoring and Auditing | 24 SQL + 2 manual |
| 4 | User Access and Authorization | 3 SQL + 7 manual |
| 5 | Connection and Login | 4 SQL + 2 manual |
| 6 | PostgreSQL Settings | 4 SQL + 7 manual |
| 7 | Replication | 2 SQL + 3 manual |
| 8 | Special Configuration Considerations | 0 SQL + 3 manual |
| MANL | Manual checks (OS-level + CIS *Manual* items) | 35 total, each pointing to its CIS section |

> **What "Automated" means here:** 37 of the 72 CIS recommendations can be
> evaluated directly from SQL against the live server and yield a real
> PASS / FAIL / WARN / SKIP. The other 35 are surfaced as `MANL` — 21 are
> operating-system checks `psql` physically cannot perform (file modes,
> `umask`, systemd, shell profiles, `sudoers`, FIPS, pgBackRest, on-disk
> directory layout) and 14 are CIS *Manual* items with no single fixed
> correct value (the 6.3–6.6 runtime-parameter inventories, administrative
> privilege review, RLS design, etc.). One item (7.2, replication-command
> logging) is reported as `PASS` when enabled and `MANL` otherwise, so a
> typical run shows around 36 MANL rows. Each MANL row names its CIS section
> so you can read the manual Audit / Remediation steps in the benchmark PDF.

### Prerequisites

> **You must already be running `psql` and connected to the target database
> before you run the script.** The script does not log in or connect — it uses
> the current session.

- **`psql`** — the standard PostgreSQL interactive terminal. Any reasonably
  recent version works; the benchmark targets a PostgreSQL **18** server but
  the script also runs cleanly against earlier servers (items that reference
  parameters not present on the server degrade to `SKIP` rather than failing).
- **A database connection** — open it however you normally do, e.g.:

```bash
psql -h <host> -U <user> -d <db>
# or, for a local socket:
psql -d <db>
```

- **Privileges** — **no superuser is required, and no write access to schema
  `public` is needed.** The script creates only a `TEMP` table and one
  `pg_temp` helper function, both of which every role can create and which are
  dropped automatically at session end. A few catalogs
  (`pg_authid.rolpassword`, `pg_hba_file_rules`) and some restricted GUCs are
  only readable by a superuser or a member of `pg_monitor` /
  `pg_read_all_settings`; items that cannot be read with the current
  privileges report `SKIP` (with an explanation) instead of a false `FAIL`.

> **Want the privileged items evaluated as a non-superuser?** Grant your
> audit role membership in `pg_monitor` (covers `pg_hba_file_rules` and the
> restricted settings). The `4.10` password check additionally needs a
> superuser to read `pg_authid.rolpassword`.

### Running the Audit

From your open `psql` prompt, simply execute the script with `\i`:

```text
<db>=# \i CIS_PostgreSQL18_Benchmark.sql
```

The script fills a `TEMP` table `cis_results(section, title, status, detail)`
while it runs and then prints three blocks: a compact **overview** table
(Section / Title / Status), a **details** block, and a **summary** with the
count per status. Results stay in the `cis_results` temp table for the rest of
the session, so you can query them directly, for example:

```sql
SELECT section, title, detail FROM cis_results WHERE status = 'FAIL';
```

> **Per-database scope:** a few items (4.5 / 4.6 / 4.7) inspect objects that
> live inside a single database, so `psql` only sees the database you are
> connected to. For a complete audit, run the script once in each database.

> **No file is written.** Unlike the PowerShell benchmarks (which emit a CSV),
> the PostgreSQL script keeps everything in-session in the `cis_results` temp
> table. To capture the run to a file, use psql's own tooling, e.g. launch with
> `psql -o cis_report.txt` or wrap the call in `\o cis_report.txt` … `\o`.

### Status meanings (PostgreSQL benchmark)

| Status | Meaning |
|--------|---------|
| `PASS` | The SQL check found the server compliant. |
| `FAIL` | The SQL check found the server non-compliant. |
| `WARN` | Compliant-ish but needs human confirmation (e.g. a value acceptable only under a specific policy). |
| `SKIP` | The check could not run with the current privileges, or the parameter does not exist on this server. |
| `MANL` | OS-level item, or a CIS *Manual* item with no fixed value. Not evaluated — the row states what to check and points to the matching CIS section. |

---

## Output Format

> This section describes the four **Microsoft PowerShell** benchmarks. The
> PostgreSQL 18 SQL benchmark has its own output model (in-session `cis_results`
> temp table, no CSV) and status table — see
> [Section 5](#5--cis-postgresql-18-benchmark-v100).

The four PowerShell benchmark scripts produce:
- **Console output** with color-coded results: `[PASS]`, `[FAIL]`, `[WARN]`, `[SKIP]`, `[MANL]`
- **CSV report** with columns: Section, Title, Status, Detail

Status meanings:

| Status | Meaning |
|--------|---------|
| `PASS` | The automated check found the tenant to be compliant. |
| `FAIL` | The automated check found the tenant to be non-compliant. |
| `WARN` | The check could not run (missing permission / service not connected). Needs investigation. |
| `SKIP` | The check does not apply to this tenant (e.g. `.onmicrosoft.com`-only domains for DMARC). |
| `MANL` | CIS item documented as **Manual**. Requires an administrator to verify in the portal; the script prints the portal path, audit steps, and remediation. |

### Sample console output (M365 benchmark)

```text
----------------------------------------------------------------------------------
 SECTION 1 - Microsoft 365 Admin Center
----------------------------------------------------------------------------------

 [1.1.1 (L1)] Ensure Administrative accounts are cloud-only (Automated)
 [PASS] No hybrid-synced users found in privileged roles.

 [1.1.3 (L1)] Ensure between two and four global admins are designated (Automated)
 Global Admins found: 6
 -> MOD Administrator | admin@M365x55944128.onmicrosoft.com
 -> Allan Deyoung | AllanD@M365x55944128.OnMicrosoft.com
 -> Nestor Wilke | NestorW@M365x55944128.OnMicrosoft.com
 -> Isaiah Langer | IsaiahL@M365x55944128.OnMicrosoft.com
 -> Megan Bowen | MeganB@M365x55944128.OnMicrosoft.com
 -> Lidia Holloway | LidiaH@M365x55944128.OnMicrosoft.com
 [FAIL] 6 Global Admins - maximum is 4. Reduce privileged access.

 [1.1.4 (L1)] Ensure admin accounts use licenses with reduced application footprint (Automated)
 Checking privileged users for assigned service plans (Teams, Exchange, SharePoint)...
 -> MOD Administrator: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 -> Allan Deyoung: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 -> Nestor Wilke: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 -> Isaiah Langer: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 -> Megan Bowen: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 -> Lidia Holloway: Microsoft Teams, SharePoint Online (Plan 1) [E3], SharePoint Online (Plan 1), Exchange Online (Plan 1)
 [FAIL] 6 admin(s) have productivity services assigned.
 Recommendation: Create dedicated cloud-only admin accounts without productivity licenses.

 [1.2.1 (L2)] Ensure only organizationally managed/approved public groups exist (Automated)
 Retrieving all Unified (M365) groups (client-side visibility filter)...
 Total M365 groups: 14, Public: 6
 [WARN] 6 public M365 group(s) - verify each is organizationally approved:
 -> All Company | allcompany@M365x55944128.onmicrosoft.com
 -> Sales and Marketing | SalesAndMarketing@M365x55944128.onmicrosoft.com
 -> Mark 8 Project Team | Mark8ProjectTeam@M365x55944128.onmicrosoft.com
 -> New Employee Onboarding | newemployeeonboarding@M365x55944128.onmicrosoft.com
 -> Contoso marketing | Contosomarketing@M365x55944128.onmicrosoft.com
 -> Remote living | Remoteliving@M365x55944128.onmicrosoft.com

 [1.2.2 (L1)] Ensure sign-in to shared mailboxes is blocked (Automated)
 [PASS] All 0 shared mailbox(es) have sign-in blocked.

 [1.3.1 (L1)] Ensure the Password expiration policy is set to never expire (Automated)
 [PASS] All verified domains have 'Never expire' password policy (value = 2147483647).

 [1.3.2 (L2)] Ensure 'Idle session timeout' is set to 3 hours or less (Automated)
 [FAIL] No Activity-Based Timeout policy found - idle session timeout is not configured.
 Remediation: Entra ID > Properties > Manage security defaults > Session timeout

 [1.3.3 (L2)] Ensure external sharing of calendars is not available (Automated)
 [FAIL] External calendar sharing policy allows anonymous access:
 -> Default Sharing Policy: Anonymous:CalendarSharingFreeBusyReviewer *:CalendarSharingFreeBusySimple

 [1.3.4 (L1)] Ensure 'User owned apps and services' is restricted (Automated)
 AllowedToCreateApps : True
 [FAIL] Users CAN create apps (AllowedToCreateApps = True). Restrict this setting.
 Remediation: Entra ID > User settings > App registrations > No

 [1.3.5 (L1)] Ensure internal phishing protection for Forms is enabled (Automated)
 isInOrgFormsPhishingScanEnabled: True
 [PASS] Internal phishing protection for Forms is ENABLED.

 [1.3.6 (L2)] Ensure the customer lockbox feature is enabled (Automated)
 CustomerLockBoxEnabled: False
 [FAIL] Customer Lockbox is NOT enabled.
 Remediation: M365 Admin Center > Settings > Org Settings > Security & Privacy > Customer Lockbox > On

 [1.3.7 (L2)] Ensure third-party storage services are restricted in Microsoft 365 (Automated)
 [PASS] Third-party storage service principal not found in tenant (not added = restricted).

 [1.3.9 (L1)] Ensure shared Bookings pages are restricted to select users (Automated)
 BookingsMailboxCreationEnabled: True
 BookingsEnabled (org)         : True
 [FAIL] Any user can create Bookings pages (BookingsMailboxCreationEnabled = True).
 Remediation: Exchange Admin > Settings > Bookings > restrict to specific users
```

### Sample console output (PostgreSQL 18 benchmark)

```text
===============================================================================
  CIS PostgreSQL 18 Benchmark v1.0.0 - audit via psql
===============================================================================
Server: 18.0 (180000) | user: app_auditor | database: appdb | superuser: off

------------------------------------------------------------------------------
  RESULTS (overview)
------------------------------------------------------------------------------
+---------+------------------------------------------------------------+--------+
| Section |                           Title                            | Status |
+---------+------------------------------------------------------------+--------+
| 1.1     | Ensure packages are obtained from authorized repositories  | MANL   |
| 3.1.20  | Ensure log_connections is enabled                          | FAIL   |
| 3.1.24  | Ensure log_line_prefix is set correctly                    | FAIL   |
| 4.8     | Ensure the set_user extension is installed                 | FAIL   |
| 6.6     | Ensure 'User' Runtime Parameters are Configured            | MANL   |
| 6.8     | Ensure TLS is enabled and configured correctly             | PASS   |
| 6.9     | Ensure the TLSv1.0 and TLSv1.1 Protocols are Disabled      | PASS   |
| 7.4     | Ensure WAL archiving is configured and functional          | PASS   |
+---------+------------------------------------------------------------+--------+

------------------------------------------------------------------------------
  DETAILS
------------------------------------------------------------------------------
| 3.1.24  | FAIL   | log_line_prefix = '%m [%p] '; missing escape(s): %u %d %a %h
| 4.8     | FAIL   | set_user is not available on this server (not installed on disk)
| 6.6     | MANL   | 146 user-settable runtime parameter(s) present - review their values
|         |        | against your security policy (no fixed CIS value; inspect via: SELECT
|         |        | name, setting FROM pg_settings WHERE context = 'user'). See the CIS
|         |        | PostgreSQL 18 Benchmark PDF, section 6.6, for the manual procedure.
| 1.1     | MANL   | [Manual] Not checkable via psql (package repository configuration
|         |        | (dnf/apt) - OS access). See the CIS PostgreSQL 18 Benchmark PDF,
|         |        | section 1.1, for the manual Audit/Remediation procedure.

------------------------------------------------------------------------------
  SUMMARY
------------------------------------------------------------------------------
+--------+-------+
| Status | Count |
+--------+-------+
| PASS   |    17 |
| FAIL   |    16 |
| WARN   |     3 |
| SKIP   |     6 |
| MANL   |    35 |
+--------+-------+

  Legend: PASS=compliant  FAIL=non-compliant  WARN=needs review
          SKIP=insufficient privilege / not applicable  MANL=OS item (manual)
===============================================================================
```

> The `SKIP` rows above appear because this example was run as a non-superuser
> without `pg_monitor`: the `pg_hba_file_rules` and restricted-GUC items can't
> be read, so they report `SKIP` rather than a misleading `FAIL`. Running as a
> superuser (or a `pg_monitor` member) turns most of those into real verdicts.

## Troubleshooting

### `Method not found: '!0 Microsoft.Identity.Client.BaseAbstractApplicationBuilder`1.WithLogging(...)'`

Symptom (Azure benchmark `Connect-AzAccount -ServicePrincipal` step):

```
[FAIL] Azure connection failed: ClientSecretCredential authentication failed:
Method not found: '!0 Microsoft.Identity.Client.BaseAbstractApplicationBuilder`1
.WithLogging(Microsoft.IdentityModel.Abstractions.IIdentityLogger, Boolean)'.
```

This is **not** a tenant or service-principal issue. It means the Az modules
currently installed ship an MSAL (`Microsoft.Identity.Client.dll`) that expects
a newer `Microsoft.IdentityModel.Abstractions.dll` than the one already loaded
in the PowerShell session -- typically because an older `Az.Accounts` version
is present, or `Microsoft.Graph.*` was imported first with a mismatched
abstractions DLL.

Fix (run in a **fresh** PowerShell window -- do not `Import-Module` anything
first):

```powershell
Update-Module Az.Accounts, Az.Resources, Az.Network, Az.Security, `
              Az.Storage, Az.KeyVault, Az.Monitor, Az.Compute, `
              Az.OperationalInsights, Az.PolicyInsights -Force
```

If that does not help, clear out old `Az.Accounts` copies and reinstall:

```powershell
Uninstall-Module Az.Accounts -AllVersions -Force -ErrorAction SilentlyContinue
Install-Module Az.Accounts -Force -AllowClobber -Scope CurrentUser
```

Then open a **new** PowerShell window and re-run `.\CIS_Azure_Benchmark_Full.ps1`.
The script loads `Az.*` before `Microsoft.Graph.*` on purpose; do not pre-import
`Microsoft.Graph` in the same session.

## Contributing / Agent instructions

Rules for human contributors and AI agents (Copilot, Copilot Desktop, etc.):

1. **CIS benchmarks must include Manual (MANL) steps.** When the CIS
   documentation marks an item `(Manual)`, add it to the benchmark script as
   a `MANL`-status check (category `MANL`, function `Check-MANL-<section>`)
   with the portal path, audit steps, remediation, and references. For the
   PostgreSQL SQL benchmark the equivalent rule is: items that cannot be
   evaluated from `psql` (OS-level checks) or that CIS marks *Manual* with no
   fixed value are inserted with `status = 'MANL'`, and the `detail` must name
   the matching CIS section so the operator can find the manual procedure.
2. **Keep `README.md` up to date** whenever coverage totals, status
   categories, CLI parameters, prerequisites, or sample output change.
3. **Verify / update the Permissions helper** after adding new functionality.
   Any new Graph scope, directory role, or API permission must be added to
   the helper's grant list and verification table. If no new permission is
   needed, say so explicitly in the commit message.

The full rules live in [`.github/copilot-instructions.md`](.github/copilot-instructions.md)
and are summarised in [`AGENTS.md`](AGENTS.md).

## License

This project is provided as-is for security auditing purposes.
