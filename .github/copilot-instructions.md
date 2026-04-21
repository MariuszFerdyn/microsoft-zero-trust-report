# Copilot / Agent Instructions

These instructions apply to any AI agent (GitHub Copilot, Copilot Desktop, Copilot
coding agents) contributing to this repository.

## Project overview

This repo contains PowerShell automation that audits a Microsoft tenant against
the CIS Benchmarks:

- `CIS_Azure_Benchmark_Full.ps1` + `CIS_Azure_Permissions.ps1` — CIS Microsoft Azure Foundations v5.0.0
- `CIS_M365_Benchmark_Full.ps1`  + `CIS_M365_Permissions.ps1`  — CIS Microsoft 365 Foundations v6.0.1

The benchmark scripts emit color-coded results (`PASS`, `FAIL`, `WARN`, `SKIP`,
`MANL`) to the console and a timestamped CSV (`Section, Title, Status, Detail`).

## Core rules

### 1. Always include Manual (MANL) steps when working on CIS benchmarks

When a CIS document marks an item as **(Manual)**, the benchmark script **must
include that item as a `MANL`-status check**, alongside the Automated checks.

- Use the section prefix / category **`MANL`** (not `WARN`, not `SKIP`).
- Function naming convention: `Check-MANL-<section>` (e.g. `Check-MANL-1_3_8`).
- Each MANL check must print, for the operator:
  - the portal path (URL + menu breadcrumb),
  - the CIS **Audit** steps,
  - the CIS **Remediation** steps,
  - relevant references.
- Where possible, pull contextual diagnostic data via Graph / EXO / Teams (for
  example, enumerate candidate break-glass accounts for `1.1.2`, check
  `OnPremisesSyncEnabled` for `5.1.8.1`, read Teams global app policy for
  `8.4.1`). A MANL check that can still surface useful tenant data is much more
  valuable than one that only prints static text.
- Record the result with `Add-Result <section> <title> "MANL" <detail>` and
  increment the MANL counter via `Write-Manl`.
- Wire new MANL checks into the `SECTION MANL` banner block at the bottom of
  the main script.

### 2. Update README when behavior or coverage changes

If a change alters user-visible behavior (new checks, new parameters, new
statuses, new sections, new prerequisites), the `README.md` **must** be updated
in the same change:

- Keep the coverage table counts (Automated / Manual) accurate.
- Document any new CLI parameter.
- Keep the sample console output representative (update `PASS` / `FAIL` /
  `MANL` examples if the format has changed).
- Mention any new required permission / role.

### 3. Verify and update the Permissions helper when adding checks

After adding any new Automated or Manual check, **review the matching
Permissions helper** (`CIS_M365_Permissions.ps1` or `CIS_Azure_Permissions.ps1`):

- If the new check uses a Graph scope, directory role, or API that is not
  already granted — add it to the helper's permission list **and** the
  verification table at the bottom.
- If no new permission is required (e.g. a MANL check that only prints CIS
  text), leave the code unchanged but note this explicitly in the commit
  message or the helper's header comment.
- Keep the README prerequisites / permissions section in sync with any change
  to the helper.

## Coding conventions

- PowerShell 5.1 compatible; use `#Requires -Version 5.1`.
- Use the existing helpers: `Invoke-Check`, `Write-Pass`, `Write-Fail`,
  `Write-Warn`, `Write-Manl`, `Write-Info`, `Add-Result`.
- Wrap EXO pipeline output in `@(...)` to guard against `$null` / single-object
  `.Count` issues with deserialized objects.
- Never commit secrets. The default tenant/app/secret values in the `param()`
  block of `CIS_M365_Benchmark_Full.ps1` are only examples — do not replace
  them with live credentials.

## Validation

Before finishing a change, at minimum run a PowerShell AST parse to catch
syntax errors:

```powershell
$tokens = $null; $errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    ".\CIS_M365_Benchmark_Full.ps1", [ref]$tokens, [ref]$errors) | Out-Null
$errors
```

The check must emit no errors. When possible, run the benchmark end-to-end
against a lab tenant and confirm the new result appears in the CSV.
