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

### 4. CSV schema is a stable contract

The results CSV written by each benchmark script has a fixed schema:

- **Columns (in order):** `Section, Title, Status, Detail`.
- **Allowed `Status` values:** `PASS`, `FAIL`, `WARN`, `SKIP`, `MANL`.

Treat this as a public interface. Do not rename, reorder, add, or remove
columns; do not introduce new `Status` values without also updating the
README status table, the color map in `Show-Summary`, and any downstream
consumers. If a schema change is truly required, call it out explicitly in
the PR description.

### 5. Section IDs and level tags must match the CIS source exactly

- The `Section` value (e.g. `1.3.8`, `6.1.1.10`) must match the CIS
  benchmark PDF verbatim. Do not renumber, invent, or pad section IDs.
- Preserve the CIS **level** annotation in the title string: `(L1)` or
  `(L2)`. The canonical form used by `Invoke-Check` is
  `"<section> (L1|L2)"` for the first argument and the full CIS title
  (including a trailing `(Automated)` or `(Manual)`) for the second.
- The `Add-Result` section argument must equal the first part of the
  `Invoke-Check` section string (no level tag). Keep the two aligned.

### 6. Never commit generated result CSVs

- Result CSVs (`CIS_*_Results_*.csv`) are tenant-specific audit output and
  must never be committed.
- The repo's `.gitignore` already excludes `CIS_*_Results_*.csv`. Do not
  weaken or remove this rule. If you accidentally stage one, un-stage it
  before committing.

### 7. Permissions scripts must be idempotent

`CIS_M365_Permissions.ps1` and `CIS_Azure_Permissions.ps1` are expected to
be safely re-runnable by operators. When modifying them:

- Use "create or reuse" patterns (look up the App Registration / Service
  Principal / role assignment by name or id first, create only if missing).
- Do not generate or overwrite a client secret on every run — only when
  explicitly requested by a parameter.
- Do not fail the whole script because a role assignment already exists;
  treat that as success. Prefer `az ... --only-show-errors` and explicit
  `try { } catch { }` around idempotent operations.
- Keep the verification table at the bottom in sync with the grants above.

### 8. Permissions scripts must offer to run the benchmark at the end

At the end of every successful run, both `CIS_M365_Permissions.ps1` and
`CIS_Azure_Permissions.ps1` must:

- print the exact `CIS_*_Benchmark_Full.ps1` invocation (tenant, app,
  subscription, secret placeholder, any optional flags) so the operator
  can copy-paste it later;
- then, unless `-NoPause` was passed, prompt **`Run benchmark now? [Y/N]`**
  and, on `Y`, invoke the matching benchmark script in-process with the
  parameters that were just configured.

Handle the no-secret path explicitly. When the operator did not pass
`-CreateSecret`, there is no secret in memory. In that case the prompt
must still be offered; if the operator chooses `Y`, ask for the existing
secret via `Read-Host -AsSecureString` (never echo it, never persist it
to `CIS_*_Permissions_Output.json`), convert it with
`Marshal.SecureStringToBSTR` / `PtrToStringAuto`, and pass the plain
value only as an in-process argument to the benchmark script. If the
operator presses Enter without supplying a secret, print a single
`Write-Warn 'No client secret provided -- benchmark run skipped.'` and
exit cleanly.

Do not pass placeholder text (for example `YOUR-CLIENT-SECRET` or
`<NOT_CREATED - re-run with -CreateSecret>`) to the benchmark script --
guard against it.

## Coding conventions

- PowerShell 5.1 compatible; use `#Requires -Version 5.1`.
- Use the existing helpers: `Invoke-Check`, `Write-Pass`, `Write-Fail`,
  `Write-Warn`, `Write-Manl`, `Write-Info`, `Add-Result`.
- Wrap EXO pipeline output in `@(...)` to guard against `$null` / single-object
  `.Count` issues with deserialized objects.
- Never commit secrets. The default tenant/app/secret values in the `param()`
  block of `CIS_M365_Benchmark_Full.ps1` are only examples — do not replace
  them with live credentials.

## Commit message requirements

Every commit created by an AI agent in this repository must include the
following trailer at the end of the commit message:

```
Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```

This applies to both single-agent commits and multi-author / pair-programmed
commits. Do not rewrite existing history to add or remove this trailer.

## Validation

Before finishing a change, run a PowerShell AST parse over **all four**
scripts (not just the one you edited — shared helper patterns drift
easily):

```powershell
$scripts = @(
    'CIS_Azure_Benchmark_Full.ps1',
    'CIS_Azure_Permissions.ps1',
    'CIS_M365_Benchmark_Full.ps1',
    'CIS_M365_Permissions.ps1'
)
foreach ($f in $scripts) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        ".\$f", [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors) { "$f : $($errors.Count) errors"; $errors[0] }
    else         { "$f : OK" }
}
```

The check must emit `OK` for every script. When possible, run the benchmark
end-to-end against a lab tenant and confirm the new result appears in the
CSV.

### UTF-8 BOM is mandatory on every `.ps1`

Windows PowerShell 5.1 decodes BOM-less files using the host's ANSI code
page. Any multi-byte UTF-8 character in the script (e.g. the box-drawing
`─` used in banner comments, or accented characters in CIS titles) will
desynchronise the tokenizer and produce misleading errors far from the
real cause, typically `Unexpected token '}' in expression or statement`
pointing at a random closing brace. `Parser.ParseFile` — which reads the
file as UTF-8 — will still report `OK`, which hides the problem.

Always verify every `.ps1` starts with a UTF-8 BOM (`EF BB BF`) before
committing. If any file is missing the BOM, prepend it and re-run the
parse check:

```powershell
$scripts = @(
    'CIS_Azure_Benchmark_Full.ps1',
    'CIS_Azure_Permissions.ps1',
    'CIS_M365_Benchmark_Full.ps1',
    'CIS_M365_Permissions.ps1'
)
$bom = [byte[]](0xEF, 0xBB, 0xBF)
foreach ($f in $scripts) {
    $bytes = [System.IO.File]::ReadAllBytes($f)
    $hasBom = $bytes.Length -ge 3 -and
              $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    if (-not $hasBom) {
        [System.IO.File]::WriteAllBytes($f, $bom + $bytes)
        "BOM added: $f"
    } else {
        "BOM OK: $f"
    }
}
```

Do not rely on editors to preserve the BOM — many default to BOM-less
UTF-8 on save. If you edit a script with a tool that strips the BOM,
re-add it as part of the same change. This check is part of validation
and must pass before opening a PR.

### Clean up stray artifacts before committing

Never commit files that are produced by running the scripts. In addition
to the CSV rule above, the following must stay out of the repo and out
of git history:

- `CIS_*_Results_*.csv` — benchmark result files
- `CIS_*_Permissions_Output.json` — permissions-helper output (may
  contain a freshly minted client secret)
- any other `*_Output.*` / `*.log` / tenant-specific exports

`.gitignore` already excludes these patterns. Before committing, run
`git status` and confirm nothing matching the patterns above is staged.
If one slipped in, `git rm --cached <file>` and amend before pushing —
GitHub push protection will otherwise reject the push and you will
have to rewrite the commit anyway.

## Updating to a new CIS benchmark version

When CIS publishes a new version of the Azure Foundations or M365
Foundations benchmark, follow the playbook in
[`.github/skills/cis-benchmark-update.md`](skills/cis-benchmark-update.md).
In short: extract the PDF to text with `pdftotext -layout` (Xpdf), diff
the section list against the current scripts, add / remove Automated and
MANL checks, update README counts, re-verify the Permissions helper, and
parse-check all four scripts.
