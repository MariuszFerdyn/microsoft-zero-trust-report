# Skill: Update a CIS benchmark to a new version

Use this playbook when a new version of either benchmark is released:

- CIS Microsoft Azure Foundations Benchmark (currently v5.0.0)
- CIS Microsoft 365 Foundations Benchmark (currently v6.0.1)

The goal is a single PR that brings one benchmark script up to date with
the new PDF, keeps MANL coverage complete, keeps the Permissions helper
valid, and keeps the README accurate.

## 0. Prerequisites

- The new CIS PDF (attached to the task or downloaded from CIS).
- `pdftotext.exe` from Xpdf command line tools. A known-good path used
  previously in this repo is:

  ```
  C:\Users\<user>\AppData\Local\Temp\xpdf\xpdf-tools-win-4.06\bin64\pdftotext.exe
  ```

  If not present, download from <https://www.xpdfreader.com/download.html>
  and extract the `bin64` folder. No installer is required.

- PowerShell 5.1+.

## 1. Convert the PDF to text

Always use the `-layout` flag so column layout and section numbering are
preserved. Put the output under the session artifacts directory, not in
the repo:

```powershell
& "<path>\pdftotext.exe" -layout `
    "<path>\CIS_Microsoft_Azure_Foundations_Benchmark_v<X.Y.Z>.pdf" `
    "<artifacts>\cis_azure.txt"
```

## 2. Enumerate every check (Automated and Manual)

Titles in the text output often wrap across lines, so regex-matching the
whole title on one line is unreliable. The working approach used on this
repo:

1. Find every line that is exactly `Profile Applicability` (one per check).
2. Walk backwards from that line to the nearest line that starts with a
   section number, e.g. `^(\d+(?:\.\d+){1,4})\s+`.
3. Concatenate the non-blank lines between the section heading and
   `Profile Applicability` to reconstruct the full title.
4. Classify by the trailing `(Automated)` or `(Manual)` token in the title.

The result is a list of `{ Section, Level (L1/L2), Title, Kind }` records
covering every check in the PDF.

## 3. Diff against the current script

For the matching benchmark script, extract the current coverage:

```powershell
Select-String -Path .\CIS_Azure_Benchmark_Full.ps1 `
    -Pattern 'Invoke-Check\s+"(?<sec>[^"\s]+)\s+\((?<lvl>L[12])\)"\s+"(?<title>[^"]+)"' `
    -AllMatches
```

Compare sets to produce three lists:

- **New in PDF, missing from script** -> add.
- **In script, no longer in PDF** -> remove (or mark deprecated, with a
  note in the PR description).
- **Present in both but title / level / section changed** -> update.

## 4. Add or update checks

### Automated items

- Follow the existing per-section style in the script.
- Reuse helpers: `Invoke-Check`, `Write-Pass`, `Write-Fail`, `Write-Warn`,
  `Write-Info`, `Add-Result`.
- Wrap pipeline output in `@(...)` to guard against single-object or
  `$null` `.Count` issues.

### Manual (MANL) items -- mandatory

- Add a function `Check-MANL-<section_with_underscores>` for every PDF
  item whose title ends in `(Manual)`.
- Each function must:
  - Call `Invoke-Check "<section> (L1|L2)" "<exact CIS title> (Manual)"`.
  - Call `Write-ManualAudit -Portal ... -AuditSteps @(...) -Remediation @(...)`.
  - Call `Write-Manl "<short message>"`.
  - Call `Add-Result "<section>" "<short title>" "MANL" "<detail>"`.
- Wire each new function into the `SECTION MANL` invocation block near
  the end of the script.

### Source text for portal / audit / remediation

The PDF sections are noisy (line wraps, bullets rendered as spaces).
Expect to **hand-curate** the portal path, audit steps, and remediation
for manual checks -- fully automatic extraction typically only succeeds
for ~half of items. Keep the text aligned with the CIS wording but short
enough to read on a console.

## 5. Update counters, banner, and summary

In the benchmark script, update:

- `.SYNOPSIS` / `.DESCRIPTION` header counts.
- The startup banner that prints `Automated + Manual` totals.
- `Show-Summary` if you added a new section or status (shouldn't be
  needed for a version bump).

## 6. Update the Permissions helper

Per `copilot-instructions.md` rule 3 and rule 7, review the matching
`CIS_*_Permissions.ps1`:

- Add any new Graph scope, directory role, or Azure RBAC role required
  by a new Automated check.
- Confirm idempotency (create-or-reuse App Registration, role
  assignments, etc.).
- If MANL-only changes were made and no new permission is needed, state
  that explicitly in the commit message.
- Keep the verification table at the bottom of the helper in sync.

## 7. Update the README

- Benchmarks table: new Automated / Manual counts.
- Per-section sub-table: new per-section counts (split Automated vs
  Manual where it adds clarity).
- Sample console output: refresh if the output format changed.
- Prerequisites / permissions list: reflect any new grant.

## 8. Validate

Parse-check all four scripts (see `copilot-instructions.md`). All must
report `OK`. If a lab tenant is available, run the updated benchmark
end-to-end and confirm:

- New Automated checks return `PASS` / `FAIL` / `WARN` (not an
  unhandled exception).
- New MANL checks produce the `[MANL]` lines with portal + audit +
  remediation.
- The result CSV contains rows for every new section.

## 9. Commit hygiene

- Do **not** commit `CIS_*_Results_*.csv`.
- Every commit must include the required `Co-authored-by: Copilot ...`
  trailer (see `copilot-instructions.md`).
- Keep unrelated reformatting out of the PR; CIS version bumps are
  already large enough to review.
