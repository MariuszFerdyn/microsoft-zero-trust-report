# Agent instructions

See [`.github/copilot-instructions.md`](.github/copilot-instructions.md) for the
full set of rules that apply to any AI agent working in this repository.

Key points, in short:

1. **CIS benchmarks must include Manual (MANL) steps.** Whenever the CIS
   documentation marks an item `(Manual)`, add it to the benchmark script as a
   `MANL`-status check (category `MANL`, function name `Check-MANL-<section>`)
   with portal path, audit steps, remediation, and references. Pull tenant
   diagnostic data where the API allows it.
2. **Update `README.md`** whenever coverage, status categories, CLI
   parameters, prerequisites, or sample output change.
3. **Verify / update the Permissions helper** (`CIS_M365_Permissions.ps1` or
   `CIS_Azure_Permissions.ps1`) after adding new functionality. Add any new
   Graph scope / directory role / API permission to the helper's grant list
   and its verification table. If no new permission is needed, say so
   explicitly in the commit message.
4. **CSV schema is a contract.** Columns are `Section, Title, Status, Detail`;
   `Status` is one of `PASS|FAIL|WARN|SKIP|MANL`. Don't change without a
   README update.
5. **Preserve exact CIS section IDs and level tags** (`(L1)` / `(L2)`) in
   check titles.
6. **Never commit result CSVs** (`CIS_*_Results_*.csv`). They are
   tenant-specific and excluded via `.gitignore`.
7. **Permissions scripts must stay idempotent** -- safe to re-run without
   duplicating app registrations, secrets, or role assignments.
8. **Parse-check all four scripts** after any edit (see validation block in
   `copilot-instructions.md`). As part of that check, **every `.ps1` must
   start with a UTF-8 BOM** (`EF BB BF`) — PowerShell 5.1 misparses
   BOM-less files that contain non-ASCII bytes. Also run `git status`
   and make sure no `CIS_*_Results_*.csv` or
   `CIS_*_Permissions_Output.json` is staged; those are tenant-specific
   artifacts and must not be committed.
9. **Commit trailer required:**
   `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`
   on every agent commit.

For new CIS benchmark versions, follow
[`.github/skills/cis-benchmark-update.md`](.github/skills/cis-benchmark-update.md).
