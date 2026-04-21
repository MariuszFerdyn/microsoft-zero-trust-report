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
