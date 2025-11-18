# Repository Guidelines

## Project Structure & Module Organization
- `Install-WorldOfWorkflows.ps1` orchestrates the full Azure deployment (resource group, storage, plan, web app) and invokes the other scripts; treat it as the primary entry point for contributors.
- `ADDeploymentScript.ps1` provisions/updates the Entra ID app registrations, permissions, and secrets; keep identifier URI updates localized here.
- `WowCentralDeployRequest.ps1` publishes the completed deployment to WoW Central, including Kudu profile sharing.
- `WebAppConfig.json` holds the base configuration pushed into the Linux App Service; edit it conservatively and document any new settings in PR notes.

## Build, Test, and Development Commands
- `pwsh -NoLogo -File Install-WorldOfWorkflows.ps1` — interactive end‑to‑end deployment flow; run from the repo root to validate changes before submitting.
- `pwsh -NoLogo -File Install-WorldOfWorkflows.ps1 -BusinessEditionSolution enhanced -WhatIf` — dry‑run to confirm parameter validations and Az cmdlet bindings without touching Azure.
- `pwsh -NoLogo -File ADDeploymentScript.ps1 -ClientAppName <name> -ServerAppName <name> -BaseAddress <url> -TenantId <id> -AdminUserPrincipalName <upn>` — standalone test of Entra automation when iterating on permissions or redirect URIs.

## Coding Style & Naming Conventions
- PowerShell 7 syntax, 4‑space indentation, and PascalCase for functions (e.g., `Ensure-WowFileShare`); internal helpers may use camelCase variables for readability.
- Keep parameter names descriptive and align multi-line splats; prefer `[Parameter(Mandatory)]` annotations over manual validation.
- Use `Write-Host` or `Write-Verbose` with consistent sentence casing to keep logs searchable; do not echo secrets.

## Testing Guidelines
- Prefer idempotent reruns: validate that scripts handle re-existing Azure resources and app registrations.
- Include focused Pester tests for new helper functions; place them under `tests/` when added (create the folder if missing).
- Capture manual validation steps (e.g., portal checks, WoW Central receipt) in the PR description; attach logs for failing Az cmdlets.

## Commit & Pull Request Guidelines
- Follow the short, imperative commit style already in history (`fixed typo in json`, `send admin name to deploy ps1`); group related script + config updates in a single commit.
- PRs should describe the scenario exercised (`standard` vs `enhanced`), list PowerShell commands executed, and call out any tenant-level prerequisites (Global Admin, subscription owner).
- Mention whether secrets or tenant-specific identifiers changed; never include actual secret material—store references in Azure Key Vault instead.
