# TenantCheck 365 — tools

- `tenantcheck-export.ps1` — the guided export helper. A customer's own
  admin runs it on Windows; it signs in interactively with the
  Microsoft Graph PowerShell SDK (read-only scopes), reads the tenant
  data the scan needs, asks the owner-stated questions, and writes
  `tenantcheck-snapshot.json` locally (UTF-8, no BOM). It stores and
  transmits no credentials and sends nothing anywhere. The app serves
  it at `/export-script`. Since 2026-11-13 it also writes the
  `sharingInventory` section for the CopilotReady oversharing audit:
  a digest of each site's permission list and default-library (drive
  root) permission list, drive ownership, and the OneDrive root
  permissions of disabled accounts — permission settings only, never
  file contents, and never per-file links below the library root
  (that limit is stated in the script header). Also since
  2026-11-13 it asks three more owner-stated questions for the
  expanded InsureReady questionnaire (written security policy,
  offline/immutable backup copy, penetration-test recency) and
  writes them into `securityControls`; the penetration-test answer
  may be left unrecorded, in which case the scan reports evidence
  missing rather than a default. (The script is edited
  defensively and balance-checked, but PowerShell cannot run in
  the build environment, so these additions carry the same
  unverified-against-a-real-tenant caveat as the rest of the
  script.)
- `sample-script-output.json` — a fixture in exactly the shape the
  script emits (same sections, same field names, same null conventions
  for data Graph cannot supply), for a small fictional accounting firm.
  `check_app.py` uploads it through the real upload flow to prove
  script-shaped output scans end to end. The firm and people in it are
  invented test data; `_meta.fictional` is `false` because that is
  what the script writes for a real run. Its `sharingInventory`
  carries two items (a site with a company-wide link and a disabled
  account owner's OneDrive) that produce the fixture's 2 CopilotReady
  findings.
