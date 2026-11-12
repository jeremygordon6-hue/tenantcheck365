# TenantCheck 365 — tools

- `tenantcheck-export.ps1` — the guided export helper. A customer's own
  admin runs it on Windows; it signs in interactively with the
  Microsoft Graph PowerShell SDK (read-only scopes), reads the tenant
  data the scan needs, asks the owner-stated questions, and writes
  `tenantcheck-snapshot.json` locally (UTF-8, no BOM). It stores and
  transmits no credentials and sends nothing anywhere. The app serves
  it at `/export-script`.
- `sample-script-output.json` — a fixture in exactly the shape the
  script emits (same sections, same field names, same null conventions
  for data Graph cannot supply), for a small fictional accounting firm.
  `check_app.py` uploads it through the real upload flow to prove
  script-shaped output scans end to end. The firm and people in it are
  invented test data; `_meta.fictional` is `false` because that is
  what the script writes for a real run.
