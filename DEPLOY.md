# TenantCheck 365 — going live (NOT done in this build)

This build is verified locally only. **Nothing has been deployed, no
payment collection exists, and no live Microsoft connection exists.**
Going live is three separate steps, each needing Jeremy's explicit
go-ahead:

## 1. Deployment (hosting)

Same pattern NorthCheck used (Render free tier from a GitHub repo):

- Push this folder to a repo, create a Render Web Service
  (Python 3, build command `true`, start command `bash run.sh`).
- Set `HOST=0.0.0.0`; Render supplies `PORT`. `run.sh` already honours
  both.
- **Storage caveat:** Render's free filesystem is ephemeral — the
  `data/` JSON stores (founding list, scan records) do not persist
  across restarts, the same known NorthCheck caveat. Before real
  signups matter, add a persistent disk or move the stores to a real
  database.
- A custom domain is a separate purchase/decision, as with
  NorthCheck.

## 2. Live Microsoft 365 connection (the real production unlock)

- Register TenantCheck 365 as a multi-tenant app in Microsoft Entra
  ID (Azure app registration) with a fixed, read-only permission set.
- Build the admin-consent flow: the customer's own Global
  Administrator grants tenant admin consent; only then can the app
  build the snapshot from Microsoft Graph automatically.
- Add credential/token handling, per-tenant storage and scheduled
  re-scans (the monitoring offer) on top of the consent.
- Only after a live connection exists can "fix application" even be
  considered — and it stays owner-approved per step by design.

## 3. Payments (Stripe)

- Create Stripe products for the founding prices (TenantFix scan
  $149 one-time, monitoring $39/month, bundle $49/month) on the live
  Stripe account, as was done for NorthCheck.
- Add buy buttons / checkout links to the landing page deliberately;
  this build intentionally has none.
- Prices are founding hypotheses (see README pricing note) — the
  research's validation scans may change them before charging starts.
