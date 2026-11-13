# TenantCheck 365 — going live (NOT done in this build)

This build is verified locally only. **Checkout is the Stripe Payment
Links on the landing page (section 3), in CAD. This app does not take
card numbers. A live Microsoft connection exists in code and stays off
until `SETUP-GRAPH.md` is done.**
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

- Stripe Payment Links for the founding prices are on the landing
  page: TenantFix scan $149 CAD one time, monitoring $39 CAD/month,
  bundle $49 CAD/month. CAD is the currency configured on those live
  Payment Links. The amounts are unchanged.
- The app links out to Stripe. It does not take card numbers, and it
  does not record whether a payment succeeded.
- Prices are founding hypotheses (see README pricing note) — the
  research's validation scans may change them.
