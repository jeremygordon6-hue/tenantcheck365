# TenantCheck 365 — production web app

TenantCheck 365 is the brand over the three M365-cluster modules, all
running on one tenant scan engine:

- **TenantFix 365** — Microsoft 365 hardening scan for small firms
  (roughly 3–50 seats) with no IT person, plus an owner-approved fix
  plan.
- **TokenWatch** — OAuth grant inventory ranked by scope sensitivity ×
  consent type, with a loading for unverified publishers. Time unused
  changes the rank only when the snapshot includes a real last-use
  date. The export script writes that date as null, because Graph
  permission grants do not include it, so an export is ranked without
  a dormancy guess. The live Graph path can fill it from app sign-in
  logs when Microsoft returns them.
- **InsureReady 365** — the same scan mapped to a representative
  Canadian cyber-insurance evidence questionnaire (Supported / Gap /
  Evidence missing, each tied to scan evidence).

**Honesty rule (product requirement):** TenantCheck 365 prepares
evidence. It does not certify compliance and is not legal or insurance
advice. Every finding is an *issue to review*; the owner makes the
call. Every downloaded report carries the engine's DRAFT stamp.

**Scan input — honest by design:** this version runs on an **exported
tenant snapshot** (JSON shaped like Microsoft Graph responses) that
the visitor uploads, or on the fictional demo tenant bundled with the
app. It does **not** connect to Microsoft Graph, does **not** sign
anyone into Microsoft, and **never collects Microsoft credentials** —
there is no Microsoft sign-in anywhere in the app. A live connection
needs an Azure app registration and tenant admin consent granted by
the customer's own administrator; that is the next step and is
described on the app's `/live-connection` page.

## Free-tools inventory

This build uses **free / open-source tools only**:

| Piece | Tool | Cost |
|---|---|---|
| Language + runtime | Python 3 (PSF licence) | Free |
| Web server | `http.server` from the Python standard library | Free |
| Checks engine | `m365.py` — the verified M365-cluster engine, Python stdlib only (`json`, `pathlib`) | Free, built in-house |
| Pages | Server-rendered HTML with inline CSS — no JavaScript frameworks, no external CDNs, no npm packages, no paid APIs, no paid services | Free |
| Upload parsing | Hand-written multipart parser in `app.py` (stdlib `re`) | Free |
| Storage | JSON files under `data/` (created at runtime) | Free |
| Process | `bash run.sh` | Free |

Checkout is three Stripe Payment Links on the landing page. The
amounts are in CAD, which is the currency configured on those links.
Card numbers are entered on Stripe, not in this app, and this app
does not record whether a payment succeeded. The live Microsoft
Graph connection stays off until the app registration in
`SETUP-GRAPH.md` is configured.

## Run it

```bash
bash run.sh
```

Serves on `http://127.0.0.1:8795` by default (binds localhost only).
Override with `PORT=9000 bash run.sh` or `HOST=0.0.0.0` where a
deployment platform requires it — see `DEPLOY.md`.

## Features

- **Landing page (`/`)** — the pitch (Microsoft 365 security check
  for small firms with no IT person), how it works, all three modules,
  founding prices (below), a one-click demo scan, and the founding
  list signup (name + email + company stored to
  `data/founding.json`; **no email is sent**).
- **Scan (`/scan`)** — upload an exported tenant snapshot JSON
  (6 MB cap, multipart form), or run the demo. The app validates the
  snapshot's structure and rejects bad JSON, missing sections and
  empty files with clean plain-English errors (HTTP 400/413, no
  tracebacks). Results render in the browser per module — summary
  counts, TenantFix findings with severity/why/fix steps, the
  TokenWatch ranking table, the InsureReady question list — and are
  stored in `data/scans.json`, re-renderable at `/results/<id>`.
- **Report downloads (`/report/<id>/tenantfix|tokenwatch|insureready`)**
  — the engine's Markdown reports, byte-for-byte the prototype's
  outputs, each DRAFT-stamped, served as file attachments.
- **How to export (`/how-to-export`)** — a guided page with two
  paths. **Option A (about 10 minutes):** the customer firm's own
  admin downloads `tools/tenantcheck-export.ps1` (served at
  `/export-script` as a file attachment), runs it on their own
  Windows machine, signs in interactively with the Microsoft Graph
  PowerShell SDK under read-only scopes, answers the owner-stated
  questions the script asks, and uploads the
  `tenantcheck-snapshot.json` it writes. The script stores and
  transmits no credentials and sends nothing anywhere.
  **Option B:** the original manual assembly, kept as a fallback,
  with the table mapping each snapshot section to its Microsoft
  Graph / admin source. Both paths keep the standing rule that no
  Microsoft password is ever asked for.
- **Live connection (`/live-connection`)** — the consent explainer:
  app registration, admin consent granted only by the customer's own
  Global Administrator, read-only permissions, revocability — and a
  plain statement that the live connection is **not switched on** in
  this version.

## The engine

`m365.py` in this folder is a **byte-identical copy** of the verified
prototype engine from `../m365-cluster/` (md5-verified at copy time),
so the app is self-contained. The app imports and reuses its functions
(`run_scan`, `normalise`, `tenantfix`, `tokenwatch`, `insureready`,
the three `render_*` report writers, `STAMP`, `FIX_PLAN_NOTE`) rather
than re-implementing any check. The only adaptation lives in `app.py`:
uploaded snapshots that arrive without the demo's `_meta` block get a
truthful one synthesised from the tenant itself, because the report
renderer reads firm name / snapshot date / label from `_meta`.

`demo_snapshot.json` is likewise copied in: a fabricated ~18-seat firm
("Maple & Main Bookkeeping Co.") with 24 planted problems (10
TenantFix, 3 TokenWatch-flagged of 8 grants, 11 InsureReady gaps of
13 questions), labelled fictional in the file and in every report.

## Verification

```bash
python3 check_app.py
```

**114 / 114 end-to-end checks passed** (58 original checks as of
2026-11-09, plus the export-helper checks added 2026-11-11, plus the
public-claim checks: CAD on the founding prices, no ExecutionPolicy
Bypass, no host or environment-variable names on the connection
pages, and export last-use shown as unknown). The export-helper
checks confirm the guided page offers Option A and Option B,
`/export-script` serves the script file as an attachment, and a
fixture in exactly the script's output shape passes the upload flow
with its expected results — 3 TenantFix findings, 1 of 2 grants
flagged, 5 of 13 InsureReady gaps. The rest of the suite covers
server and landing
(all three modules, all three founding prices, honesty line, signup
fields), explainer pages (export sources, consent steps, "not
switched on" status), demo flow returning the prototype's exact
expected findings (TenantFix **10**, TokenWatch **3 flagged of 8**,
InsureReady **11 gaps of 13**), stored-record re-rendering and
persistence, all three report downloads carrying the DRAFT stamp,
upload flow (valid snapshot → same findings; invalid JSON, missing
sections and empty file → clean 400s, no traceback), founding signup
persistence (name/email/company) and bad-email rejection, 404
handling — and the copied engine re-verifying **40 / 40** on the demo
snapshot inside the app. The checker backs up and restores `data/`, so
test entries never reach the real stores.

## Founding prices — and where they come from

| Offer | Founding price |
|---|---|
| TenantFix 365 scan + owner-approved fix plan | **$149 CAD** one time |
| TenantFix monitoring (scheduled re-scan alerts) | **$39 CAD/month** |
| Full bundle (TenantFix + TokenWatch + InsureReady) | **$49 CAD/month** |

**Pricing source note (required honesty):** the CTIO research behind
these modules validated **no dollar price** for any of them. What the
research *did* establish: the paid alternative in Canada is a managed
security layer at roughly **CA$185–$230+ per user/month** (Track C
§1, Amen Security cost guide), which prices micro-firms out;
enterprise SSPM for TokenWatch's job is, in an SMB buyer guide's own
verdict, "not yet" for a ~60-person firm (Track A §1); and
InsureReady's willingness-to-pay signal is deadline-driven (annual
renewal), with the dollar figure unvalidated (Track A §2). The
research's own stated next step for TenantFix was validation with 5
tenant scans before any price is set. The founding prices above
therefore follow the **NorthCheck founding ladder** ($149 CAD evidence
pack / $39 CAD monitoring / $49 CAD subscription) as deliberate introductory
hypotheses for the first cohort — labelled "founding prices" on the
site, to be confirmed or changed by those validation scans. They are
not validated prices. Checkout for these amounts is open through the
Stripe Payment Links on the landing page, in CAD. The app does not
take card numbers and does not record whether a payment succeeded.

## Limitations (stated plainly)

- **Export-based, not live.** Findings cover only what the uploaded
  snapshot contains. The manual export is an interim path (see
  `/how-to-export`); some `securityControls` items (backup restore
  tests, training, a written incident plan) are owner-stated facts,
  and anything absent is reported as *evidence missing*, never
  assumed.
- **No fix application.** TenantFix outputs an owner-approved fix
  plan and labels it exactly that way. Applying changes to a real
  tenant is production work behind app registration and admin
  consent.
- **InsureReady is a representative sample.** The 13-question
  questionnaire models a typical Canadian SMB cyber-insurance
  evidence questionnaire; it is not a specific insurer's form, and
  wording varies by insurer and broker.
- **Checklist thresholds are code choices** (3 Global Admins, 90-day
  dormancy, 12-character passwords, ~95% EDR/encryption, 90-day
  backup-test window), named in `m365.py` for tuning during
  validation interviews — not Microsoft or insurer mandates.
- Storage is local JSON files — fine for founding-cohort volume, not
  a multi-tenant database. No user accounts. Demo verification proves
  the engine catches the problems planted in the demo snapshot; it is
  not evidence about any real tenant.

## Files

| File | Purpose |
|---|---|
| `app.py` | The web app (stdlib only): pages, upload/scan flow, downloads, signup |
| `m365.py` | The verified engine, copied byte-identical from `../m365-cluster/` |
| `demo_snapshot.json` | Fabricated demo tenant with planted-problems manifest |
| `check_app.py` | Automated end-to-end verification (114 checks + engine 40/40) |
| `run.sh` | Start the app (PORT/HOST overridable, defaults 8795 / 127.0.0.1) |
| `tools/tenantcheck-export.ps1` | Guided export helper the customer's own admin runs (Graph SDK, read-only) |
| `tools/sample-script-output.json` | Fixture in exactly the script's output shape, uploaded by `check_app.py` |
| `data/` | Runtime JSON stores: `founding.json`, `scans.json` |
| `DEPLOY.md` | What going live still requires (not done in this build) |
