# TenantCheck 365 — production web app

TenantCheck 365 is the brand over the three M365-cluster modules, all
running on one tenant scan engine:

- **TenantFix 365** — Microsoft 365 hardening scan for small firms
  (roughly 3–50 seats) with no IT person, plus an owner-approved fix
  plan.
- **TokenWatch** — OAuth grant inventory ranked by scope sensitivity ×
  dormancy × consent type, with a loading for unverified publishers.
  Includes an AI apps view: grants identified by app name against a
  maintained list of known AI services, with each app's access in
  plain English (name-based identification only — an unlisted AI
  tool would not be flagged, and the reports say so).
- **InsureReady 365** — the same scan mapped to a representative
  Canadian cyber-insurance evidence questionnaire (Supported / Gap /
  Evidence missing, each tied to scan evidence). Since 2026-11-13
  the questionnaire is 25 questions (IR-Q01..Q25) and the download
  is a broker-ready pack: plain answers derived from status, the
  evidence behind each, and a closing owner-review section warning
  that insurers treat attested answers as fact at claim time. The
  12 added questions each map to exactly one honest source: an
  existing snapshot field or module result (password policy,
  dormant accounts, TokenWatch flagged apps, sharing state, guest
  breadth), a new owner-stated `securityControls` field wired
  through the export script, fixture, demo and Graph owner-facts
  (`writtenSecurityPolicyDocumented`,
  `penetrationTestLastMonthsAgo`, `backupOfflineOrImmutableCopy`),
  or no source at all — prior incidents/claims, sensitive-data
  volumes, remote-access MFA and email authentication always
  answer Evidence missing with owner guidance.
- **CopilotReady** (`copilot_audit.py`, a companion module — the
  engine stays byte-identical) — the Copilot oversharing audit,
  included in the scan at no separate price since 2026-11-13.
  Microsoft Copilot answers only from what the asking employee may
  already read, so broad sharing grants are the exposure. The audit
  reads the snapshot's `sharingInventory` section (a per-site /
  per-library permission digest written by the export script) and
  reports, in plain English: anonymous "anyone with the link" links
  (CA-ANYONE-LINK, Critical when editable, else High), grants to
  "Everyone" (CA-EVERYONE-EXTERNAL, High), grants to every staff
  member (CA-EVERYONE-STAFF, High when editable, else Medium),
  company-wide links (CA-ORG-LINK, Medium), sites with no owner
  found (CA-OWNERLESS, Medium), OneDrives whose owner account is
  disabled (CA-DISABLED-OWNER, Medium), and guests allowed to
  re-share (CA-GUEST-RESHARE, Medium). A snapshot without a
  `sharingInventory` reports the audit as NOT COVERED — absence is
  never rendered as a pass.

Also added 2026-11-13, all included in the scan at no separate
price:

- **Sign-in rules evidence** — a results section and downloadable
  report stating what a snapshot can prove about Conditional
  Access (policy count only), MFA registration and legacy auth,
  with the explicit limit that policy *contents* are not in the
  snapshot, so nothing claims a policy is correctly configured.
- **Scan-to-scan change report** — when a firm is scanned again,
  the results page shows "What changed since the last scan"
  (TenantFix findings new vs resolved, InsureReady status changes,
  CopilotReady changes, flagged-app changes, headline deltas), or
  "Baseline scan" the first time. In-product only: no email
  alerting, no scheduler.
- **AI Governance Pack** — a downloadable pack per scan: the
  TokenWatch AI inventory, the CopilotReady oversharing summary, a
  ready-to-adopt AI acceptable-use policy TEMPLATE (stamped as a
  template with blanks; the firm's policy only once the owner
  adopts it), and an evidence page separating scan evidence from
  owner-to-state items.
- **TenantCheck for Google Workspace** (`google_check.py`) — an
  export-based companion at `/google`: GoogleFix checks (2-Step
  Verification, dormant/admin accounts, super-admin sprawl, less
  secure app access, Drive sharing, anyone-with-the-link counts,
  external group members, risky third-party apps incl. the same
  name-based AI identification), its own app inventory, and the
  same 25-question InsureReady questionnaire via an explicit
  adapter/mapping (documented in the module). Its fictional demo
  domain (`demo_google_snapshot.json`) carries a planted manifest
  verified 17/17 by `google_check.py verify`.
- **Google live connection** (`google_connect.py`) — the Google
  counterpart of the Microsoft connection, built to Google's own
  model: a service account with **domain-wide delegation**. The
  owner creates a Google Cloud project + service account
  (SETUP-GOOGLE.md); each customer domain's super admin then
  authorizes the service account's client ID in their Admin
  console with a fixed read-only scope list, and the app
  impersonates a named admin email to read users, groups and
  per-user third-party tokens via the Admin SDK, building the
  same snapshot the export path produces. Status and connect
  pages at `/google/live-connection` and `/google/connect`.
  INACTIVE until the owner sets the `TENANTCHECK_GOOGLE_*`
  environment variables; while absent, both pages report setup
  pending and refuse gracefully. The service-account key exists
  only in that environment variable — never on disk, never in a
  store, never collected from a customer. What the Directory API
  cannot supply (domain Drive settings, mail forwarding, the
  group allows-external setting) is owner-stated or reported not
  covered, never fabricated.

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
described on the app's `/live-connection` page. The Google companion
works the same way: exports today, and a live connection that needs
the owner's Google Cloud service account setup (SETUP-GOOGLE.md)
plus each customer admin's domain-wide delegation authorization,
described on `/google/live-connection`.

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

The **only** future paid-adjacent pieces are **payment processing**
(Stripe) and **hosting**, and the **Azure app registration** for live
scans — all explicitly **not** included in this build. No payments are
collected anywhere in this app, and nothing is deployed.

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
- **Report downloads (`/report/<id>/tenantfix|tokenwatch|insureready|copilot`)**
  — the engine's Markdown reports, byte-for-byte the prototype's
  outputs, each DRAFT-stamped, served as file attachments. The
  `copilot` download is the CopilotReady audit report (or its
  NOT COVERED note) from `copilot_audit.py`, carrying the same
  DRAFT stamp.
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

`m365.py` in this folder began as a **byte-identical copy** of the verified
prototype engine from `../m365-cluster/` (md5-verified at copy time),
so the app is self-contained. The app imports and reuses its functions
(`run_scan`, `normalise`, `tenantfix`, `tokenwatch`, `insureready`,
the three `render_*` report writers, `STAMP`, `FIX_PLAN_NOTE`) rather
than re-implementing any check. The only adaptation lives in `app.py`:
uploaded snapshots that arrive without the demo's `_meta` block get a
truthful one synthesised from the tenant itself, because the report
renderer reads firm name / snapshot date / label from `_meta`.

`demo_snapshot.json` is likewise copied in: a fabricated ~18-seat firm
("Maple & Main Bookkeeping Co.") with planted problems across every
module (10 TenantFix, 4 TokenWatch-flagged of 10 grants (incl. 2
planted AI apps, 1 flagged), 23 InsureReady gaps of 25 questions) plus, since 2026-11-13, a `sharingInventory` of 6
sites and drives carrying 7 planted oversharing cases for the
CopilotReady audit (manifested under `_planted.copilotaudit`),
labelled fictional in the file and in every report.

## Verification

```bash
python3 check_app.py
```

**187 / 187 end-to-end checks passed** as of 2026-11-13 (the
Google live-connection build added 26 checks — pending and
configured states over HTTP, plus a mocked Admin SDK domain run
end to end with a fake signer; the
Google Workspace build added 18 checks, the AI governance pack
build 4, the sign-in evidence + drift build 7, the TokenWatch
AI-apps build 8; the InsureReady expansion build added 7 checks
and expanded the
questionnaire from 13 to 25 questions with a broker-ready pack;
the CopilotReady build added 15 checks: the demo tenant's 7 planted
oversharing cases caught in-process against the snapshot's
`_planted.copilotaudit` manifest and over HTTP, the script-shaped
fixture's 2 findings, a no-inventory upload reporting the audit as
NOT COVERED, the `/report/<id>/copilot` download with its DRAFT
stamp, and the landing page presenting CopilotReady as included in
the scan). The 2026-11-11 count was

**67 / 67 end-to-end checks passed** (58 original checks as of
2026-11-09, plus the export-helper checks added 2026-11-11: the
guided page offers Option A and Option B, `/export-script` serves
the script file as an attachment, and a fixture in exactly the
script's output shape passes the upload flow with its expected
results — 3 TenantFix findings, 1 of 2 grants flagged, 12 of 25
InsureReady gaps): server and landing
(all three modules, all three founding prices, honesty line, signup
fields), explainer pages (export sources, consent steps, "not
switched on" status), demo flow returning the prototype's exact
expected findings (TenantFix **10**, TokenWatch **4 flagged of 10**,
InsureReady **23 gaps of 25**), stored-record re-rendering and
persistence, all three report downloads carrying the DRAFT stamp,
upload flow (valid snapshot → same findings; invalid JSON, missing
sections and empty file → clean 400s, no traceback), founding signup
persistence (name/email/company) and bad-email rejection, 404
handling — and the copied engine re-verifying **53 / 53** on the demo
snapshot inside the app. The checker backs up and restores `data/`, so
test entries never reach the real stores.

## Founding prices — and where they come from

| Offer | Founding price |
|---|---|
| TenantFix 365 scan + owner-approved fix plan | **$149 CAD** one time |
| TenantFix monitoring (re-scans on request) | **$39 CAD/month** |
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
therefore follow the **NorthCheck founding ladder** ($149 CAD
evidence pack / $39 CAD monitoring / $49 CAD subscription, all in
CAD) as deliberate introductory
hypotheses for the first cohort — labelled "founding prices" on the
site, to be confirmed or changed by those validation scans. They are
not validated prices, and no payment is collected in this build.

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
- **InsureReady is a representative sample.** The 25-question
  questionnaire models a typical Canadian SMB cyber-insurance
  evidence questionnaire; it is not a specific insurer's form, and
  wording varies by insurer and broker.
- **The change report is not monitoring.** It compares two scans
  when the second one runs; nothing is scheduled and no alert is
  emailed. Drift alerting would need the live connection plus a
  scheduler, neither of which exists yet.
- **The Google companion is younger, and its live path has named
  gaps.** Its InsureReady mapping is explicit in `google_check.py`;
  questions whose concept has no Google equivalent (IR-Q04
  Conditional Access) answer Evidence missing by design, and Drive
  evidence is domain-level settings, not file-level permission
  lists. The live connection (`google_connect.py`) is code-complete
  but inactive until the owner setup in SETUP-GOOGLE.md is done —
  and its token exchange additionally needs an RS256 signer at
  runtime (the Python standard library cannot sign; the
  `cryptography` package is used when importable, and until then
  validation reports signing as unavailable and records nothing).
  On the live path, domain Drive settings / less-secure-app /
  password policy are owner-stated or not covered, per-user mail
  forwarding is not read at all (Gmail API is outside the
  authorized scopes), and the group allows-external-members
  setting is not exposed by the Directory API — so GG-GROUP-
  EXTERNAL cannot fire live and IR-Q07 / IR-Q20 can differ from
  the export path. All three deltas are asserted in the suite.
  One scope note: `admin.directory.user.security` (the token
  inventory) has no read-only variant at Google; it can
  technically also revoke tokens, and TenantCheck only ever reads
  with it — the connect page tells customers so.
- **Checklist thresholds are code choices** (3 Global Admins, 90-day
  dormancy, 12-character passwords, ~95% EDR/encryption, 90-day
  backup-test window), named in `m365.py` for tuning during
  validation interviews — not Microsoft or insurer mandates.
- Storage is local JSON files — fine for founding-cohort volume, not
  a multi-tenant database. No user accounts. Demo verification proves
  the engine catches the problems planted in the demo snapshot; it is
  not evidence about any real tenant.
- **CopilotReady reads permission lists, not content, and not every
  permission.** The export script digests site-level and
  library-root (drive root) permission lists; sharing links attached
  to individual files or folders below that level are NOT enumerated
  (that needs a per-item crawl of every file), so a clean audit is
  not proof that no file-level link exists — the report says so. The
  audit never sees file contents, so it cannot judge sensitivity;
  the snapshot does not record Copilot licences, so findings are
  framed as exposure *if* Copilot is used (the same grants are
  readable today by the audience they name, Copilot or not); and
  whether guests may re-share is not exposed by Microsoft Graph, so
  the export writes it as null and that check stays silent. The
  live-Graph path (`graph_connect.py`) does not yet emit a
  `sharingInventory`, so Graph-connected scans currently report the
  audit as not covered.

## Files

| File | Purpose |
|---|---|
| `app.py` | The web app (stdlib only): pages, upload/scan flow, downloads, signup |
| `m365.py` | The scan engine (TenantFix / TokenWatch / InsureReady), originally copied from `../m365-cluster/`, extended in place since (InsureReady 25 questions + broker pack, TokenWatch AI view) and re-verified after every change |
| `copilot_audit.py` | CopilotReady oversharing audit: runs on the snapshot's `sharingInventory`, renders the DRAFT-stamped audit report |
| `google_check.py` | Google Workspace companion engine: GoogleFix checks, app inventory with AI view, the InsureReady adapter/mapping, DRAFT-stamped reports, planted-manifest verify (17/17) |
| `google_connect.py` | Live Google Workspace connection (domain-wide delegation): env-gated service-account config, JWT token exchange behind an injectable transport + pluggable RS256 signer, validation-before-recording, Admin SDK fetch layer building the google_check snapshot |
| `SETUP-GOOGLE.md` | Owner-only Google Cloud + Render setup for the Google live connection (service account, key handling, per-customer DWD authorization) |
| `demo_google_snapshot.json` | Fabricated Google Workspace demo domain with planted-problems manifest |
| `demo_snapshot.json` | Fabricated demo tenant with planted-problems manifest |
| `check_app.py` | Automated end-to-end verification (187 checks + engine 53/53 + Google engine 17/17) |
| `run.sh` | Start the app (PORT/HOST overridable, defaults 8795 / 127.0.0.1) |
| `tools/tenantcheck-export.ps1` | Guided export helper the customer's own admin runs (Graph SDK, read-only) |
| `tools/sample-script-output.json` | Fixture in exactly the script's output shape, uploaded by `check_app.py` |
| `data/` | Runtime JSON stores: `founding.json`, `scans.json`, `connections.json` (Microsoft tenants), `google_connections.json` (Google domains — ids, admin emails and owner-stated facts only, never keys or tokens) |
| `DEPLOY.md` | What going live still requires (not done in this build) |
