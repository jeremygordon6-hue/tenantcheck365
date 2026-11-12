#!/usr/bin/env python3
"""
TenantCheck 365 — production web app (free-tools build).

One brand over the three verified M365-cluster modules:

  * TenantFix 365   — Microsoft 365 hardening scan for small firms with
                      no IT person, plus an owner-approved fix plan.
  * TokenWatch      — OAuth grant inventory ranked by scope x dormancy
                      x consent, with unverified-publisher loading.
  * InsureReady 365 — the same scan mapped to a cyber-insurance
                      evidence pack (Supported / Gap / Evidence missing).

Stack: Python standard library only — http.server, server-rendered
HTML with inline CSS, no JavaScript frameworks, no external requests.
All checking logic is the verified prototype engine in m365.py,
imported and reused, not rewritten (the engine file is a byte-identical
copy of ../m365-cluster/m365.py, verified 40/40 on the demo snapshot).

SCAN INPUT — HONEST BY DESIGN: scans run on an EXPORTED tenant
snapshot (JSON shaped like Microsoft Graph responses) that the visitor
uploads, or on the fictional demo tenant. The live Microsoft Graph
connection code (graph_connect.py) is built but INACTIVE until the
product owner configures the app registration described in
SETUP-GRAPH.md: while the TENANTCHECK_MS_* environment variables are
absent, /connect refuses gracefully and /live-connection reports that
setup is pending. The app never collects Microsoft passwords; live
access works through an app registration plus tenant admin consent
granted by the customer's own administrator, and the client secret
exists only in an environment variable, never on disk.

Honesty rule (product requirement): TenantCheck 365 prepares evidence.
It does not certify compliance and is not legal or insurance advice.
Every finding is an issue to review; the owner makes the call. Every
report carries the engine's DRAFT stamp.
"""

import datetime
import json
import os
import re
import sys
import urllib.parse
import uuid
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m365  # the verified prototype engine (copied in byte-identical)
import graph_connect  # live Microsoft Graph connection (inactive
                      # until the TENANTCHECK_MS_* env vars are set)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
FOUNDING_PATH = os.path.join(DATA_DIR, "founding.json")
SCANS_PATH = os.path.join(DATA_DIR, "scans.json")
DEMO_SNAPSHOT_PATH = os.path.join(APP_DIR, "demo_snapshot.json")
EXPORT_SCRIPT_PATH = os.path.join(APP_DIR, "tools",
                                  "tenantcheck-export.ps1")

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8795"))

MAX_UPLOAD = 6_000_000    # bytes; tenant snapshots are small JSON files

PRODUCT = "TenantCheck 365"
HONESTY_LINE = ("TenantCheck 365 prepares evidence. It does not certify "
                "compliance and is not legal or insurance advice.")

REQUIRED_LIST_SECTIONS = ("users", "inboxRules", "oauthGrants")
REQUIRED_DICT_SECTIONS = ("tenantSettings", "securityControls")

# ---------------------------------------------------------------------------
# JSON stores (created at runtime)
# ---------------------------------------------------------------------------

def _load(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return default
    return default


def _save(path, data):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)


def load_list(path):
    data = _load(path, [])
    return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# Styling — inline CSS only, no external resources
# ---------------------------------------------------------------------------

CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial,
       sans-serif; margin: 0; color: #1c2430; background: #f6f7f9;
       line-height: 1.55; }
header.site { background: #14304d; color: #fff; padding: 14px 20px; }
header.site a { color: #fff; text-decoration: none; font-weight: 700;
                font-size: 1.25rem; }
header.site nav { float: right; }
header.site nav a { font-size: .95rem; font-weight: 400; margin-left: 16px; }
main { max-width: 880px; margin: 0 auto; padding: 24px 20px 60px; }
h1 { font-size: 1.9rem; line-height: 1.25; margin: .4em 0 .3em; }
h2 { margin-top: 1.6em; }
.deadline { background: #fff3cd; border: 1px solid #e0c25e;
            border-radius: 8px; padding: 14px 18px; margin: 18px 0; }
.card { background: #fff; border: 1px solid #dde1e6; border-radius: 8px;
        padding: 18px 20px; margin: 16px 0; }
.badge { display: inline-block; background: #e8eef7; color: #274b73;
         border-radius: 999px; padding: 1px 10px; font-size: .8rem;
         margin-left: 8px; vertical-align: middle; }
form label { display: block; font-weight: 600; margin: 14px 0 4px; }
input[type=text], input[type=url], input[type=email], input[type=date],
input[type=file], textarea { width: 100%; padding: 9px 10px;
           border: 1px solid #b9c0c9; border-radius: 6px; font: inherit;
           background: #fff; }
textarea { min-height: 220px; }
button, .btn { background: #14304d; color: #fff; border: 0;
               border-radius: 6px; padding: 10px 18px; font: inherit;
               cursor: pointer; text-decoration: none; display: inline-block;
               margin-top: 16px; }
button:hover, .btn:hover { background: #1e4a73; }
.sev { display: inline-block; border-radius: 4px; padding: 0 8px;
       font-size: .8rem; font-weight: 700; text-transform: uppercase; }
.sev-critical { background: #7a1f28; color: #fff; }
.sev-high { background: #f8d7da; color: #7a1f28; }
.sev-medium { background: #fff3cd; color: #7a5b00; }
.sev-low { background: #d1ecf1; color: #0c5460; }
.status { display: inline-block; border-radius: 4px; padding: 0 8px;
          font-size: .8rem; font-weight: 700; }
.status-supported { background: #d4edda; color: #155724; }
.status-gap { background: #f8d7da; color: #7a1f28; }
.status-missing { background: #fff3cd; color: #7a5b00; }
.flagged { background: #fdf0f0; }
.finding { border-left: 4px solid #b9c0c9; padding: 6px 0 6px 14px;
           margin: 14px 0; }
.finding p { margin: 4px 0; }
code, .evidence { font-family: ui-monospace, Menlo, Consolas, monospace;
                  font-size: .88rem; background: #f1f3f5; padding: 1px 5px;
                  border-radius: 4px; word-break: break-all; }
pre.sample { font-family: ui-monospace, Menlo, Consolas, monospace;
             font-size: .82rem; background: #f1f3f5; padding: 12px;
             border-radius: 6px; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; background: #fff; }
th, td { border: 1px solid #dde1e6; padding: 8px 10px; text-align: left;
         vertical-align: top; }
th { background: #f1f3f5; }
.notice { background: #eef4fb; border: 1px solid #b8cfe4; border-radius: 8px;
          padding: 12px 16px; margin: 16px 0; }
footer.site { max-width: 880px; margin: 0 auto; padding: 0 20px 40px;
              color: #5a6572; font-size: .9rem; }
.small { color: #5a6572; font-size: .9rem; }
"""


def page(title, body):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} — {PRODUCT}</title>
<style>{CSS}</style>
</head>
<body>
<header class="site">
  <a href="/">{PRODUCT}</a>
  <nav>
    <a href="/scan">Run a scan</a>
    <a href="/how-to-export">How to export</a>
    <a href="/live-connection">Live connection</a>
    <a href="/connect">Connect</a>
  </nav>
</header>
<main>
{body}
</main>
<footer class="site">
  <p>{HONESTY_LINE}</p>
</footer>
</body>
</html>
"""


def error_page(title, message):
    return page(title, f"""
<h1>{escape(title)}</h1>
<div class="notice">{escape(message)}</div>
<p><a href="/scan">Back to the scan page</a> ·
<a href="/">Back to {PRODUCT}</a></p>
""")


# ---------------------------------------------------------------------------
# Landing page
# ---------------------------------------------------------------------------

def landing_page(joined=False):
    thanks = ('<div class="notice">Thanks — you are on the founding list. '
              'We will write when the founding cohort opens.</div>') \
        if joined else ""
    body = f"""
<h1>Your Microsoft 365, checked before an attacker — or an insurer —
checks it.</h1>
<p>{PRODUCT} is a Microsoft 365 security check for small firms with no
IT person. Most small tenants run on setup defaults: no MFA on some
accounts, old sign-in protocols still on, third-party apps holding mail
access nobody remembers approving. One scan of your tenant produces a
fix plan you approve step by step, a ranked list of risky app grants,
and an evidence pack your cyber-insurance renewal can actually use.</p>

<div class="deadline">
  <strong>Why now:</strong> insurers have stopped accepting "yes, we
  have MFA" as an answer — renewals now ask for configuration
  <em>evidence</em>, and answers given on the form are treated as fact
  if there is ever a claim. Knowing your real state before renewal is
  the difference between evidence and a guess.
</div>

<h2>How it works</h2>
<div class="card">
  <p><strong>1. Export</strong> — your tenant's settings are exported
  as one JSON file shaped like Microsoft's own admin data.
  <a href="/how-to-export">See exactly where each part comes from</a>,
  or skip straight to the demo below.</p>
  <p><strong>2. Upload</strong> — the scan runs on the export. No
  Microsoft sign-in, no password, nothing installed.</p>
  <p><strong>3. Review</strong> — you get the three reports below, each
  dated and DRAFT-stamped. Fixes are a plan for your approval, never
  applied behind your back.</p>
  <p class="small">A live connection that skips the export is the next
  step — it needs an app registration and consent from your own admin.
  <a href="/live-connection">How that will work</a>.</p>
</div>

<div class="card">
  <h2>TenantFix 365 <span class="badge">Module 1 — live</span></h2>
  <p>The hardening scan: accounts without MFA (admins flagged critical),
  legacy authentication still enabled, inbox rules quietly forwarding
  mail outside the business, anonymous file sharing, too many Global
  Administrators, dormant admin accounts, broad guest access, and weak
  password policy. Every finding comes with the reason it matters and
  the exact fix steps, as an owner-approved fix plan.</p>
  <p><strong>Founding price: $149</strong> one time for the scan and
  fix plan · <strong>$39/month</strong> monitoring with re-scan alerts.</p>
  <a class="btn" href="/scan">Run a scan</a>
  <a class="btn" href="https://buy.stripe.com/00w9AMaJj76fbCu6AQ5Rm03">Buy the scan — $149</a>
  <a class="btn" href="https://buy.stripe.com/9B66oAg3DgGP0XQ7EU5Rm04">Add monitoring — $39/month</a>
</div>

<div class="card">
  <h2>TokenWatch <span class="badge">Module 2 — live</span></h2>
  <p>Every third-party app your people have connected to Microsoft 365
  keeps the access it was granted — often mail and file access — long
  after everyone forgot it. TokenWatch inventories every OAuth grant
  and ranks it by what it can reach, how long it has sat unused, and
  whether one user approved it alone, with extra weight on unverified
  publishers. These grants bypass MFA entirely.</p>
  <p>Included in the bundle below.</p>
</div>

<div class="card">
  <h2>InsureReady 365 <span class="badge">Module 3 — live</span></h2>
  <p>Thirteen questions a typical Canadian cyber-insurance renewal
  asks — MFA, legacy auth, EDR coverage, tested backups, admin limits,
  training, incident response — each answered <em>Supported</em>,
  <em>Gap</em>, or <em>Evidence missing</em> from the same scan, with
  the evidence attached. Where the tenant data cannot support an
  answer, the pack says so instead of guessing.</p>
  <p>Included in the bundle below.</p>
</div>

<div class="card">
  <h2>The bundle <span class="badge">All three modules</span></h2>
  <p>TenantFix + TokenWatch + InsureReady on one tenant scan engine,
  with scheduled re-scans so the state you attested to stays true
  between renewals.</p>
  <p><strong>Founding price: $49/month</strong> for the full bundle.</p>
  <a class="btn" href="https://buy.stripe.com/9B600cdVv1LV9umgbq5Rm05">Subscribe — $49/month</a>
  <p class="small">Founding prices are the introductory prices for the
  first cohort, and checkout is open now. Join the list below and
  founding pricing is locked for you.</p>
</div>

<div class="card">
  <h2>See it on a demo tenant first</h2>
  <p>The demo runs the full scan on a fictional 18-person bookkeeping
  firm with real problems planted in it — no MFA on three accounts
  including an admin, an inbox rule forwarding invoices to an outside
  address, and a forgotten app with mail access unused for 210 days.
  Same engine, same reports, zero risk.</p>
  <form method="post" action="/scan/demo">
    <button type="submit">Run the demo scan</button>
  </form>
</div>

<div class="card">
  <h2>Join the founding list</h2>
  <p>Leave your details and we will write when the founding cohort
  opens. No email is sent by this form — it only records your details
  for the launch note.</p>
  {thanks}
  <form method="post" action="/founding">
    <label for="name">Your name</label>
    <input type="text" id="name" name="name" required
           placeholder="Alex Owner">
    <label for="email">Email address</label>
    <input type="email" id="email" name="email" required
           placeholder="you@yourbusiness.ca">
    <label for="company">Company</label>
    <input type="text" id="company" name="company"
           placeholder="Your Business Inc.">
    <button type="submit">Join the founding list</button>
  </form>
</div>

<p class="small">{HONESTY_LINE} Every finding is an issue to review,
found by deterministic checks — never a certification.</p>
"""
    return page("Microsoft 365 security, checked", body)


# ---------------------------------------------------------------------------
# Scan pages
# ---------------------------------------------------------------------------

def scan_page(error=None):
    err = f'<div class="notice">{escape(error)}</div>' if error else ""
    body = f"""
<h1>Run a scan</h1>
<p>Upload an exported tenant snapshot (one JSON file) and {PRODUCT}
runs all three modules on it: TenantFix hardening findings, the
TokenWatch grant ranking, and the InsureReady evidence pack. The
snapshot is stored only as your scan record on this server, so your
reports stay downloadable.</p>
{err}
<div class="card">
  <h2>Upload your tenant export</h2>
  <form method="post" action="/scan/upload" enctype="multipart/form-data">
    <label for="snapshot">Tenant snapshot JSON file</label>
    <input type="file" id="snapshot" name="snapshot" accept=".json,application/json" required>
    <button type="submit">Run the scan</button>
  </form>
  <p class="small">Not sure what the file should look like?
  <a href="/how-to-export">How to export</a> explains where every part
  of the snapshot comes from. This site never asks for your Microsoft
  username or password, and there is no Microsoft sign-in here.</p>
</div>
<div class="card">
  <h2>Or run the demo tenant</h2>
  <p>The full scan on a fictional firm with planted problems — the
  fastest way to see exactly what the reports look like.</p>
  <form method="post" action="/scan/demo">
    <button type="submit">Run the demo scan</button>
  </form>
</div>
<p class="small">{HONESTY_LINE}</p>
"""
    return page("Run a scan", body)


def export_page():
    body = f"""
<h1>How to export your tenant snapshot</h1>
<p>The scan runs on one JSON file: a snapshot of your Microsoft 365
tenant's settings, shaped like the responses of Microsoft's own
Microsoft Graph API. It contains settings and account facts — never
email contents, never passwords. There are two ways to produce it.
Option A is the guided path and takes about 10 minutes. Option B is
the manual assembly it replaced, kept as a fallback. Either way,
nothing connects to your tenant from this site — the
<a href="/live-connection">live connection</a> is a separate, later
step.</p>

<div class="card">
  <h2>Option A — run the export script (about 10 minutes)</h2>
  <p>A small PowerShell script runs on <strong>your own
  computer</strong>, signed in with <strong>your own admin
  account</strong>. It reads the tenant settings the scan needs
  through Microsoft's official Graph PowerShell tools, asks you the
  handful of questions only you can answer, and writes one file,
  <code>tenantcheck-snapshot.json</code>. The script sends nothing
  anywhere — you upload the file yourself in step 5.</p>
  <p><a class="btn" href="/export-script">Download the export script
  (tenantcheck-export.ps1)</a></p>
  <p><strong>1. What you need.</strong> A Windows computer, an admin
  account for your own tenant (Global Administrator, or Global Reader
  with reports access), and Microsoft's free Graph PowerShell module.
  If the module is missing, the script stops and prints the one
  install command — nothing to install from us.</p>
  <p><strong>2. Run it.</strong> Save the download, open PowerShell in
  that folder, and run:
  <code>powershell -ExecutionPolicy Bypass -File
  .\tenantcheck-export.ps1</code>. The Bypass flag applies to this
  one run only; the script itself is plain text and you can read
  every line before running it.</p>
  <p><strong>3. Sign in — to Microsoft, not to us.</strong> A
  Microsoft sign-in window opens. You sign in with your own admin
  account and approve a fixed list of <strong>read-only</strong>
  permissions: user and directory reads, role assignments, policy
  reads, the MFA registration report, sign-in activity, app consent
  records, and inbox <em>rule definitions</em> (rule settings such as
  forwarding targets — the script never reads message contents). The
  script never sees, stores, or sends your password; no permission in
  the list can change anything in your tenant.</p>
  <p><strong>4. Answer the questions only you can answer.</strong>
  Some insurance questions are about your devices and documents, not
  tenant settings: backup restore tests, security training, a written
  incident plan. The script asks for those directly. Pressing Enter
  for "don't know" is a real answer — the scan then shows a gap to
  review for that item instead of a pass, and the script lists every
  default it used before it finishes.</p>
  <p><strong>5. Upload the file.</strong> The script writes
  <code>tenantcheck-snapshot.json</code> next to itself. Upload it on
  the <a href="/scan">scan page</a> and review your three reports.
  Fixes are listed as steps in an owner-approved plan; this tool
  applies nothing.</p>
  <p class="small">Two honest limits of the script: Microsoft does not
  expose when each third-party app grant was last used, so grants are
  scored without a dormancy guess; and it cannot see how broadly a
  guest account can reach, so guests are never flagged on a guess —
  both facts are stated in the script itself.</p>
</div>

<div class="card">
  <h2>Option B — assemble the export manually</h2>
  <p>If you would rather build the file by hand, the snapshot is one
  JSON object with the sections below. The demo tenant on this site
  is a complete example of the exact shape — run the demo scan and
  download its reports to see the format end to end.</p>
  <table>
    <tr><th>Snapshot section</th><th>What it holds</th>
        <th>Where it comes from</th></tr>
    <tr><td><code>users</code></td>
        <td>Accounts, enabled state, MFA registration, directory roles,
            guest status, last sign-in</td>
        <td>Microsoft Entra ID — Graph <code>/users</code>, the
            authentication methods registration report, and directory
            role assignments</td></tr>
    <tr><td><code>inboxRules</code></td>
        <td>Per-mailbox inbox rules, including any forwarding or
            redirect targets (rule settings, not message contents)</td>
        <td>Exchange — Graph inbox message rules per mailbox, or the
            Exchange admin rule reports</td></tr>
    <tr><td><code>tenantSettings</code></td>
        <td>Legacy authentication state, external sharing level,
            password policy</td>
        <td>Conditional Access / authentication policies, SharePoint
            admin sharing settings, domain password policy</td></tr>
    <tr><td><code>oauthGrants</code></td>
        <td>Third-party app consents: app name, scopes granted, who
            consented, publisher verification, last use</td>
        <td>Enterprise applications — Graph OAuth2 permission grants
            and service principals</td></tr>
    <tr><td><code>securityControls</code></td>
        <td>Conditional Access policy count, EDR and encryption
            coverage, backup state, training currency, incident
            response plan</td>
        <td>Secure Score / Defender reports for the measurable parts.
            A few items — backup restore tests, training, a written
            incident plan — are facts only you can state; the snapshot
            records what you state, and anything unstated is reported
            as <em>evidence missing</em>, never assumed</td></tr>
  </table>
  <p>The shape, trimmed down, looks like this:</p>
  <pre class="sample">{{"users": [{{"userPrincipalName": "alex@yourbusiness.ca",
              "accountEnabled": true, "mfaRegistered": true,
              "roles": [], "accountType": "member"}}],
 "tenantSettings": {{"legacyAuthenticationEnabled": false,
              "externalSharingCapability": "ExistingExternalUserSharingOnly"}},
 "inboxRules": [], "oauthGrants": [], "securityControls": {{...}}}}</pre>
</div>

<div class="notice">
  <strong>What we will never ask for:</strong> your Microsoft username
  or password. There is no Microsoft sign-in anywhere in this app, by
  design. Anyone asking for your Microsoft password "for a scan" is
  not us.
</div>
<p class="small">{HONESTY_LINE}</p>
"""
    return page("How to export your tenant snapshot", body)


def live_connection_page():
    cfg = graph_connect.config()
    if cfg["scan_ready"]:
        status = f"""
<div class="deadline">
  <strong>Status, plainly:</strong> setup is complete on this server —
  the app registration is configured, so the live connection is
  switched on. A tenant is connected only when its own Global
  Administrator grants consent on the
  <a href="/connect">connect page</a>; until that moment we can see
  nothing of it. The export path (<a href="/how-to-export">how that
  works</a>) remains available.
</div>
<p>Uploading an export works, but it is a snapshot of one day. The
monitoring offer — re-scans that catch a new risky app grant or an MFA
change between insurance renewals — needs a standing, read-only
connection. This is exactly what the connection requires:</p>"""
    else:
        remaining = "".join(
            f"<li><code>{escape(name)}</code></li>"
            for name in cfg["missing_config"])
        status = f"""
<div class="deadline">
  <strong>Status, plainly:</strong> setup is pending. The live
  connection code is built, but it is <strong>not switched on</strong>
  in this version because the app registration is not configured on
  this server yet. {PRODUCT} runs today on an uploaded export
  (<a href="/how-to-export">how that works</a>) — nothing on this site
  connects to your tenant, and nothing here can.
  <p>What remains, on the product owner's side:</p>
  <ol>
    <li>Register the app in Microsoft Entra ID (an Azure app
    registration) with the redirect URI
    <code>https://tenantcheck365.ca/connect/callback</code>.</li>
    <li>Create a client secret on that registration.</li>
    <li>Add these environment variables on the host (Render) and
    restart the service:
    <ul>{remaining}</ul></li>
  </ol>
  <p>Until then, the <a href="/connect">connect page</a> stays off and
  says the same thing this page does.</p>
</div>
<p>Uploading an export works, but it is a snapshot of one day. The
monitoring offer — re-scans that catch a new risky app grant or an MFA
change between insurance renewals — needs a standing, read-only
connection. This is exactly what that connection will require, so you
can judge it before it exists:</p>"""
    body = f"""
<h1>The live connection — how it works</h1>
{status}

<div class="card">
  <h2>Step 1 — we register the app</h2>
  <p>{PRODUCT} is registered as an application in Microsoft Entra ID
  (an Azure app registration) with a fixed, published list of
  <strong>read-only</strong> permissions: directory and role reads,
  policy reads, app-consent reads, and rule <em>settings</em>. No mail
  contents, no write permissions.</p>
</div>
<div class="card">
  <h2>Step 2 — your admin consents, not us</h2>
  <p>A Global Administrator <strong>from your own firm</strong> opens a
  Microsoft consent screen, sees the exact permission list, and grants
  or refuses tenant admin consent. Consent cannot be granted by us,
  by a salesperson, or by a regular user — Microsoft reserves it for
  your admin, deliberately. Until that moment, we can see nothing.</p>
</div>
<div class="card">
  <h2>Step 3 — the same scan, automatically</h2>
  <p>With consent in place, the app builds the same snapshot the export
  produces today and runs the identical checks — same engine, same
  reports. Monitoring re-runs it on schedule and alerts on change.</p>
</div>
<div class="card">
  <h2>Step 4 — you can revoke it any time</h2>
  <p>Consent is withdrawn in Entra ID under Enterprise applications in
  about a minute, by your admin, without asking us. Revoking ends all
  access immediately.</p>
</div>

<div class="notice">
  <strong>Standing rules, live or not:</strong> we never collect or
  store Microsoft passwords — there is no password field anywhere in
  this product. Fixes are never applied without the owner's approval
  of each step; a read-only connection cannot apply them anyway.
</div>
<p class="small">{HONESTY_LINE}</p>
"""
    return page("The live connection", body)


# ---------------------------------------------------------------------------
# Live connection pages — admin consent flow (graph_connect.py)
# ---------------------------------------------------------------------------

def connect_page(message=None):
    cfg = graph_connect.config()
    notice = (f'<div class="notice">{escape(message)}</div>'
              if message else "")
    if not cfg["consent_ready"]:
        remaining = "".join(
            f"<li><code>{escape(name)}</code></li>"
            for name in cfg["missing_config"])
        body = f"""
<h1>Connect your tenant</h1>
{notice}
<div class="deadline">
  <strong>Setup is pending.</strong> The live connection is switched
  off until the product owner finishes the app registration on this
  server, so this page cannot start a consent and nothing has been
  sent to Microsoft. What remains:
  <ul>{remaining}</ul>
  See <a href="/live-connection">how the live connection works</a>
  for the full picture. In the meantime the
  <a href="/scan">export-based scan</a> works exactly as before.
</div>
<p class="small">{HONESTY_LINE}</p>
"""
        return page("Connect your tenant", body)

    consent_url, _state = graph_connect.admin_consent_url()
    permissions = "".join(
        f"<li>{escape(p)}</li>"
        for p in graph_connect.READ_ONLY_PERMISSIONS)
    connections = graph_connect.load_connections()
    if connections:
        rows = []
        for conn in connections:
            tenant_id = escape(conn.get("tenant_id", ""))
            scan_control = ""
            if cfg["scan_ready"]:
                scan_control = f"""
  <form method="post" action="/connect/scan">
    <input type="hidden" name="tenant_id" value="{tenant_id}">
    <button type="submit">Run a live scan for this tenant</button>
  </form>"""
            rows.append(f"""
<div class="card">
  <p>Tenant: <code>{tenant_id}</code><br>
  Consent recorded: {escape(conn.get('consented_at', ''))}</p>
  {scan_control}
</div>""")
        connected_html = "<h2>Connected tenants</h2>" + "".join(rows)
    else:
        connected_html = ("<h2>Connected tenants</h2>"
                          "<p>None yet. The first tenant appears here "
                          "after its own admin grants consent.</p>")
    if not cfg["scan_ready"]:
        connected_html += ('<div class="notice">Consent can be '
                           'recorded now, but live scans also need '
                           '<code>TENANTCHECK_MS_CLIENT_SECRET</code> '
                           'to be configured on this server.</div>')
    body = f"""
<h1>Connect your tenant</h1>
{notice}
<p>Connecting takes one step on Microsoft's own site: a Global
Administrator <strong>from your firm</strong> opens the consent screen,
sees the exact read-only permission list below, and grants or refuses.
We cannot grant it, pre-approve it, or see anything before that
moment.</p>
<div class="card">
  <h2>The permissions your admin will see</h2>
  <ul>{permissions}</ul>
  <p>All read-only. No mail contents, no write permissions. Consent
  can be revoked by your admin in Entra ID at any time, without asking
  us.</p>
  <a class="btn" href="{escape(consent_url, quote=True)}">Connect a tenant with Microsoft admin consent</a>
</div>
{connected_html}
<p class="small">{HONESTY_LINE}</p>
"""
    return page("Connect your tenant", body)


def connect_callback_page(outcome):
    status, detail = outcome
    if status == "recorded":
        body = f"""
<h1>Consent recorded</h1>
<div class="notice">Consent recorded for tenant
<code>{escape(detail.get('tenant_id', ''))}</code> at
{escape(detail.get('consented_at', ''))}. The tenant is now listed on
the <a href="/connect">connect page</a>, where a live scan can be run
for it.</div>
<p class="small">{HONESTY_LINE}</p>
"""
    elif status == "not_configured":
        body = f"""
<h1>Setup is pending</h1>
<div class="notice">{escape(detail)} Nothing was recorded.</div>
<p><a href="/live-connection">How the live connection works</a></p>
"""
    else:
        body = f"""
<h1>Consent not recorded</h1>
<div class="notice">{escape(detail)} Nothing was recorded. You can
start again from the <a href="/connect">connect page</a>.</div>
<p class="small">{HONESTY_LINE}</p>
"""
    return page("Connect your tenant", body)


def connect_incomplete_page(tenant_id, missing, warnings):
    items = "".join(f"<li><code>{escape(m)}</code></li>"
                    for m in missing)
    warns = ""
    if warnings:
        warns = ("<p>Also noted while reading the tenant:</p><ul>"
                 + "".join(f"<li>{escape(w)}</li>" for w in warnings)
                 + "</ul>")
    body = f"""
<h1>Live scan not run yet</h1>
<div class="notice">The connection returned everything Microsoft
Graph can supply for tenant <code>{escape(tenant_id)}</code>, but the
scan has <strong>not</strong> been run: these owner-stated items are
still missing, and {PRODUCT} reports evidence missing instead of
guessing values for them.</div>
<ul>{items}</ul>
{warns}
<p>These are the same facts the export path asks the owner to state in
the snapshot (backup state, EDR and encryption coverage, training, the
incident response plan, the password policy). Once they are recorded
on the connection, the live scan runs the identical checks.</p>
<p><a href="/connect">Back to the connect page</a></p>
"""
    return page("Live scan not run yet", body)


# ---------------------------------------------------------------------------
# Snapshot handling — validation, demo metadata shim, engine run + store
# ---------------------------------------------------------------------------

def validate_snapshot(snap):
    """Return a plain-English problem string, or None if scannable."""
    if not isinstance(snap, dict):
        return "That file is not a snapshot object. Upload the JSON " \
               "tenant export described on the How to export page."
    missing = [k for k in REQUIRED_LIST_SECTIONS + REQUIRED_DICT_SECTIONS
               if k not in snap]
    if missing:
        return ("That snapshot is missing section(s): "
                + ", ".join(missing)
                + ". See the How to export page for what each section "
                  "holds.")
    for key in REQUIRED_LIST_SECTIONS:
        if not isinstance(snap[key], list):
            return f"The '{key}' section must be a list."
    for key in REQUIRED_DICT_SECTIONS:
        if not isinstance(snap[key], dict):
            return f"The '{key}' section must be an object."
    if not snap["users"]:
        return "That snapshot lists no user accounts, so there is " \
               "nothing to scan."
    return None


def with_meta(snap, source):
    """Ensure the snapshot carries the _meta block the report renderer
    reads. Demo snapshots ship with a full fictional _meta; uploaded
    exports may not, so a truthful one is synthesised from the tenant
    itself. The engine file is not modified."""
    snap = dict(snap)
    if source == "demo":
        return snap
    meta = dict(snap.get("_meta") or {})
    try:
        domain = m365.tenant_domain(snap)
    except Exception:
        domain = ""
    meta["firm_name"] = meta.get("firm_name") or domain \
        or "Uploaded tenant"
    meta["snapshot_date"] = meta.get("snapshot_date") \
        or datetime.date.today().isoformat()
    if source == "graph":
        meta["label"] = ("Live Microsoft Graph connection, read with "
                         "the tenant admin's consent. Findings cover "
                         "only what the connection returned.")
    else:
        meta["label"] = ("Uploaded tenant export, scanned exactly as "
                         "provided. Findings cover only what the export "
                         "contains.")
    snap["_meta"] = meta
    return snap


def run_and_store(snap, source):
    snap = with_meta(snap, source)
    norm, tf, tw, ir = m365.run_scan(snap)
    record = {
        "id": uuid.uuid4().hex[:12],
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "source": source,
        "firm": snap["_meta"]["firm_name"],
        "snapshot_date": snap["_meta"]["snapshot_date"],
        "summary": {
            "tenantfix_findings": len(tf),
            "tokenwatch_grants": len(tw),
            "tokenwatch_flagged": sum(1 for i in tw if i["flagged"]),
            "insureready_questions": len(ir),
            "insureready_gaps": sum(1 for r in ir
                                     if r["status"] != "Supported"),
        },
        "tenantfix": tf,
        "tokenwatch": tw,
        "insureready": ir,
        "reports": {
            "tenantfix": m365.render_tenantfix(snap, tf),
            "tokenwatch": m365.render_tokenwatch(snap, tw),
            "insureready": m365.render_insureready(snap, ir),
        },
    }
    scans = load_list(SCANS_PATH)
    scans.append(record)
    _save(SCANS_PATH, scans)
    return record


def load_scan(scan_id):
    return next((s for s in load_list(SCANS_PATH)
                 if s.get("id") == scan_id), None)


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def tenantfix_html(findings):
    if not findings:
        return "<p>No hardening findings. That means none of the " \
               "deterministic checks matched — it is not a guarantee " \
               "the tenant is secure.</p>"
    out = []
    for f in sorted(findings, key=lambda x: SEV_ORDER[x["severity"]]):
        steps = "".join(f"<li>{escape(s)}</li>" for s in f["fix_steps"])
        out.append(f"""
<div class="finding">
  <p><span class="sev sev-{f['severity'].lower()}">{f['severity']}</span>
     <strong>{escape(f['title'])}</strong></p>
  <p class="small">Check: {escape(f['check'])} ·
     Subject: {escape(f['subject'])}</p>
  <p>Why it matters: {escape(f['why'])}</p>
  <p>Fix steps:</p>
  <ol>{steps}</ol>
</div>""")
    return "".join(out)


def tokenwatch_html(inventory):
    rows = []
    for i in inventory:
        flag = ('<span class="status status-gap">Flagged</span>'
                if i["flagged"] else
                '<span class="status status-supported">OK</span>')
        reasons = ("<br><span class=\"small\">"
                   + escape("; ".join(i["flag_reasons"])) + "</span>"
                   ) if i["flag_reasons"] else ""
        last = i["last_used_days_ago"]
        last_txt = "unknown" if last is None else f"{last} days ago"
        rows.append(f"""
<tr{' class="flagged"' if i['flagged'] else ''}>
  <td><strong>{escape(i['app'])}</strong>{reasons}</td>
  <td>{i['risk']}</td>
  <td>{flag}</td>
  <td>{escape(', '.join(i['scopes']))}</td>
  <td>{last_txt}</td>
  <td>{escape(i['consent_type'])}</td>
  <td>{'Yes' if i['publisher_verified'] else 'No'}</td>
</tr>""")
    return f"""
<table>
  <tr><th>App</th><th>Risk</th><th>Status</th><th>Scopes</th>
      <th>Last used</th><th>Consent</th><th>Publisher verified</th></tr>
  {''.join(rows)}
</table>"""


def insureready_html(rows):
    out = []
    cls = {"Supported": "status-supported", "Gap": "status-gap",
           "Evidence missing": "status-missing"}
    for r in rows:
        gap = (f"<p>Gap: {escape(r['gap'])}</p>" if r["gap"] else "")
        out.append(f"""
<div class="finding">
  <p><span class="status {cls[r['status']]}">{r['status']}</span>
     <strong>{escape(r['id'])} — {escape(r['question'])}</strong></p>
  <p>{escape(r['evidence'])}</p>
  {gap}
</div>""")
    return "".join(out)


def results_page(record):
    s = record["summary"]
    src = {"demo": "fictional demo tenant",
           "graph": "live Microsoft Graph connection"}.get(
               record["source"], "uploaded tenant export")
    body = f"""
<h1>Scan results</h1>
<p>Tenant: <strong>{escape(record['firm'])}</strong> ({src})<br>
Snapshot date: {escape(record['snapshot_date'])} ·
Scanned: {escape(record['timestamp'])}</p>

<div class="card">
  <h2>The headline numbers</h2>
  <table>
    <tr><th>Module</th><th>Result</th></tr>
    <tr><td>TenantFix 365</td>
        <td><strong>{s['tenantfix_findings']} hardening findings</strong>
            in the fix plan</td></tr>
    <tr><td>TokenWatch</td>
        <td><strong>{s['tokenwatch_flagged']} of {s['tokenwatch_grants']} app grants flagged</strong> by risk</td></tr>
    <tr><td>InsureReady 365</td>
        <td><strong>{s['insureready_gaps']} of {s['insureready_questions']} insurance questions</strong> are gaps or missing evidence</td></tr>
  </table>
  <p>
    <a class="btn" href="/report/{record['id']}/tenantfix">Download the TenantFix report</a>
    <a class="btn" href="/report/{record['id']}/tokenwatch">Download the TokenWatch report</a>
    <a class="btn" href="/report/{record['id']}/insureready">Download the InsureReady evidence pack</a>
  </p>
  <p class="small">All three downloads are Markdown reports carrying
  the DRAFT stamp below.</p>
</div>

<div class="card">
  <h2>TenantFix 365 — owner-approved fix plan</h2>
  <p>{escape(m365.FIX_PLAN_NOTE)}</p>
  {tenantfix_html(record['tenantfix'])}
</div>

<div class="card">
  <h2>TokenWatch — OAuth grant risk inventory</h2>
  <p>Risk = scope sensitivity × dormancy × consent type, with a loading
  for unverified publishers. Ranked highest risk first.</p>
  {tokenwatch_html(record['tokenwatch'])}
</div>

<div class="card">
  <h2>InsureReady 365 — insurance evidence</h2>
  <p>A representative Canadian SMB cyber-insurance questionnaire
  answered from this scan's evidence — not a specific insurer's form.</p>
  {insureready_html(record['insureready'])}
</div>

<div class="card">
  <h2>Honesty note</h2>
  <p>Every item above is an issue to review, found by deterministic
  checks against the snapshot provided. A finding is not a
  determination about the tenant, and an empty findings list would not
  be a guarantee of security either. Anything the snapshot does not
  contain is reported as evidence missing, never assumed. The owner
  reviews the evidence and makes the calls.</p>
  <p class="small">{escape(m365.STAMP)}</p>
</div>
"""
    return page("Scan results", body)


# ---------------------------------------------------------------------------
# Multipart parsing (stdlib only, for the snapshot file upload)
# ---------------------------------------------------------------------------

def parse_multipart(body, content_type):
    """Minimal multipart/form-data parser: returns {field_name: bytes}.
    Sufficient for one file field plus plain fields; file contents are
    returned raw and decoded by the caller."""
    match = re.search(r"boundary=([^;]+)", content_type or "")
    if not match:
        return {}
    boundary = match.group(1).strip().strip('"')
    delim = b"--" + boundary.encode("utf-8", "replace")
    fields = {}
    for part in body.split(delim):
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"--"):
            part = part[:-2]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        if not part:
            continue
        head, sep, content = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        disposition = ""
        for line in head.decode("utf-8", "replace").split("\r\n"):
            if line.lower().startswith("content-disposition:"):
                disposition = line
        name_match = re.search(r'name="([^"]+)"', disposition)
        if name_match:
            fields[name_match.group(1)] = content
    return fields


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

REPORT_FILES = {
    "tenantfix": ("tenantfix_report", "TenantFix 365 report"),
    "tokenwatch": ("tokenwatch_report", "TokenWatch report"),
    "insureready": ("insureready_evidence_pack",
                    "InsureReady 365 evidence pack"),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "TenantCheck365/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(),
                                        fmt % args))

    # -- helpers ----------------------------------------------------------

    def _send(self, status, body, content_type="text/html; charset=utf-8",
              extra_headers=None):
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)

    def _redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _form(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        parsed = urllib.parse.parse_qs(raw)
        return {k: v[0] for k, v in parsed.items()}

    def _not_found(self):
        self._send(404, error_page(
            "Not found",
            "That page does not exist."))

    # -- routes -----------------------------------------------------------

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/":
            joined = query.get("joined", [""])[0] == "1"
            self._send(200, landing_page(joined=joined))
        elif path == "/scan":
            self._send(200, scan_page())
        elif path == "/how-to-export":
            self._send(200, export_page())
        elif path == "/export-script":
            if not os.path.exists(EXPORT_SCRIPT_PATH):
                self._not_found()
            else:
                with open(EXPORT_SCRIPT_PATH, "rb") as fh:
                    script = fh.read()
                self._send(
                    200, script,
                    content_type="text/plain; charset=utf-8",
                    extra_headers={
                        "Content-Disposition":
                            'attachment; '
                            'filename="tenantcheck-export.ps1"'})
        elif path == "/live-connection":
            self._send(200, live_connection_page())
        elif path == "/connect":
            self._send(200, connect_page(
                message=query.get("msg", [""])[0] or None))
        elif path == "/connect/callback":
            flat = {k: v[0] for k, v in query.items()}
            self._send(200, connect_callback_page(
                graph_connect.handle_callback(flat)))
        elif path.startswith("/results/"):
            record = load_scan(path[len("/results/"):])
            if record is None:
                self._not_found()
            else:
                self._send(200, results_page(record))
        elif path.startswith("/report/"):
            bits = path[len("/report/"):].split("/")
            record = load_scan(bits[0]) if bits else None
            module = bits[1] if len(bits) > 1 else ""
            if record is None or module not in REPORT_FILES:
                self._not_found()
            else:
                stem, _label = REPORT_FILES[module]
                self._send(
                    200, record["reports"][module],
                    content_type="text/markdown; charset=utf-8",
                    extra_headers={
                        "Content-Disposition":
                            f'attachment; filename="tenantcheck365_'
                            f'{stem}_{record["id"]}.md"'})
        else:
            self._not_found()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/scan/upload":
            self._handle_upload()
            return
        form = self._form()
        if path == "/connect/scan":
            self._handle_connect_scan(form)
            return
        if path == "/founding":
            name = (form.get("name") or "").strip()
            email = (form.get("email") or "").strip()
            company = (form.get("company") or "").strip()
            if not name or "@" not in email or "." not in email:
                self._send(400, error_page(
                    "Details not recorded",
                    "Add your name and a complete email address and "
                    "try again."))
                return
            entries = load_list(FOUNDING_PATH)
            entries.append({
                "name": name,
                "email": email,
                "company": company,
                "timestamp": datetime.datetime.now().isoformat(
                    timespec="seconds"),
            })
            _save(FOUNDING_PATH, entries)
            self._redirect("/?joined=1")
        elif path == "/scan/demo":
            with open(DEMO_SNAPSHOT_PATH, encoding="utf-8") as fh:
                snap = json.load(fh)
            record = run_and_store(snap, "demo")
            self._send(200, results_page(record))
        else:
            self._not_found()

    def _handle_connect_scan(self, form):
        cfg = graph_connect.config()
        if not cfg["scan_ready"]:
            self._send(200, connect_page())
            return
        tenant_id = (form.get("tenant_id") or "").strip()
        if not tenant_id \
                or graph_connect.get_connection(tenant_id) is None:
            self._send(400, error_page(
                "Unknown tenant",
                "That tenant has not granted consent, so there is no "
                "live connection to scan. Connect it first from the "
                "connect page."))
            return
        try:
            outcome = graph_connect.scan_tenant(tenant_id)
        except graph_connect.GraphError as exc:
            self._send(502, error_page(
                "Microsoft Graph could not be reached",
                str(exc)))
            return
        if outcome["status"] == "incomplete":
            self._send(200, connect_incomplete_page(
                tenant_id, outcome["missing"], outcome["warnings"]))
            return
        record = run_and_store(outcome["snapshot"], "graph")
        self._send(200, results_page(record))

    def _handle_upload(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD:
            self._send(413, scan_page(
                "That file is too large for a tenant snapshot "
                "(6 MB limit). Check you chose the JSON export."))
            return
        raw = self.rfile.read(length) if length else b""
        fields = parse_multipart(raw, self.headers.get("Content-Type"))
        content = fields.get("snapshot")
        if not content:
            self._send(400, scan_page(
                "Choose a tenant snapshot JSON file first."))
            return
        try:
            snap = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, scan_page(
                "That file is not valid JSON. Upload the tenant "
                "export exactly as produced — see How to export."))
            return
        problem = validate_snapshot(snap)
        if problem:
            self._send(400, scan_page(problem))
            return
        try:
            record = run_and_store(snap, "upload")
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            self._send(400, scan_page(
                f"That snapshot is missing fields the scan needs "
                f"({exc}). See the How to export page for the fields "
                f"each section must carry."))
            return
        self._send(200, results_page(record))


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"{PRODUCT} listening on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
