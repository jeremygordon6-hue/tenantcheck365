#!/usr/bin/env python3
"""
TenantCheck 365 — production web app (free-tools build).

One brand over the three verified M365-cluster modules:

  * TenantFix 365   — Microsoft 365 hardening scan for small firms with
                      no IT person, plus an owner-approved fix plan.
  * TokenWatch      — OAuth grant inventory ranked by scope sensitivity
                      and consent type, with an unverified-publisher
                      loading. Time unused changes the rank only when
                      the snapshot includes a real last-use date.
  * InsureReady 365 — the same scan mapped to a cyber-insurance
                      evidence pack (Supported / Gap / Evidence missing).
  * CopilotReady    — the Copilot oversharing audit (copilot_audit.py):
                      reads the snapshot's per-site / per-library
                      permission inventory and reports what Microsoft
                      Copilot could surface to staff who should not
                      see it. Included in the scan; no separate price.
  * Sign-in rules evidence, a scan-to-scan change report, and an
                      AI Governance Pack are produced with every scan
                      (app.py; the change report is in-product only —
                      no email alerts, no scheduler).
  * Google Workspace companion (google_check.py): a scan for
                      Google domains at /google — same pattern,
                      export-based, plus a live connection code
                      side (google_connect.py) mirroring the
                      Microsoft one: a service account with
                      domain-wide delegation authorized by each
                      customer domain's own admin. INACTIVE until
                      the owner setup in SETUP-GOOGLE.md is done;
                      no Google passwords are ever collected.

Stack: Python standard library only — http.server, server-rendered
HTML with inline CSS, no JavaScript frameworks, no external requests.
All checking logic is the verified prototype engine in m365.py,
imported and reused (the engine began as a byte-identical
copy of ../m365-cluster/m365.py and has since been extended in
place — InsureReady 25 questions + broker pack, TokenWatch AI
apps view — re-verified after every change: engine 53/53,
app suite green).

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
import m365  # the scan engine (TenantFix/TokenWatch/InsureReady)
import copilot_audit  # Copilot oversharing audit (companion module;
                      # runs on the snapshot's sharingInventory)
import graph_connect  # live Microsoft Graph connection (inactive
                      # until the TENANTCHECK_MS_* env vars are set)
import google_check  # Google Workspace companion engine
import google_connect  # live Google Workspace connection (inactive
                      # until the TENANTCHECK_GOOGLE_* env vars are
                      # set; see SETUP-GOOGLE.md)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
FOUNDING_PATH = os.path.join(DATA_DIR, "founding.json")
SCANS_PATH = os.path.join(DATA_DIR, "scans.json")
DEMO_SNAPSHOT_PATH = os.path.join(APP_DIR, "demo_snapshot.json")
DEMO_GOOGLE_PATH = os.path.join(APP_DIR, "demo_google_snapshot.json")
EXPORT_SCRIPT_PATH = os.path.join(APP_DIR, "tools",
                                  "tenantcheck-export.ps1")

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8795"))

MAX_UPLOAD = 6_000_000    # bytes; tenant snapshots are small JSON files

PRODUCT = "TenantCheck 365"
HONESTY_LINE = ("TenantCheck 365 prepares evidence. It does not certify "
                "compliance and is not legal or insurance advice.")

BASE_URL = "https://tenantcheck365.ca"

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
.skip { position: absolute; left: -9999px; top: 0; background: #fff;
        color: #14304d; padding: 10px 16px; z-index: 10;
        font-weight: 700; }
.skip:focus { left: 8px; top: 8px; }
@media (max-width: 760px) {
  header.site nav { float: none; margin-top: 8px; }
  header.site nav a { display: inline-block; margin: 2px 14px 2px 0; }
}
"""


# ---------------------------------------------------------------------------
# Search and sharing metadata (SEO)
# ---------------------------------------------------------------------------

# Per-page metadata, keyed by the title each page passes to page().
# "path" is the page's canonical public path. The scan results view
# has a per-record URL, so it carries a description but no canonical.
PAGE_SEO = {
    "Microsoft 365 security check for small firms": {
        "path": "/",
        "description":
            "A Microsoft 365 security check for small firms with no "
            "IT person: MFA gaps, risky app grants and insurer-ready "
            "evidence. We never ask for your password.",
    },
    "Run a scan": {
        "path": "/scan",
        "description":
            "Run a TenantCheck 365 scan: upload an exported tenant "
            "snapshot and get an owner-approved fix plan, a ranked "
            "app-grant inventory, and insurer evidence.",
    },
    "How to export your tenant snapshot": {
        "path": "/how-to-export",
        "description":
            "Export your Microsoft 365 tenant snapshot in about 10 "
            "minutes: a guided script runs on your own computer with "
            "read-only permissions. No password needed.",
    },
    "The live connection": {
        "path": "/live-connection",
        "description":
            "How the TenantCheck 365 live connection will work: an "
            "app registration, read-only permissions, and consent "
            "granted by your own admin. No passwords, ever.",
    },
    "Connect your tenant": {
        "path": "/connect",
        "description":
            "Connect your Microsoft 365 tenant: your own Global "
            "Administrator grants or refuses read-only consent only "
            "on Microsoft's own consent screen, never ours.",
    },
    "Scan results": {
        "description":
            "Your TenantCheck 365 scan results: hardening findings "
            "and fix steps, a ranked inventory of app grants, and "
            "insurer questions mapped from the same scan.",
    },
    "TenantCheck for Google Workspace": {
        "path": "/google",
        "description":
            "The Google Workspace companion to TenantCheck 365: "
            "2-Step Verification gaps, dormant and admin accounts, "
            "third-party and AI app access, Drive sharing — from an "
            "export, never a Google sign-in.",
    },
    "How to export your Google Workspace snapshot": {
        "path": "/google/how-to-export",
        "description":
            "Export your Google Workspace settings as one JSON "
            "snapshot with the Admin SDK or GAM: exactly which "
            "sections the scan needs and where each comes from.",
    },
    "Google Workspace scan results": {
        "description":
            "Your Google Workspace scan results: findings and fix "
            "steps, a third-party app inventory with an AI apps "
            "view, and the same insurance questionnaire answered "
            "from the same export.",
    },
    "The Google live connection": {
        "path": "/google/live-connection",
        "description":
            "How the TenantCheck for Google Workspace live "
            "connection works: a service account authorized by "
            "your own admin through domain-wide delegation, with "
            "read-only scopes. No passwords, ever.",
    },
    "Connect your Google Workspace domain": {
        "path": "/google/connect",
        "description":
            "Connect your Google Workspace domain: your own super "
            "admin authorizes our service account in your Admin "
            "console, sees the exact read-only scope list first, "
            "and can revoke it at any time.",
    },
}

# The public GET pages a crawler may index — never result views,
# report downloads or the export-script download, whose URLs are
# per-record or file downloads.
SITEMAP_PATHS = ["/", "/scan", "/how-to-export", "/live-connection",
                 "/connect", "/google", "/google/how-to-export",
                 "/google/live-connection", "/google/connect"]


def sitemap_xml():
    urls = "".join(f"  <url><loc>{BASE_URL}{p}</loc></url>\n"
                   for p in SITEMAP_PATHS)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/'
            'sitemap/0.9">\n' + urls + "</urlset>\n")


def robots_txt():
    return ("User-agent: *\nAllow: /\n"
            f"Sitemap: {BASE_URL}/sitemap.xml\n")


def security_txt():
    return ("Contact: mailto:jeremygordon6@gmail.com\n"
            "Preferred-Languages: en, fr\n"
            f"Canonical: {BASE_URL}/.well-known/security.txt\n"
            "\n"
            "TenantCheck 365 is operated by CanCheck (Jeremy "
            "Gordon). Please report\nsecurity issues with this "
            "site to the contact above.\n")


# Baseline security headers sent on every response. The CSP is a
# baseline, not a strict policy: the pages are server-rendered with
# an inline <style> block and inline JSON-LD <script> blocks, so
# 'unsafe-inline' is required for style-src and script-src or the
# site breaks; everything else is locked to 'self', framing is
# denied (also via X-Frame-Options), and form posts go to 'self'.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy":
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
}


def _json_ld(data):
    return ('<script type="application/ld+json">'
            + json.dumps(data, ensure_ascii=False) + "</script>")


def home_json_ld():
    """Homepage structured data: the organization, plus a FAQ whose
    answers restate only facts and prices already shown on the page
    (the module cards and the how-it-works copy)."""
    org = {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": PRODUCT,
        "url": BASE_URL + "/",
        "description": PAGE_SEO[
            "Microsoft 365 security check for small firms"
        ]["description"],
    }
    faq_pairs = [
        ("What does a TenantCheck 365 scan check?",
         "Accounts without MFA (admins flagged critical), legacy "
         "authentication still enabled, inbox rules quietly "
         "forwarding mail outside the business, anonymous file "
         "sharing, too many Global Administrators, dormant admin "
         "accounts, broad guest access, and weak password policy — "
         "plus an inventory of every third-party app grant, 25 "
         "cyber-insurance questions, and a Copilot oversharing "
         "audit of your site and library permissions."),
        ("Do I have to give TenantCheck 365 my Microsoft password?",
         "No. There is no Microsoft sign-in anywhere in this app, "
         "and your Microsoft username or password is never asked "
         "for. The scan runs on an exported tenant snapshot, and the "
         "live connection works only through an app registration "
         "plus consent granted by your own administrator."),
        ("How does TenantCheck 365 help with cyber insurance?",
         "InsureReady 365 maps the same scan to the 25 questions a "
         "typical Canadian cyber-insurance renewal asks — MFA, "
         "legacy auth, EDR coverage, tested backups, admin limits, "
         "training, incident response — each answered Supported, "
         "Gap, or Evidence missing, with the evidence attached. "
         "Where the tenant data cannot support an answer, the pack "
         "says so instead of guessing."),
        ("How much does TenantCheck 365 cost?",
         "Founding prices shown on this page, in CAD: $149 CAD one "
         "time for the scan and fix plan, $39 CAD/month for "
         "monitoring (a re-scan plan: you send a fresh export, we "
         "re-run the scan and compare it with your last scan — no "
         "automatic scheduler yet), and $49 CAD/month for the full "
         "bundle of all three modules."),
    ]
    faq = {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [
            {"@type": "Question", "name": q,
             "acceptedAnswer": {"@type": "Answer", "text": a}}
            for q, a in faq_pairs],
    }
    return _json_ld(org) + "\n" + _json_ld(faq)


def page(title, body, extra_head=""):
    full_title = f"{title} — {PRODUCT}"
    seo = PAGE_SEO.get(title, {})
    description = seo.get("description")
    path = seo.get("path")
    head_extra = (
        '\n<meta name="google-site-verification" '
        'content="zSL9EpgwpfB0zGLIYpzCE0gk8uuYKcNteYM6LHS__MY">'
        '\n<meta name="msvalidate.01" '
        'content="5A6E6E3DD0931B9DB02307A62305125F">')
    if description:
        head_extra += (f'\n<meta name="description" '
                       f'content="{escape(description, quote=True)}">')
    if path:
        head_extra += (f'\n<link rel="canonical" '
                       f'href="{BASE_URL}{path}">')
    if description:
        head_extra += (
            f'\n<meta property="og:title" '
            f'content="{escape(full_title, quote=True)}">'
            f'\n<meta property="og:description" '
            f'content="{escape(description, quote=True)}">'
            '\n<meta property="og:type" content="website">')
        if path:
            head_extra += (f'\n<meta property="og:url" '
                           f'content="{BASE_URL}{path}">')
        head_extra += (
            '\n<meta name="twitter:card" content="summary">'
            f'\n<meta name="twitter:title" '
            f'content="{escape(full_title, quote=True)}">'
            f'\n<meta name="twitter:description" '
            f'content="{escape(description, quote=True)}">')
    if extra_head:
        head_extra += "\n" + extra_head
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(full_title)}</title>{head_extra}
<style>{CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to main content</a>
<header class="site">
  <a href="/">{PRODUCT}</a>
  <nav aria-label="Primary">
    <a href="/scan">Run a scan</a>
    <a href="/how-to-export">How to export</a>
    <a href="/live-connection">Live connection</a>
    <a href="/connect">Connect</a>
  </nav>
</header>
<main id="main">
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
              'Checkout is open now at the founding prices above.'
              '</div>') \
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
  <strong>Why now:</strong> many cyber-insurance renewal
  questionnaires now ask for configuration <em>evidence</em>, not
  just a "yes" to MFA — and answers given on the form are treated
  as fact if there is ever a claim. Knowing your real state before
  renewal is the difference between evidence and a guess.
</div>

<h2>How it works</h2>
<div class="card">
  <p><strong>1. Export</strong> — your tenant's settings are exported
  as one JSON file shaped like Microsoft's own admin data.
  <a href="/how-to-export">See exactly where each part comes from</a>,
  or skip straight to the demo below.</p>
  <p><strong>2. Upload</strong> — the scan runs on the export. No
  Microsoft sign-in, no password, nothing installed.</p>
  <p><strong>3. Review</strong> — you get the reports below, each
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
  <p><strong>Founding price: $149 CAD</strong> one time for the scan and
  fix plan · <strong>$39 CAD/month</strong> monitoring — a re-scan plan: you send a fresh export, we re-run the scan and compare it with your last scan. No automatic scheduler yet.</p>
  <a class="btn" href="/scan">Run a scan</a>
  <a class="btn" href="https://buy.stripe.com/00w9AMaJj76fbCu6AQ5Rm03">Buy the scan — $149 CAD</a>
  <a class="btn" href="https://buy.stripe.com/9B66oAg3DgGP0XQ7EU5Rm04">Add monitoring — $39 CAD/month</a>
</div>

<div class="card">
  <h2>TokenWatch <span class="badge">Module 2 — live</span></h2>
  <p>Every third-party app your people have connected to Microsoft 365
  keeps the access it was granted — often mail and file access — long
  after everyone forgot it. TokenWatch inventories every OAuth grant
  and ranks it by what it can reach, whether one user approved it
  alone, and whether the publisher is verified. Time unused changes
  that rank only when the snapshot includes a real last-use date.
  The export script does not have one: Microsoft's permission-grant
  records do not include last use, so an export is ranked without a
  dormancy guess and last use shows as unknown. A live connection
  can fill last use from the app's sign-in logs when Microsoft
  returns them. These grants bypass MFA entirely. The inventory also
  carries an AI apps view: connected apps identified by name as AI
  tools (meeting note-takers, AI writing and chat apps and the
  like), with what each one can read, in plain English.</p>
  <p>Included in the bundle below.</p>
</div>

<div class="card">
  <h2>InsureReady 365 <span class="badge">Module 3 — live</span></h2>
  <p>Twenty-five questions a typical Canadian cyber-insurance renewal
  asks — MFA, legacy auth, EDR coverage, tested backups, admin limits,
  training, incident response — each answered <em>Supported</em>,
  <em>Gap</em>, or <em>Evidence missing</em> from the same scan, with
  the evidence attached. Where the tenant data cannot support an
  answer, the pack says so instead of guessing.</p>
  <p>Included in the bundle below.</p>
</div>

<div class="card">
  <h2>CopilotReady <span class="badge">Included in the scan</span></h2>
  <p>Copilot answers from everything the asking employee is already
  allowed to read — so every broad grant hiding in SharePoint and
  OneDrive becomes something Copilot can quote back to the wrong
  person. The scan now includes an oversharing audit of your site
  and library permissions: "anyone with the link" links, grants to
  every staff member, company-wide links, ownerless sites, drives
  whose owner has left, and guests who can re-share. It reads the
  permission inventory in your export, never file contents.</p>
  <p>Included in the scan and the bundle below — no separate price.</p>
</div>

<div class="card">
  <h2>AI Governance Pack <span class="badge">Included in the scan</span></h2>
  <p>Every scan also produces an AI Governance Pack: the AI tools
  TokenWatch identified in your tenant, the CopilotReady
  oversharing summary, a ready-to-adopt AI acceptable-use policy
  template written for a small firm, and an evidence page tying
  them together. The template is a starting document for the owner
  to review and adopt — not legal advice.</p>
  <p>Included in the scan — no separate price.</p>
</div>

<div class="card">
  <h2>The bundle <span class="badge">All three modules</span></h2>
  <p>TenantFix + TokenWatch + InsureReady on one tenant scan engine,
  with the CopilotReady oversharing audit included in every scan,
  and re-scans on request — you send a fresh export, we re-run
  the scan and compare it with your last one — so the state you
  attested to is checked again between renewals.</p>
  <p><strong>Founding price: $49 CAD/month</strong> for the full bundle.</p>
  <a class="btn" href="https://buy.stripe.com/9B600cdVv1LV9umgbq5Rm05">Subscribe — $49 CAD/month</a>
  <p class="small">Founding prices are the introductory prices for the
  first cohort, and checkout is open now at those prices. The list
  below records your details so we can write to you about the founding
  offer.</p>
</div>

<div class="card">
  <h2>TenantCheck for Google Workspace <span class="badge">Export-based — new</span></h2>
  <p>On Google Workspace instead of Microsoft 365? The companion
  scan checks the same ground — 2-Step Verification, dormant and
  admin accounts, third-party and AI app access, Drive sharing —
  from an export your own admin produces, and answers the same
  insurance questionnaire wherever it honestly maps. A live
  connection option is built for it too, switched on once the
  owner setup is done — its
  <a href="/google/live-connection">status page</a> says plainly
  whether it is on. No Google sign-in, no password.</p>
  <a class="btn" href="/google">Open the Google Workspace scan</a>
</div>

<div class="card">
  <h2>See it on a demo tenant first</h2>
  <p>The demo runs the full scan on a fictional 18-person bookkeeping
  firm with real problems planted in it — no MFA on three accounts
  including an admin, an inbox rule forwarding invoices to an outside
  address, and a forgotten app with mail access. The demo snapshot
  includes a last-use date for that app (210 days) so the ranking
  can show the time-unused factor. An export from the script does
  not include that date, and last use stays unknown.
  Same engine, same reports, zero risk.</p>
  <form method="post" action="/scan/demo">
    <button type="submit">Run the demo scan</button>
  </form>
</div>

<div class="card">
  <h2>Join the founding list</h2>
  <p>Checkout is open now at the founding prices above. Leave your
  details and we will write to you about the founding offer. No email
  is sent by this form — it only records your details so we can send
  that note.</p>
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
  <p class="small">CanCheck is operated by Jeremy Gordon. By
  joining the founding list, you agree to receive email from
  CanCheck about the founding offer. You can unsubscribe at any
  time — reply to any email and ask to be removed, and we will
  remove you.</p>
</div>

<p class="small">{HONESTY_LINE} Every finding is an issue to review,
found by deterministic checks — never a certification.</p>
"""
    return page("Microsoft 365 security check for small firms", body,
                extra_head=home_json_ld())


# ---------------------------------------------------------------------------
# Scan pages
# ---------------------------------------------------------------------------

def scan_page(error=None):
    err = f'<div class="notice">{escape(error)}</div>' if error else ""
    body = f"""
<h1>Run a scan</h1>
<p>Upload an exported tenant snapshot (one JSON file) and {PRODUCT}
runs all three modules on it — TenantFix hardening findings, the
TokenWatch grant ranking, and the InsureReady evidence pack — plus
the CopilotReady oversharing audit of the snapshot's site and
library permission inventory. The
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
  that folder, and run:</p>
  <pre class="sample">Unblock-File -LiteralPath .\tenantcheck-export.ps1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\tenantcheck-export.ps1</pre>
  <p class="small">Windows marks a downloaded script as coming from
  the internet and may refuse to run it. <code>Unblock-File</code>
  clears that mark on this file only.
  <code>Set-ExecutionPolicy -Scope Process</code> allows local scripts
  in this window only (<code>RemoteSigned</code>). That is enough to
  run this script, and the change ends when you close the window. It
  does not turn script checks off for anything else. The script itself
  is plain text and you can read every line before running it.</p>
  <p><strong>3. Sign in — to Microsoft, not to us.</strong> A
  Microsoft sign-in window opens. You sign in with your own admin
  account and approve a fixed list of <strong>read-only</strong>
  permissions: user and directory reads, role assignments, policy
  reads, the MFA registration report, sign-in activity, app consent
  records, site and library <em>permission lists</em> (who and what
  each site is shared with — never file contents), and inbox
  <em>rule definitions</em> (rule settings such as
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
  <p class="small">Honest limits of the script: permission-grant
  records do not include when an app was last used, and this script
  does not read app sign-in logs, so every grant is written with last
  use unknown and scored without a dormancy guess. It cannot see
  how broadly a guest account can reach, so guests are never flagged
  on a guess. The Copilot oversharing audit reads site-level and
  library-root permission lists, not every file — sharing links on
  individual files below that level are not enumerated. And if the
  script cannot read a mailbox's inbox rules, it counts that mailbox
  as skipped and writes the count into the export: the scan then
  reports the forwarding answer as evidence missing for those
  mailboxes, never as "no rules found". All of these facts are
  stated in the script itself.</p>
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
            redirect targets (rule settings, not message contents).
            The export also carries an <code>exportCoverage</code>
            count of mailboxes read and mailboxes skipped</td>
        <td>Exchange — Graph inbox message rules per mailbox (read
            with the MailboxSettings.Read permission — rule settings
            only), or the Exchange admin rule reports. A mailbox the
            export could not read is counted as skipped, and the
            scan reports its forwarding evidence as missing</td></tr>
    <tr><td><code>tenantSettings</code></td>
        <td>Legacy authentication state, external sharing level,
            password policy</td>
        <td>Conditional Access / authentication policies, SharePoint
            admin sharing settings, domain password policy</td></tr>
    <tr><td><code>oauthGrants</code></td>
        <td>Third-party app consents: app name, scopes granted, who
            consented, and publisher verification. Last use is not
            included — Microsoft's grant records do not include it,
            so the export writes last use as unknown</td>
        <td>Enterprise applications — Graph OAuth2 permission grants
            and service principals. The script does not read app
            sign-in logs</td></tr>
    <tr><td><code>sharingInventory</code></td>
        <td>Per-site and per-drive sharing digest: owners, anonymous
            and company-wide link permissions, grants to "Everyone"
            or to every staff member, guest counts</td>
        <td>SharePoint — Graph site permission lists and library
            (drive) root permission lists, plus drive ownership.
            Permission lists only, never file contents</td></tr>
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
monitoring offer, as it works today, is re-scans on request:
you send a fresh export, we re-run the scan and send you the
comparison against your last scan. Scheduled re-scans that catch
a new risky app grant or an MFA change between insurance
renewals need a standing, read-only connection. This is exactly what the connection requires:</p>"""
    else:
        status = f"""
<div class="deadline">
  <strong>Status, plainly:</strong> setup is pending. The live
  connection is <strong>not switched on</strong> yet, so nothing on
  this site connects to your tenant. {PRODUCT} runs today on an
  uploaded export (<a href="/how-to-export">how that works</a>).
  What remains is setup on the product owner's side: the app
  registration has to be created and configured on the server.
  The <a href="/connect">connect page</a> stays off until setup is
  finished, and it says the same thing this page does.
</div>
<p>Uploading an export works, but it is a snapshot of one day. The
monitoring offer, as it works today, is re-scans on request:
you send a fresh export, we re-run the scan and send you the
comparison against your last scan. Scheduled re-scans that catch
a new risky app grant or an MFA change between insurance
renewals need a standing, read-only connection. This is exactly what that connection will require, so you
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
  <h2>Step 3 — the same scan, without the export</h2>
  <p>With consent in place, the app builds the same snapshot the export
  produces today and runs the identical checks — same engine, same
  reports. Scheduled monitoring — the scan re-running itself on a
  schedule and flagging changes — is what this connection makes
  possible; it does not run today. Until then, monitoring is
  re-scans on request: you ask, we re-run the scan and send you
  the comparison against your last scan.</p>
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
  this product. The permissions are read-only: directory and role
  reads, policy reads, app-consent reads, and inbox rule settings.
  No mail contents, and nothing that can change the tenant. A live
  scan stores the same kind of snapshot as an upload, only as your
  scan record, so the reports stay downloadable. Fixes are never
  applied without the owner's approval of each step; a read-only
  connection cannot apply them anyway.
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
        body = f"""
<h1>Connect your tenant</h1>
{notice}
<div class="deadline">
  <strong>Setup is pending.</strong> The live connection is switched
  off until setup is finished, so this page cannot start a consent
  and nothing has been sent to Microsoft. When it is on, it is
  read-only: your own Global Administrator grants or refuses tenant
  admin consent on Microsoft's screen. We never ask for your
  Microsoft password. See
  <a href="/live-connection">how the live connection works</a>
  for the permissions and how the data is handled. In the meantime
  the <a href="/scan">export-based scan</a> works exactly as before.
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
                           'recorded now. A live scan stays off until '
                           'setup is finished, so nothing is read from '
                           'the tenant yet. When a scan is on, it is '
                           'read-only.</div>')
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


def signin_data(snap, norm, tf):
    """The sign-in rules evidence a snapshot can honestly support:
    Conditional Access policy COUNT, MFA registration facts, and the
    legacy-auth state. Policy contents are never in a snapshot, so
    nothing here speaks to whether a policy is correctly
    configured — the rendered proof says so in plain words."""
    c = snap.get("securityControls") or {}
    ts = snap.get("tenantSettings") or {}
    members = norm["enabled_members"]
    return {
        "ca_policy_count": c.get("conditionalAccessPolicyCount"),
        "legacy_auth_enabled": ts.get("legacyAuthenticationEnabled"),
        "legacy_protocols": ts.get("legacyAuthProtocols") or [],
        "mfa_registered": sum(1 for u in members if u["mfaRegistered"]),
        "member_count": len(members),
        "admins_without_mfa": [u["displayName"]
                               for u in norm["global_admins"]
                               if not u["mfaRegistered"]],
        "mfa_findings": sum(1 for f in tf if f["check"] == "TF-MFA"),
    }


SIGNIN_LIMIT = (
    "The contents of those policies are not in the snapshot — "
    "which users and conditions they cover, and what they require, "
    "cannot be seen from an export. This section is evidence of "
    "presence and of the related settings below; it is not proof "
    "that any policy is correctly configured, and it is never "
    "worded that way.")


def render_signin_report(snap, data, tf, ir):
    out = m365.header(snap, "TenantCheck 365 - Sign-in Rules Evidence")
    out += ["Evidence about the tenant's sign-in rules that this "
            "snapshot can support, prepared for the owner's review "
            "and for questions like IR-Q04 on the insurance "
            "questionnaire.", ""]
    ca_count = data["ca_policy_count"]
    out += ["## Conditional Access policies",
            (f"Policies present in the snapshot: {ca_count}."
             if ca_count is not None else
             "Policy count: not recorded in this snapshot."), ""]
    out += ["## MFA evidence",
            f"Enabled member accounts with MFA registered: "
            f"{data['mfa_registered']} of {data['member_count']}.",
            "Global Administrators without MFA: "
            + (", ".join(data["admins_without_mfa"])
               if data["admins_without_mfa"] else "none") + ".",
            f"TenantFix MFA findings in this scan: "
            f"{data['mfa_findings']}.", ""]
    legacy = data["legacy_auth_enabled"]
    out += ["## Legacy authentication",
            ("Legacy authentication is ENABLED (protocols: "
             + ", ".join(data["legacy_protocols"]) + ")."
             if legacy else
             "Legacy authentication is disabled in this snapshot.")
            if legacy is not None else
            "Legacy authentication state: not recorded in this "
            "snapshot.", ""]
    out += ["## What this evidence does not show", "", SIGNIN_LIMIT, ""]
    return "\n".join(out)


POLICY_TEMPLATE = """## AI acceptable-use policy — TEMPLATE

**This is a template, not an adopted policy and not legal
advice.** It becomes the firm's policy only when the owner reviews
it, fills in the blanks, adopts it, and tells staff it is in force.
Have it reviewed if the firm handles regulated data.

Firm: [Firm name]
Effective date: [Date]
Policy owner: [Name / role]

### 1. Purpose
This policy covers the use of AI tools — including Microsoft
Copilot and any third-party AI service — by everyone at the firm,
on firm systems and firm data.

### 2. Permitted uses
- Drafting, summarising and editing the staff member's own work.
- Brainstorming, research and first drafts that a person then
  checks before use.
- Use of the AI tools listed in the approved-tools section of
  this pack, for the purposes they were approved for.

### 3. Prohibited data
Never enter the following into an AI tool that the firm has not
approved for it:
- Client personal information, payroll or HR records, or anything
  covered by a client confidentiality agreement.
- Passwords, access keys, financial credentials, or full payment
  card numbers.
- Anything whose disclosure would breach a law, a regulator's
  rule, or a contract.

### 4. Human review
AI output is a draft, not a decision. A named person reviews and
takes responsibility for anything sent to a client, filed, or
relied on for money, tax, legal or safety decisions. AI output is
never sent as-is to a client.

### 5. New AI tools
Staff ask the policy owner before connecting a new AI tool to
firm accounts or data. The owner records the tool in the firm's
inventory (the TokenWatch inventory in this pack is the starting
point) before it is used with firm data.

### 6. Incident reporting
Anyone who believes firm or client data was entered into an
unapproved AI tool, or that AI output caused an error, reports it
to [Name / role] the same day. Reporting a mistake is never
punished; hiding one is a policy breach.

### 7. Review
The policy owner reviews this policy and the AI tool inventory
every [6 / 12] months, and whenever a new AI tool is adopted.
"""


def render_governance_pack(snap, tw, ca):
    """The AI Governance Pack: TokenWatch's AI inventory, the
    CopilotReady oversharing summary, a ready-to-adopt AI
    acceptable-use policy template, and an evidence page tying
    them together. Honest by construction: absent data renders as
    an explicit statement, never as an empty pass."""
    out = m365.header(snap, "TenantCheck 365 - AI Governance Pack")
    out += ["This pack gives a small firm the three things an AI "
            "governance conversation actually needs: which AI tools "
            "already have access to its systems, what those tools "
            "could surface, and a policy to adopt. It prepares "
            "evidence and a template; it does not certify anything "
            "and is not legal advice.", ""]
    ais = m365.ai_apps(tw)
    out += ["## 1. AI tool inventory (from TokenWatch)", "",
            m365.AI_IDENTIFICATION_NOTE, "",
            f"AI apps identified: {len(ais)}", ""]
    if not ais:
        out += ["No connected app was identified as an AI tool by "
                "name in this scan. That is not proof the firm uses "
                "no AI tools — only that none of the connected app "
                "names matched the known list. Staff may also use "
                "AI tools outside the tenant, which no tenant scan "
                "can see.", ""]
    for i in ais:
        last = i["last_used_days_ago"]
        last_txt = ("last used unknown" if last is None
                    else f"last used {last} days ago")
        out += [f"### {i['app']} — identified as {i['ai_label']}",
                f"Consent: {i['consent_type']}"
                + (f" ({i['consented_by']})" if i["consented_by"]
                   else "")
                + f" | {last_txt} | TokenWatch risk {i['risk']} "
                  f"[{'FLAGGED' if i['flagged'] else 'not flagged'}]",
                "What it can do: "
                + "; ".join(i["scopes_plain"]) + ".", ""]
    out += ["## 2. Copilot oversharing summary (from CopilotReady)",
            ""]
    if not ca["covered"]:
        out += ["**NOT COVERED BY THIS SNAPSHOT**", "",
                copilot_audit.NOT_COVERED_NOTE, ""]
    else:
        findings = ca["findings"]
        out += [f"Sites and drives reviewed: {ca['items_reviewed']}",
                f"Oversharing findings: {len(findings)}", ""]
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        for f in sorted(findings,
                        key=lambda x: order[x["severity"]]):
            out += [f"- [{f['severity']}] {f['title']} "
                    f"({f['check']})"]
        if not findings:
            out += ["No oversharing findings in the permission "
                    "lists this snapshot contains. That is not a "
                    "guarantee — the audit reads site and library "
                    "permission lists, not every file."]
        out += [""]
    out += [POLICY_TEMPLATE]
    out += ["## 4. Evidence page — how the pieces tie together", "",
            "Each governance statement below is labelled with its "
            "source. Statements the scan cannot support are marked "
            "for the owner — they are not assumed.", "",
            "| Statement | Source |",
            "|---|---|",
            f"| AI tools connected to the tenant are inventoried | "
            f"{'Evidence in this pack (section 1): ' + str(len(ais)) + ' identified by name' if ais else 'Owner to complete — no AI tool was identified by name in this scan'} |",
            f"| Oversharing exposure for Copilot has been reviewed | "
            f"{'Evidence in this pack (section 2): ' + str(len(ca['findings'])) + ' finding(s)' if ca['covered'] else 'Not covered — this snapshot has no sharing inventory'} |",
            "| A written AI acceptable-use policy exists | Owner "
            "to state — a template is provided in section 3; it "
            "counts as the firm's policy only once the owner "
            "adopts it |",
            "| Staff know which data must never enter an AI tool | "
            "Owner to state — covered by template section 3 once "
            "adopted and communicated |",
            "| AI tool inventory is reviewed on a cadence | Owner "
            "to state — template section 7 sets the cadence once "
            "adopted |", ""]
    return "\n".join(out)


def compute_changes(prev, new):
    """Scan-to-scan change report for the same firm: TenantFix
    findings new vs resolved, InsureReady status changes,
    CopilotReady finding changes, TokenWatch flagged-set changes,
    and the headline summary deltas. In-product comparison only."""
    def tf_keys(rec):
        return {(f["check"], f["subject"]) for f in rec["tenantfix"]}

    def ca_keys(rec):
        ca = rec.get("copilot") or {}
        if not ca.get("covered"):
            return None
        return {(f["check"], f["subject"]) for f in ca["findings"]}

    prev_tf, new_tf = tf_keys(prev), tf_keys(new)
    prev_ca, new_ca = ca_keys(prev), ca_keys(new)
    prev_ir = {r["id"]: r["status"] for r in prev["insureready"]}
    ir_changes = [
        {"id": r["id"], "question": r["question"],
         "from": prev_ir[r["id"]], "to": r["status"]}
        for r in new["insureready"]
        if r["id"] in prev_ir and prev_ir[r["id"]] != r["status"]]
    prev_flag = {i["app"] for i in prev["tokenwatch"] if i["flagged"]}
    new_flag = {i["app"] for i in new["tokenwatch"] if i["flagged"]}
    ps, ns = prev["summary"], new["summary"]
    return {
        "baseline": False,
        "previous_timestamp": prev["timestamp"],
        "tenantfix_new": sorted(new_tf - prev_tf),
        "tenantfix_resolved": sorted(prev_tf - new_tf),
        "insureready_changes": ir_changes,
        "copilot_comparable": prev_ca is not None and new_ca is not None,
        "copilot_new": sorted(new_ca - prev_ca)
        if prev_ca is not None and new_ca is not None else [],
        "copilot_resolved": sorted(prev_ca - new_ca)
        if prev_ca is not None and new_ca is not None else [],
        "tokenwatch_newly_flagged": sorted(new_flag - prev_flag),
        "tokenwatch_no_longer_flagged": sorted(prev_flag - new_flag),
        "summary_deltas": {
            k: (ps.get(k), ns.get(k)) for k in
            ("tenantfix_findings", "tokenwatch_flagged",
             "insureready_gaps", "copilot_findings")
            if ps.get(k) != ns.get(k)},
    }


def run_and_store(snap, source):
    snap = with_meta(snap, source)
    norm, tf, tw, ir = m365.run_scan(snap)
    ca = copilot_audit.copilotaudit(snap)
    signin = signin_data(snap, norm, tf)
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
            "copilot_covered": ca["covered"],
            "copilot_items": ca["items_reviewed"],
            "copilot_findings": len(ca["findings"]),
        },
        "tenantfix": tf,
        "tokenwatch": tw,
        "insureready": ir,
        "copilot": ca,
        "signin": signin,
        "reports": {
            "tenantfix": m365.render_tenantfix(snap, tf),
            "tokenwatch": m365.render_tokenwatch(snap, tw),
            "insureready": m365.render_insureready(snap, ir),
            "copilot": copilot_audit.render_copilotaudit(snap, ca),
            "signin": render_signin_report(snap, signin, tf, ir),
            "governance": render_governance_pack(snap, tw, ca),
        },
    }
    scans = load_list(SCANS_PATH)
    previous = next((s for s in reversed(scans)
                     if s.get("firm") == record["firm"]), None)
    record["changes"] = (compute_changes(previous, record)
                         if previous is not None else {"baseline": True})
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


def tokenwatch_ai_html(inventory):
    """The AI-apps view on the results page: the grants whose app
    names match the maintained AI list in m365.py. Records stored
    before this view existed have no is_ai keys and render the
    honest fallback line."""
    if not inventory or "is_ai" not in inventory[0]:
        return ""
    ais = [i for i in inventory if i.get("is_ai")]
    if not ais:
        inner = ("<p>No connected app was identified as an AI tool "
                 "by name. That is not proof the firm uses no AI "
                 "tools — only that no connected app name matched "
                 "the known list.</p>")
    else:
        rows = []
        for i in ais:
            flag = ('<span class="status status-gap">Flagged</span>'
                    if i["flagged"] else
                    '<span class="status status-supported">OK</span>')
            last = i["last_used_days_ago"]
            last_txt = "unknown" if last is None else f"{last} days ago"
            by = (f" ({escape(i['consented_by'])})"
                  if i.get("consented_by") else "")
            rows.append(f"""
<tr{' class="flagged"' if i['flagged'] else ''}>
  <td><strong>{escape(i['app'])}</strong><br>
      <span class="small">identified as
      {escape(i.get('ai_label') or 'AI tool')}</span></td>
  <td>{flag}</td>
  <td>{escape('; '.join(i.get('scopes_plain') or i['scopes']))}</td>
  <td>{last_txt}</td>
  <td>{escape(i['consent_type'])}{by}</td>
</tr>""")
        inner = f"""
<table>
  <tr><th>AI app</th><th>Status</th><th>What it can do</th>
      <th>Last used</th><th>Consent</th></tr>
  {''.join(rows)}
</table>"""
    return f"""
<h3>AI apps with access to this tenant</h3>
<p>AI tools are identified as AI tools <strong>by app name</strong>
against a maintained list of known AI services
({len(ais)} identified). An AI tool whose name does not match the
list would not be flagged here, and a non-AI app with an AI-sounding
name could be listed — the owner confirms each one.</p>
{inner}"""


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


def copilot_html(ca):
    """Render the CopilotReady section of the results page. Records
    stored before this module existed have no "copilot" entry and
    render nothing extra."""
    if ca is None:
        return ""
    if not ca["covered"]:
        return f"""
<div class="card">
  <h2>CopilotReady — oversharing audit</h2>
  <div class="notice"><strong>Not covered by this snapshot.</strong>
  {escape(copilot_audit.NOT_COVERED_NOTE)}</div>
</div>"""
    findings = ca["findings"]
    if not findings:
        inner = ("<p>No oversharing findings in the permission lists "
                 "this snapshot contains. That is not a guarantee — "
                 "the audit reads site and library permission lists, "
                 "not every file.</p>")
    else:
        out = []
        for f in sorted(findings,
                        key=lambda x: SEV_ORDER[x["severity"]]):
            steps = "".join(f"<li>{escape(s)}</li>"
                            for s in f["fix_steps"])
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
        inner = "".join(out)
    return f"""
<div class="card">
  <h2>CopilotReady — oversharing audit</h2>
  <p>Copilot answers only from what the asking employee may already
  read, so broad sharing grants are the exposure. This audit read
  the permission lists for {ca['items_reviewed']} site(s) and
  drive(s) in the snapshot — permission lists only, never file
  contents.</p>
  {inner}
</div>"""


def signin_html(record):
    """Sign-in rules evidence section on the results page. Records
    stored before this section existed carry no "signin" data and
    render an honest note instead."""
    data = record.get("signin")
    if data is None:
        return f"""
<div class="card">
  <h2>Sign-in rules evidence</h2>
  <p>Not recorded for this stored scan — run a fresh scan to
  produce the sign-in rules evidence section.</p>
</div>"""
    ca_count = data["ca_policy_count"]
    ca_txt = (f"{ca_count} Conditional Access policies are present "
              f"in the snapshot (count only)."
              if ca_count is not None else
              "The Conditional Access policy count was not recorded "
              "in this snapshot.")
    admins = data["admins_without_mfa"]
    admins_txt = (", ".join(escape(a) for a in admins)
                  if admins else "none")
    legacy = data["legacy_auth_enabled"]
    legacy_txt = ("still <strong>enabled</strong> ("
                  + escape(", ".join(data["legacy_protocols"])) + ")"
                  if legacy else "disabled")
    if legacy is None:
        legacy_txt = "not recorded in this snapshot"
    return f"""
<div class="card">
  <h2>Sign-in rules evidence</h2>
  <p>What this snapshot can actually prove about the tenant's
  sign-in rules:</p>
  <table>
    <tr><th>Item</th><th>Evidence in this scan</th></tr>
    <tr><td>Conditional Access policies</td><td>{ca_txt}</td></tr>
    <tr><td>MFA registration</td>
        <td>{data['mfa_registered']} of {data['member_count']}
            enabled member accounts have MFA registered;
            {data['mfa_findings']} MFA findings in the fix plan.</td></tr>
    <tr><td>Administrators without MFA</td><td>{admins_txt}</td></tr>
    <tr><td>Legacy authentication</td><td>{legacy_txt}.</td></tr>
  </table>
  <p class="small">{escape(SIGNIN_LIMIT)}</p>
</div>"""


def changes_html(record):
    """The scan-to-scan change report section. Renders nothing for
    records stored before comparisons existed."""
    ch = record.get("changes")
    if ch is None:
        return ""
    if ch.get("baseline"):
        inner = ("<p><strong>Baseline scan</strong> — no earlier "
                 "scan of this firm to compare with. The next scan "
                 "of the same firm will show what changed.</p>")
    else:
        def key_list(pairs):
            return "".join(
                f"<li>{escape(c)} — {escape(s)}</li>" for c, s in pairs)

        def named(items, empty):
            return ("<ul>" + "".join(f"<li>{escape(x)}</li>"
                                     for x in items) + "</ul>"
                    if items else f"<p>{empty}</p>")

        ir_items = "".join(
            f"<li>{escape(c['id'])}: {escape(c['from'])} → "
            f"{escape(c['to'])} — {escape(c['question'])}</li>"
            for c in ch["insureready_changes"])
        deltas = "".join(
            f"<li>{escape(k.replace('_', ' '))}: {v[0]} → {v[1]}</li>"
            for k, v in ch["summary_deltas"].items())
        copilot_block = ""
        if ch["copilot_comparable"]:
            copilot_block = f"""
  <p><strong>CopilotReady findings</strong> — new:</p>
  {named([f"{c} — {s}" for c, s in ch['copilot_new']], "None.")}
  <p>Resolved:</p>
  {named([f"{c} — {s}" for c, s in ch['copilot_resolved']], "None.")}"""
        else:
            copilot_block = ("<p><strong>CopilotReady:</strong> not "
                             "comparable — one of the two scans has "
                             "no sharing inventory, so no change is "
                             "claimed.</p>")
        inner = f"""
  <p>Compared with the previous scan of this firm
  ({escape(ch['previous_timestamp'])}):</p>
  <p><strong>TenantFix findings — new:</strong></p>
  {named([f"{c} — {s}" for c, s in ch['tenantfix_new']], "None.")}
  <p><strong>TenantFix findings — resolved:</strong></p>
  {named([f"{c} — {s}" for c, s in ch['tenantfix_resolved']], "None.")}
  <p><strong>InsureReady answer changes:</strong></p>
  {('<ul>' + ir_items + '</ul>') if ir_items else '<p>None.</p>'}
  <p><strong>App grants newly flagged:</strong>
  {escape(', '.join(ch['tokenwatch_newly_flagged'])) if ch['tokenwatch_newly_flagged'] else 'none'} ·
  <strong>no longer flagged:</strong>
  {escape(', '.join(ch['tokenwatch_no_longer_flagged'])) if ch['tokenwatch_no_longer_flagged'] else 'none'}</p>
  {copilot_block}
  <p><strong>Headline numbers that moved:</strong></p>
  {('<ul>' + deltas + '</ul>') if deltas else '<p>None.</p>'}"""
    return f"""
<div class="card">
  <h2>What changed since the last scan</h2>
  {inner}
  <p class="small">This comparison lives inside the product only:
  {PRODUCT} does not send drift alert emails and does not run
  scheduled re-scans on its own — a change appears here when a new
  scan of the same firm is run.</p>
</div>"""


def results_page(record):
    s = record["summary"]
    ca = record.get("copilot")
    if ca is not None and s.get("copilot_covered"):
        copilot_row = (f"<strong>{s['copilot_findings']} Copilot "
                       f"oversharing findings</strong> across "
                       f"{s['copilot_items']} sites and drives")
        copilot_button = (f'<a class="btn" '
                          f'href="/report/{record["id"]}/copilot">'
                          f'Download the CopilotReady audit</a> ')
    elif ca is not None:
        copilot_row = ("<strong>Not covered</strong> — this snapshot "
                       "has no sharing inventory")
        copilot_button = (f'<a class="btn" '
                          f'href="/report/{record["id"]}/copilot">'
                          f'Download the CopilotReady note</a> ')
    else:
        copilot_row = "Not run for this stored scan"
        copilot_button = ""
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
    <tr><td>CopilotReady</td>
        <td>{copilot_row}</td></tr>
  </table>
  <p>
    <a class="btn" href="/report/{record['id']}/tenantfix">Download the TenantFix report</a>
    <a class="btn" href="/report/{record['id']}/tokenwatch">Download the TokenWatch report</a>
    <a class="btn" href="/report/{record['id']}/insureready">Download the InsureReady evidence pack</a>
    <a class="btn" href="/report/{record['id']}/signin">Download the sign-in rules evidence</a>
    <a class="btn" href="/report/{record['id']}/governance">Download the AI Governance Pack</a>
    {copilot_button}
  </p>
  <p class="small">All downloads are Markdown reports carrying
  the DRAFT stamp below.</p>
</div>

{changes_html(record)}

<div class="card">
  <h2>TenantFix 365 — owner-approved fix plan</h2>
  <p>{escape(m365.FIX_PLAN_NOTE)}</p>
  {tenantfix_html(record['tenantfix'])}
</div>

{signin_html(record)}

<div class="card">
  <h2>TokenWatch — OAuth grant risk inventory</h2>
  <p>Ranked by scope sensitivity, whether one user approved the grant
  alone, and whether the publisher is verified. Time unused raises
  the score only when Last used is a number of days. Unknown means
  the snapshot has no last-use date — that is every grant from the
  export script, because Microsoft's grant records do not include
  it — and an unknown date does not change the rank. Highest risk
  first.</p>
  {tokenwatch_html(record['tokenwatch'])}
  {tokenwatch_ai_html(record['tokenwatch'])}
</div>

<div class="card">
  <h2>InsureReady 365 — insurance evidence</h2>
  <p>A representative Canadian SMB cyber-insurance questionnaire
  answered from this scan's evidence — not a specific insurer's form.</p>
  {insureready_html(record['insureready'])}
</div>

{copilot_html(ca)}

<div class="card">
  <h2>AI Governance Pack — included in the scan</h2>
  <p>This scan's AI Governance Pack combines the AI tool inventory
  above, the CopilotReady oversharing summary, a ready-to-adopt AI
  acceptable-use policy template, and an evidence page. The
  template counts as the firm's policy only once the owner reviews
  and adopts it — it is not legal advice.</p>
  <p><a class="btn" href="/report/{record['id']}/governance">Download the AI Governance Pack</a></p>
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
# Google Workspace companion — pages, validation, scan + store, results
# ---------------------------------------------------------------------------

GOOGLE_REQUIRED_LISTS = ("users", "oauthApps", "groups")
GOOGLE_REQUIRED_DICTS = ("domainSettings", "securityControls")

GOOGLE_REPORT_FILES = {
    "googlefix": ("googlefix_report", "Google Workspace fix plan"),
    "tokenwatch": ("google_app_inventory",
                   "Google Workspace app inventory"),
    "insureready": ("insureready_evidence_pack",
                    "InsureReady 365 evidence pack"),
}


def validate_google_snapshot(snap):
    if not isinstance(snap, dict):
        return "That file is not a snapshot object. Upload the JSON " \
               "Google Workspace export described on the Google " \
               "How to export page."
    missing = [k for k in GOOGLE_REQUIRED_LISTS + GOOGLE_REQUIRED_DICTS
               if k not in snap]
    if missing:
        return ("That snapshot is missing section(s): "
                + ", ".join(missing)
                + ". See the Google How to export page for what "
                  "each section holds.")
    for key in GOOGLE_REQUIRED_LISTS:
        if not isinstance(snap[key], list):
            return f"The '{key}' section must be a list."
    for key in GOOGLE_REQUIRED_DICTS:
        if not isinstance(snap[key], dict):
            return f"The '{key}' section must be an object."
    if not snap["users"]:
        return "That snapshot lists no user accounts, so there is " \
               "nothing to scan."
    return None


def with_google_meta(snap, source):
    snap = dict(snap)
    if source == "demo":
        return snap
    meta = dict(snap.get("_meta") or {})
    meta["firm_name"] = meta.get("firm_name") \
        or google_check._domain(snap) or "Uploaded Google domain"
    meta["snapshot_date"] = meta.get("snapshot_date") \
        or datetime.date.today().isoformat()
    meta["label"] = ("Uploaded Google Workspace export, scanned "
                     "exactly as provided. Findings cover only "
                     "what the export contains.")
    snap["_meta"] = meta
    return snap


def run_google_and_store(snap, source):
    snap = with_google_meta(snap, source)
    findings, inventory, ir, _adapter = google_check.run_google_scan(
        snap)
    record = {
        "id": uuid.uuid4().hex[:12],
        "platform": "google",
        "timestamp": datetime.datetime.now().isoformat(
            timespec="seconds"),
        "source": source,
        "firm": snap["_meta"]["firm_name"],
        "snapshot_date": snap["_meta"]["snapshot_date"],
        "summary": {
            "googlefix_findings": len(findings),
            "tokenwatch_grants": len(inventory),
            "tokenwatch_flagged": sum(1 for i in inventory
                                      if i["flagged"]),
            "insureready_questions": len(ir),
            "insureready_gaps": sum(1 for r in ir
                                    if r["status"] != "Supported"),
        },
        "googlefix": findings,
        "tokenwatch": inventory,
        "insureready": ir,
        "reports": {
            "googlefix": google_check.render_googlefix(snap, findings),
            "tokenwatch": google_check.render_google_inventory(
                snap, inventory),
            "insureready": m365.render_insureready(snap, ir),
        },
    }
    scans = load_list(SCANS_PATH)
    scans.append(record)
    _save(SCANS_PATH, scans)
    return record


def google_landing_page(error=None):
    err = f'<div class="notice">{escape(error)}</div>' if error else ""
    gcfg = google_connect.config()
    if gcfg["configured"]:
        live_card = """
<div class="card">
  <h2>Live connection — connect your domain</h2>
  <p><strong>Status: setup is complete on this server.</strong>
  Your own super admin can authorize our service account in your
  Admin console (domain-wide delegation, read-only scopes) and
  register the domain — see
  <a href="/google/connect">connect your domain</a> for the exact
  steps and scope list, or
  <a href="/google/live-connection">how the live connection
  works</a>. The export scan below keeps working either way.</p>
</div>"""
    else:
        live_card = """
<div class="card">
  <h2>Live connection — connect your domain</h2>
  <p><strong>Status: setup is pending.</strong> A live connection
  is built for this scan — a service account your own super admin
  authorizes in your Admin console (domain-wide delegation,
  read-only scopes) — but it is not switched on until the product
  owner finishes the setup on the product owner's side. See
  <a href="/google/live-connection">how the live connection will
  work</a> and what its status is. Until then, the export scan
  below is how Google domains are scanned.</p>
</div>"""
    body = f"""
<h1>TenantCheck for Google Workspace</h1>
<p>Not on Microsoft 365? This is the companion scan for a Google
Workspace domain: <strong>the scan runs on an export today, a live
connection is built and waits on owner setup, and no Google
sign-in or password is asked for, ever</strong>. Your own admin
exports the domain's settings as one JSON file; the scan checks
2-Step Verification, dormant and admin accounts, third-party and
AI app access, Drive sharing settings and external group members
— and answers the same 25-question insurance questionnaire from
the same export, wherever a question honestly maps to Google
evidence.</p>
{err}
{live_card}
<div class="card">
  <h2>Upload your Google Workspace export</h2>
  <form method="post" action="/google/scan/upload" enctype="multipart/form-data">
    <label for="snapshot">Google Workspace snapshot JSON file</label>
    <input type="file" id="snapshot" name="snapshot" accept=".json,application/json" required>
    <button type="submit">Run the Google scan</button>
  </form>
  <p class="small"><a href="/google/how-to-export">How to export</a>
  explains the exact schema and where each part comes from (Admin
  SDK / GAM-style export). Honest limits up front: the live
  connection is code-complete but not switched on until the owner
  setup is done — <a href="/google/live-connection">its status
  page</a> says which — Drive item-level permission lists are not
  in the export (domain sharing settings are), and questions with
  no Google equivalent — Conditional Access is one — answer
  "Evidence missing" rather than borrowing a number.</p>
</div>
<div class="card">
  <h2>Or run the demo Google domain</h2>
  <p>A fictional 9-person dental studio with planted problems: a
  super admin with no 2-Step Verification, a forgotten AI app with
  Drive and mail access, 14 files shared with anyone who has the
  link.</p>
  <form method="post" action="/google/scan/demo">
    <button type="submit">Run the demo Google scan</button>
  </form>
</div>
<p class="small">{HONESTY_LINE}</p>
"""
    return page("TenantCheck for Google Workspace", body)


def google_export_page():
    body = f"""
<h1>How to export your Google Workspace snapshot</h1>
<p>The Google scan runs on one JSON file: a snapshot of your
domain's settings, produced by <strong>your own admin</strong> with
Google's own tools. Nothing connects to your domain from this
site, there is no Google sign-in here, and no Google credential is
ever collected. A live connection option is built in code and
described on the <a href="/google/live-connection">Google live
connection page</a> — until the owner setup switches it on, this
export is how scans run.</p>

<div class="card">
  <h2>The collector outline</h2>
  <p>An admin produces the file with the Google Admin SDK
  (Directory, Reports and Drive APIs) or a GAM-style command-line
  run — read-only reporting commands, run on the admin's own
  machine, signed in as the admin. In outline:</p>
  <ol>
    <li><strong>Users:</strong> list users with their suspended
    state, super-admin flag, 2-Step Verification enrolment
    (Reports / Directory user security fields) and last login
    time.</li>
    <li><strong>Domain settings:</strong> less secure app access,
    Drive external sharing level, the domain count of files shared
    with anyone with the link, and the password policy.</li>
    <li><strong>Third-party apps:</strong> the domain's OAuth /
    third-party app access list (app name, scopes, trusted state,
    users with access) from the Admin console's API controls /
    token audit report.</li>
    <li><strong>Groups:</strong> groups with whether external
    members are allowed and how many there are.</li>
    <li><strong>Mail forwarding:</strong> per-user forwarding
    settings the export records (settings only, never message
    contents).</li>
    <li><strong>Owner-stated facts:</strong> the same
    <code>securityControls</code> section as the Microsoft export —
    backup state, EDR and encryption coverage, training, written
    plans, penetration-test recency. Google cannot supply these;
    the admin states them, and anything unstated is reported as
    evidence missing. One deliberate omission:
    <code>conditionalAccessPolicyCount</code> is NOT part of the
    Google schema — Google has no Conditional Access, so that
    insurance question answers "Evidence missing" honestly.</li>
  </ol>
</div>

<div class="card">
  <h2>The schema, section by section</h2>
  <table>
    <tr><th>Section</th><th>What it holds</th></tr>
    <tr><td><code>users</code></td><td>primaryEmail, displayName,
    suspended, isAdmin, twoStepEnrolled (true/false/null),
    lastLoginDaysAgo</td></tr>
    <tr><td><code>domainSettings</code></td><td>lessSecureAppAccess,
    driveExternalSharing (allowed / allowedWithWarning / blocked),
    anyoneWithLinkFileCount, passwordPolicy</td></tr>
    <tr><td><code>oauthApps</code></td><td>appName, scopes,
    trusted, lastUsedDaysAgo, usersWithAccess</td></tr>
    <tr><td><code>groups</code></td><td>email, name, memberCount,
    externalMembers, allowsExternalMembers</td></tr>
    <tr><td><code>mailForwarding</code></td><td>userEmail,
    forwardTo[]</td></tr>
    <tr><td><code>securityControls</code></td><td>The owner-stated
    facts listed above</td></tr>
  </table>
  <p>The demo domain on this page is a complete worked example of
  the exact shape.</p>
</div>

<div class="card">
  <h2>Prefer not to export by hand?</h2>
  <p>A <a href="/google/live-connection">live connection</a> is
  built for this scan: your super admin authorizes our service
  account once, in your own Admin console, and the same snapshot
  is then read directly. Its status page says plainly whether it
  is switched on yet; the
  <a href="/google/connect">connect page</a> carries the steps
  and the exact scope list.</p>
</div>
<p class="small">{HONESTY_LINE}</p>
"""
    return page("How to export your Google Workspace snapshot", body)


def google_results_page(record):
    s = record["summary"]
    if record.get("source") == "google-live":
        honesty_note = """<p>Every item above is an issue to review,
  found by deterministic checks against what the live connection
  returned. This scan read the domain through a service account
  the domain's own admin authorized: domain Drive sharing
  settings, the less-secure-app setting and the password policy
  are owner-stated where they appear (the Directory API does not
  expose them), per-user mail forwarding is not read on this
  path, and anything the connection did not return is reported
  as evidence missing, never assumed.</p>"""
    else:
        honesty_note = """<p>Every item above is an issue to review,
  found by deterministic checks against the export provided. This
  scan is export-based: it has no live connection to Google, sees
  domain sharing settings rather than file-level permission
  lists, and reports anything the export does not contain as
  evidence missing, never assumed.</p>"""
    body = f"""
<h1>Google Workspace scan results</h1>
<p>Domain: <strong>{escape(record['firm'])}</strong><br>
Snapshot date: {escape(record['snapshot_date'])} ·
Scanned: {escape(record['timestamp'])}</p>

<div class="card">
  <h2>The headline numbers</h2>
  <table>
    <tr><th>Module</th><th>Result</th></tr>
    <tr><td>GoogleFix</td>
        <td><strong>{s['googlefix_findings']} findings</strong>
            in the fix plan</td></tr>
    <tr><td>App inventory</td>
        <td><strong>{s['tokenwatch_flagged']} of {s['tokenwatch_grants']} third-party apps flagged</strong> by risk</td></tr>
    <tr><td>InsureReady 365</td>
        <td><strong>{s['insureready_gaps']} of {s['insureready_questions']} insurance questions</strong> are gaps or missing evidence</td></tr>
  </table>
  <p>
    <a class="btn" href="/google/report/{record['id']}/googlefix">Download the fix plan</a>
    <a class="btn" href="/google/report/{record['id']}/tokenwatch">Download the app inventory</a>
    <a class="btn" href="/google/report/{record['id']}/insureready">Download the InsureReady questionnaire pack</a>
  </p>
  <p class="small">All downloads are Markdown reports carrying
  the DRAFT stamp below.</p>
</div>

<div class="card">
  <h2>GoogleFix — owner-approved fix plan</h2>
  <p>{escape(m365.FIX_PLAN_NOTE)}</p>
  {tenantfix_html(record['googlefix'])}
</div>

<div class="card">
  <h2>Third-party app inventory</h2>
  <p>Apps with access to the domain, ranked by scope sensitivity,
  with a loading for untrusted apps. Time unused raises the score
  only when the snapshot carries a real last-use date; exports
  usually carry none, so those apps show last used as unknown.</p>
  {tokenwatch_html(record['tokenwatch'])}
  {tokenwatch_ai_html(record['tokenwatch'])}
</div>

<div class="card">
  <h2>InsureReady 365 — insurance evidence</h2>
  <p>The same 25-question questionnaire as the Microsoft scan,
  answered from this export wherever a question honestly maps.
  Questions with no Google evidence source answer
  <em>Evidence missing</em> — including Conditional Access
  (IR-Q04), which has no Google equivalent.</p>
  {insureready_html(record['insureready'])}
</div>

<div class="card">
  <h2>Honesty note</h2>
  {honesty_note}
  <p class="small">{escape(m365.STAMP)}</p>
</div>
"""
    return page("Google Workspace scan results", body)


# ---------------------------------------------------------------------------
# Google live connection pages — domain-wide delegation
# (google_connect.py)
# ---------------------------------------------------------------------------

def google_live_connection_page():
    cfg = google_connect.config()
    if cfg["configured"]:
        status = f"""
<div class="deadline">
  <strong>Status, plainly:</strong> setup is complete on this server —
  the service account is configured, so the live connection is
  switched on. A domain is connected only when its own super
  admin authorizes our service account in their Admin console and
  registers the domain on the
  <a href="/google/connect">Google connect page</a>; until that
  moment we can see nothing of it. The export path
  (<a href="/google/how-to-export">how that works</a>) remains
  available.
</div>
<p>Uploading an export works, but it is a snapshot of one day. A
standing, read-only connection is what lets the same scan run
against the domain as it is now. This is exactly what the
connection requires:</p>"""
    else:
        status = f"""
<div class="deadline">
  <strong>Status, plainly:</strong> setup is pending. The live
  connection is <strong>not switched on</strong> yet, so nothing on
  this site connects to your domain. {PRODUCT} runs Google scans
  today on an uploaded export
  (<a href="/google/how-to-export">how that works</a>). What
  remains is setup on the product owner's side: the service
  account has to be created and configured on the server. The
  <a href="/google/connect">Google connect page</a> stays off
  until setup is finished, and it says the same thing this page
  does.
</div>
<p>Uploading an export works, but it is a snapshot of one day. A
standing, read-only connection is what lets the same scan run
against the domain as it is now. This is exactly what that
connection will require, so you can judge it before it exists:</p>"""
    body = f"""
<h1>The Google live connection — how it works</h1>
{status}

<div class="card">
  <h2>Step 1 — we create a service account</h2>
  <p>{PRODUCT} owns a service account in its own Google Cloud
  project, with a fixed, published list of <strong>read-only</strong>
  scopes: directory users, groups and membership, customer info,
  and the third-party app list for each user. By itself that
  account can read <strong>nothing</strong> in any customer domain.</p>
</div>
<div class="card">
  <h2>Step 2 — your admin authorizes it, not us</h2>
  <p>A super admin <strong>from your own firm</strong> opens Admin
  console → Security → Access and data control → API controls →
  Domain-wide delegation, and authorizes our service account's
  client ID with the exact scope list — the same flow Google
  itself designs for domain-wide tools. Authorization cannot be
  granted by us, by a salesperson, or by a regular user. Until
  that moment, we can see nothing.</p>
</div>
<div class="card">
  <h2>Step 3 — the same scan, read directly</h2>
  <p>With delegation in place, the app impersonates the admin
  email you registered, builds the same snapshot the export
  produces today, and runs the identical checks — same engine,
  same reports. What Google's Directory API cannot return (the
  domain's Drive sharing setting, per-user mail forwarding) is
  reported as not covered or owner-stated, never invented.</p>
</div>
<div class="card">
  <h2>Step 4 — you can revoke it any time</h2>
  <p>Deleting that one delegation entry in your Admin console
  ends all access immediately, by your admin, without asking us.
  Nothing on our side can restore it.</p>
</div>

<div class="notice">
  <strong>Standing rules, live or not:</strong> we never collect or
  store Google passwords — there is no password field anywhere in
  this product. One scope deserves a plain word:
  <code>admin.directory.user.security</code> (the third-party app
  list) has no read-only variant at Google — it can technically
  also revoke a user's app tokens. We only ever read with it, and
  it is requested because there is no narrower way to inventory
  the apps your users have authorized.
</div>
<p class="small">{HONESTY_LINE}</p>
"""
    return page("The Google live connection", body)


def google_connect_page(message=None):
    cfg = google_connect.config()
    notice = (f'<div class="notice">{escape(message)}</div>'
              if message else "")
    if not cfg["configured"]:
        body = f"""
<h1>Connect your Google Workspace domain</h1>
{notice}
<div class="deadline">
  <strong>Setup is pending.</strong> The live connection is switched
  off until setup is finished, so this page cannot register a
  domain and nothing has been sent to Google. When setup is done,
  your own super admin authorizes the delegation in your Admin
  console, on Google's screen. Nothing on this page asks for a
  Google password. See
  <a href="/google/live-connection">how the Google live
  connection works</a> for the scope list and the standing rules.
  In the meantime the
  <a href="/google">export-based Google scan</a> works exactly as
  before.
</div>
<p class="small">{HONESTY_LINE}</p>
"""
        return page("Connect your Google Workspace domain", body)

    scopes = "".join(
        f"<li><code>{escape(s)}</code></li>"
        for s in google_connect.READ_ONLY_SCOPES)
    connections = google_connect.load_connections()
    if connections:
        rows = []
        for conn in connections:
            domain = escape(conn.get("domain", ""))
            rows.append(f"""
<div class="card">
  <p>Domain: <code>{domain}</code><br>
  Admin email impersonated for reads:
  {escape(conn.get('admin_email', ''))}<br>
  Authorized: {escape(conn.get('authorized_at', ''))}</p>
  <form method="post" action="/google/connect/scan">
    <input type="hidden" name="domain" value="{domain}">
    <button type="submit">Run a live scan for this domain</button>
  </form>
</div>""")
        connected_html = ("<h2>Connected Google domains</h2>"
                          + "".join(rows))
    else:
        connected_html = ("<h2>Connected Google domains</h2>"
                          "<p>None yet. The first domain appears "
                          "here after its own admin authorizes the "
                          "delegation and it validates.</p>")
    body = f"""
<h1>Connect your Google Workspace domain</h1>
{notice}
<p>Connecting happens in your own Admin console, not on a consent
screen we control: a super admin <strong>from your firm</strong>
authorizes our service account once, with the exact scope list
below, and then registers the domain here so we can prove the
delegation works. We cannot grant it, pre-approve it, or see
anything before that moment.</p>
<div class="card">
  <h2>Step 1 — authorize in your Admin console</h2>
  <p>Admin console → Security → Access and data control → API
  controls → <strong>Domain-wide delegation → Add new</strong>.
  Paste this client ID:</p>
  <p><code>{escape(cfg['sa_client_id'])}</code></p>
  <p>…and exactly these scopes (comma-separated, as the console
  asks for them):</p>
  <ul>{scopes}</ul>
  <p>All are reads. One plain word, repeated from the status
  page: <code>admin.directory.user.security</code> has no
  read-only variant at Google — it can technically also revoke a
  user's app tokens; we only ever read the app list with it.
  Deleting this delegation entry later revokes all access
  immediately, without asking us.</p>
</div>
<div class="card">
  <h2>Step 2 — register the domain here</h2>
  <p>Tell us the domain and the admin email the connection should
  impersonate for reads (a real admin in your domain; a dedicated
  reporting admin is a good choice). We immediately make one
  read-only call to prove the delegation answers; <strong>only a
  domain that validates is recorded</strong> — a failed check
  records nothing.</p>
  <form method="post" action="/google/connect">
    <label for="domain">Google Workspace domain</label>
    <input type="text" id="domain" name="domain" placeholder="firm.ca" required>
    <label for="admin_email">Admin email to impersonate for reads</label>
    <input type="email" id="admin_email" name="admin_email" placeholder="admin@firm.ca" required>
    <button type="submit">Validate and connect this domain</button>
  </form>
</div>
{connected_html}
<p class="small">{HONESTY_LINE}</p>
"""
    return page("Connect your Google Workspace domain", body)


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
    "copilot": ("copilot_report", "CopilotReady oversharing audit"),
    "signin": ("signin_rules_evidence", "Sign-in rules evidence"),
    "governance": ("ai_governance_pack", "AI Governance Pack"),
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
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(payload)

    def _redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
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

    def do_HEAD(self):
        # Same routing, status and headers as GET (including the
        # security headers and Content-Length); _send withholds the
        # body, as HEAD requires.
        self._head_only = True
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/":
            joined = query.get("joined", [""])[0] == "1"
            self._send(200, landing_page(joined=joined))
        elif path == "/.well-known/security.txt":
            self._send(200, security_txt(),
                       content_type="text/plain; charset=utf-8")
        elif path == "/sitemap.xml":
            self._send(200, sitemap_xml(),
                       content_type="application/xml; charset=utf-8")
        elif path == "/robots.txt":
            self._send(200, robots_txt(),
                       content_type="text/plain; charset=utf-8")
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
        elif path == "/google":
            self._send(200, google_landing_page())
        elif path == "/google/how-to-export":
            self._send(200, google_export_page())
        elif path == "/google/live-connection":
            self._send(200, google_live_connection_page())
        elif path == "/google/connect":
            self._send(200, google_connect_page(
                message=query.get("msg", [""])[0] or None))
        elif path.startswith("/google/results/"):
            record = load_scan(path[len("/google/results/"):])
            if record is None \
                    or record.get("platform") != "google":
                self._not_found()
            else:
                self._send(200, google_results_page(record))
        elif path.startswith("/google/report/"):
            bits = path[len("/google/report/"):].split("/")
            record = load_scan(bits[0]) if bits else None
            module = bits[1] if len(bits) > 1 else ""
            if record is None \
                    or record.get("platform") != "google" \
                    or module not in GOOGLE_REPORT_FILES \
                    or module not in record.get("reports", {}):
                self._not_found()
            else:
                stem, _label = GOOGLE_REPORT_FILES[module]
                self._send(
                    200, record["reports"][module],
                    content_type="text/markdown; charset=utf-8",
                    extra_headers={
                        "Content-Disposition":
                            f'attachment; filename="tenantcheck365_'
                            f'{stem}_{record["id"]}.md"'})
        elif path.startswith("/results/"):
            record = load_scan(path[len("/results/"):])
            if record is None:
                self._not_found()
            elif record.get("platform") == "google":
                self._redirect(f"/google/results/{record['id']}")
            else:
                self._send(200, results_page(record))
        elif path.startswith("/report/"):
            bits = path[len("/report/"):].split("/")
            record = load_scan(bits[0]) if bits else None
            module = bits[1] if len(bits) > 1 else ""
            if record is None or module not in REPORT_FILES \
                    or module not in record.get("reports", {}):
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
        if path == "/google/scan/upload":
            self._handle_google_upload()
            return
        if path == "/google/scan/demo":
            with open(DEMO_GOOGLE_PATH, encoding="utf-8") as fh:
                gsnap = json.load(fh)
            grecord = run_google_and_store(gsnap, "demo")
            self._send(200, google_results_page(grecord))
            return
        form = self._form()
        if path == "/connect/scan":
            self._handle_connect_scan(form)
            return
        if path == "/google/connect":
            self._handle_google_connect(form)
            return
        if path == "/google/connect/scan":
            self._handle_google_connect_scan(form)
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

    def _handle_google_connect(self, form):
        domain = (form.get("domain") or "").strip()
        admin_email = (form.get("admin_email") or "").strip()
        ok, detail = google_connect.validate_connection(
            domain, admin_email)
        if ok:
            self._send(200, google_connect_page(
                f"Connected: {detail.get('domain', domain)} "
                "validated against Google and recorded. It is "
                "listed below, and its live scan can be run from "
                "this page."))
            return
        self._send(200, google_connect_page(
            f"Not connected. {detail} Nothing was recorded."))

    def _handle_google_connect_scan(self, form):
        cfg = google_connect.config()
        if not cfg["configured"]:
            self._send(200, google_connect_page())
            return
        domain = (form.get("domain") or "").strip().lower()
        if not domain \
                or google_connect.get_connection(domain) is None:
            self._send(400, error_page(
                "Unknown domain",
                "That domain has not been authorized and "
                "validated, so there is no live connection to "
                "scan. Connect it first from the Google connect "
                "page."))
            return
        try:
            outcome = google_connect.scan_domain(domain)
        except google_connect.GoogleError as exc:
            self._send(502, error_page(
                "Google could not be reached",
                str(exc)))
            return
        record = run_google_and_store(outcome["snapshot"],
                                      "google-live")
        self._send(200, google_results_page(record))

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

    def _handle_google_upload(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD:
            self._send(413, google_landing_page(
                "That file is too large for a domain snapshot "
                "(6 MB limit)."))
            return
        raw = self.rfile.read(length) if length else b""
        fields = parse_multipart(raw, self.headers.get("Content-Type"))
        content = fields.get("snapshot")
        if not content:
            self._send(400, google_landing_page(
                "Choose a Google Workspace snapshot JSON file first."))
            return
        try:
            snap = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, google_landing_page(
                "That file is not valid JSON. Upload the Google "
                "Workspace export exactly as produced — see the "
                "Google How to export page."))
            return
        problem = validate_google_snapshot(snap)
        if problem:
            self._send(400, google_landing_page(problem))
            return
        try:
            record = run_google_and_store(snap, "upload")
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            self._send(400, google_landing_page(
                f"That snapshot is missing fields the scan needs "
                f"({exc}). See the Google How to export page."))
            return
        self._send(200, google_results_page(record))


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
