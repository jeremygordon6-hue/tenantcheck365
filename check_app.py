#!/usr/bin/env python3
"""
TenantCheck 365 — automated end-to-end checks.

Starts the app on a scratch port, then verifies over HTTP: landing
content and founding prices, explainer pages, the demo scan flow
against the prototype's expected findings (TenantFix 10, TokenWatch
4 flagged of 10, InsureReady 23 gaps of 25), report downloads with the
DRAFT stamp, the upload flow (valid, invalid, incomplete snapshots),
founding-list persistence, and 404 handling, the CopilotReady
oversharing audit (copilot_audit.py — the demo tenant's planted
sharing inventory must produce its 7 findings, the script-shaped
fixture its 2, a snapshot without a sharing inventory must report
the audit as not covered, and a synthetic disabled-owner drive must
fire CA-DISABLED-OWNER), plus the SEO layer
(per-page meta descriptions, Open Graph and canonical tags, homepage
JSON-LD, /sitemap.xml, /robots.txt). Also re-runs the copied
engine's own verification (53/53) so the app provably ships the
verified engine. The guided export helper is covered too: the
/how-to-export page must offer the script (Option A) and the manual
fallback (Option B), /export-script must serve tools/
tenantcheck-export.ps1 as an attachment, and a fixture in exactly
the shape the script emits (tools/sample-script-output.json) must
pass the upload flow with its expected results.

data/founding.json and data/scans.json are backed up before the run
and restored afterwards, so test entries never pollute the real
stores.

The live Microsoft Graph connection (graph_connect.py) is covered
too, with no network and no real credentials: the pending state over
HTTP (no TENANTCHECK_MS_* env vars — /live-connection and /connect
must say setup is pending and refuse gracefully), a second server
run with fake env vars (consent URL builds, callback records the
tenant, the fake secret never lands on disk), and an in-process run
of the fetch layer against a mocked Graph transport built from the
demo snapshot, which must produce the export path's findings (modulo
the one documented Graph limitation: guest access breadth has no
directory signal, so TF-GUEST-BROAD cannot fire).

data/founding.json, data/scans.json and data/connections.json are
backed up before the run and restored afterwards.

The live Google Workspace connection (google_connect.py) is
covered the same way, with no network and no real key: the pending
state over HTTP (no TENANTCHECK_GOOGLE_* env vars —
/google/live-connection and /google/connect must say setup is
pending and refuse gracefully), the configured state on the
second server (fake env vars — status complete, the connect page
shows the client ID and scope list, and a registration attempt
fails honestly and records nothing because no RSA signer is
available to it), and an in-process run against a mocked Admin
SDK transport built from the demo Google snapshot with a fake
signer, which must produce the export path's findings (modulo the
documented live-path differences: mail forwarding is not read,
and the group allows-external-members setting has no Directory
API signal). The fake service-account key must never land in
data/google_connections.json.

Usage: python3 check_app.py   (exit 0 = all checks passed)
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

APP_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = 8796
BASE = f"http://127.0.0.1:{PORT}"
DATA_DIR = os.path.join(APP_DIR, "data")
STORE_FILES = [os.path.join(DATA_DIR, "founding.json"),
               os.path.join(DATA_DIR, "scans.json"),
               os.path.join(DATA_DIR, "connections.json"),
               os.path.join(DATA_DIR, "google_connections.json")]

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'} - {name}"
          + (f" ({detail})" if detail else ""))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def request(method, path, data=None, headers=None):
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers=headers or {})
    try:
        with OPENER.open(req, timeout=10) as resp:
            return resp.status, dict(resp.headers), \
                resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def norm(text):
    return re.sub(r"\s+", " ", text)


def get(path):
    status, headers, body = request("GET", path)
    return status, headers, norm(body)


def post_form(path, fields):
    data = urllib.parse.urlencode(fields).encode()
    return request("POST", path, data=data,
                   headers={"Content-Type":
                            "application/x-www-form-urlencoded"})


def post_multipart(path, field, filename, content):
    boundary = "----tenantcheck-boundary-7d1a"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; '
            f'filename="{filename}"\r\n'
            f"Content-Type: application/json\r\n\r\n").encode() \
        + content \
        + f"\r\n--{boundary}--\r\n".encode()
    status, headers, resp = request(
        "POST", path, data=body,
        headers={"Content-Type":
                 f"multipart/form-data; boundary={boundary}"})
    return status, headers, norm(resp)


def wait_ready(proc, timeout=12):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            status, _h, _b = request("GET", "/")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def main():
    backups = {}
    for path in STORE_FILES:
        backups[path] = open(path, "rb").read() \
            if os.path.exists(path) else None

    env = dict(os.environ, PORT=str(PORT), HOST="127.0.0.1")
    # Server 1 must look UNCONFIGURED no matter what the caller's
    # environment holds, so the Graph pending-state checks below are
    # deterministic.
    for var in ("TENANTCHECK_MS_CLIENT_ID",
                "TENANTCHECK_MS_REDIRECT_URI",
                "TENANTCHECK_MS_CLIENT_SECRET",
                "TENANTCHECK_GOOGLE_SA_EMAIL",
                "TENANTCHECK_GOOGLE_SA_CLIENT_ID",
                "TENANTCHECK_GOOGLE_SA_KEY"):
        env.pop(var, None)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(APP_DIR, "app.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        check("server starts and serves /", wait_ready(proc))

        # ---- landing ------------------------------------------------
        status, _h, body = get("/")
        check("landing returns 200", status == 200)
        check("landing carries the TenantCheck 365 brand",
              "TenantCheck 365" in body)
        check("landing presents TenantFix 365", "TenantFix 365" in body)
        check("landing presents TokenWatch", "TokenWatch" in body)
        check("landing presents InsureReady 365",
              "InsureReady 365" in body)
        check("landing presents CopilotReady as included in the scan",
              "CopilotReady" in body and "Included in the scan" in body)
        check("landing labels the Google Workspace companion as "
              "export-based and new",
              "TenantCheck for Google Workspace" in body
              and "Export-based — new" in body)
        check("landing presents the AI Governance Pack as included "
              "in the scan",
              "AI Governance Pack" in body
              and "acceptable-use policy" in body)
        check("landing shows TenantFix founding price $149 CAD",
              "$149 CAD" in body)
        check("landing shows monitoring founding price $39 CAD/month",
              "$39 CAD/month" in body)
        check("landing qualifies monitoring as a re-scan plan on "
              "request (no automatic scheduler)",
              "a re-scan plan: you send a fresh export" in body
              and "No automatic scheduler yet" in body)
        check("landing no longer promises re-scan alerts or "
              "scheduled re-scans",
              "re-scan alerts" not in body
              and "scheduled re-scans" not in body)
        check("landing shows bundle founding price $49 CAD/month",
              "$49 CAD/month" in body)
        check("landing labels prices as founding prices",
              "Founding price" in body)
        # NOTE: the pre-Stripe version of this check asserted the
        # landing says no payment is taken. Checkout was wired into
        # the live site on 2026-11-10 (see README history in git-era
        # notes / parent record), so the assertion now verifies the
        # landing's current, truthful claim instead.
        check("landing states checkout is open now",
              "checkout is open now" in body)
        check("landing honesty: does not certify compliance",
              "does not certify compliance" in body)
        check("landing honesty: not legal or insurance advice",
              "not legal or insurance advice" in body)
        check("founding form has a name field", 'name="name"' in body)
        check("founding form has an email field", 'name="email"' in body)
        check("founding form has a company field",
              'name="company"' in body)

        # ---- explainer pages ----------------------------------------
        status, _h, body = get("/scan")
        check("scan page returns 200", status == 200)
        check("scan page uses a multipart upload form",
              'enctype="multipart/form-data"' in body)
        check("scan page has the snapshot file field",
              'type="file"' in body and 'name="snapshot"' in body)
        check("scan page offers the demo scan",
              'action="/scan/demo"' in body)
        status, _h, body = get("/how-to-export")
        check("how-to-export returns 200", status == 200)
        check("how-to-export explains the Graph-shaped export",
              "Graph" in body)
        check("how-to-export states passwords are never asked for",
              "never ask for" in body and "password" in body)
        check("how-to-export offers the guided script (Option A)",
              "Option A" in body and "/export-script" in body)
        check("how-to-export keeps the manual fallback (Option B)",
              "Option B" in body)

        # ---- export script download --------------------------------
        status, headers, raw_body = request("GET", "/export-script")
        check("export-script route serves the script (200)",
              status == 200)
        check("export-script is served as a .ps1 attachment",
              "attachment" in headers.get("Content-Disposition", "")
              and "tenantcheck-export.ps1"
              in headers.get("Content-Disposition", ""))
        script_path = os.path.join(APP_DIR, "tools",
                                   "tenantcheck-export.ps1")
        disk_script = open(script_path, encoding="utf-8").read() \
            if os.path.exists(script_path) else ""
        check("export-script body is the script file on disk",
              bool(disk_script)
              and "Connect-MgGraph" in raw_body
              and "tenantcheck-snapshot.json" in raw_body
              and len(raw_body) == len(disk_script))
        status, _h, body = get("/live-connection")
        check("live-connection returns 200", status == 200)
        check("live-connection names the Azure app registration",
              "app registration" in body)
        check("live-connection names tenant admin consent",
              "tenant admin consent" in body)
        check("live-connection states it is not switched on",
              "not switched on" in body)
        check("live-connection describes monitoring as re-scans on "
              "request today (no alerts-on-change claim)",
              "re-scans on request" in body
              and "alerts on change" not in body)

        # ---- SEO: metadata, sitemap, robots ----------------------
        status, _h, raw_home = request("GET", "/")
        check("seo: homepage returns 200 (raw fetch)",
              status == 200)
        m = re.search(r'<meta name="description" content="([^"]*)"',
                      raw_home)
        home_desc = m.group(1) if m else None
        check("seo: homepage carries a meta description",
              bool(home_desc))
        check("seo: homepage carries og:title",
              'property="og:title"' in raw_home)
        check("seo: homepage carries the google-site-"
              "verification meta",
              '<meta name="google-site-verification" '
              'content="zSL9EpgwpfB0zGLIYpzCE0gk8uuYKcNteYM6LHS__MY">'
              in raw_home)
        check("seo: homepage carries the msvalidate.01 meta",
              '<meta name="msvalidate.01" '
              'content="5A6E6E3DD0931B9DB02307A62305125F">'
              in raw_home)
        check("seo: homepage canonical is the production root",
              '<link rel="canonical" '
              'href="https://tenantcheck365.ca/">' in raw_home)
        ld_types = []
        for raw_ld in re.findall(
                r'<script type="application/ld\+json">(.*?)</script>',
                raw_home, re.S):
            try:
                ld_types.append(json.loads(raw_ld).get("@type"))
            except ValueError:
                ld_types.append(None)
        check("seo: homepage JSON-LD parses (Organization + "
              "FAQPage)", ld_types == ["Organization", "FAQPage"])
        status, _h, sm = request("GET", "/sitemap.xml")
        check("seo: sitemap 200 listing exactly the public pages",
              status == 200 and all(
                  f"<loc>https://tenantcheck365.ca{p}</loc>" in sm
                  for p in ["/", "/scan", "/how-to-export",
                            "/live-connection", "/connect", "/google",
                            "/google/how-to-export",
                            "/google/live-connection",
                            "/google/connect"])
              and sm.count("<url>") == 9
              and "/results/" not in sm
              and "/export-script" not in sm)
        status, _h, rb = request("GET", "/robots.txt")
        check("seo: robots 200 referencing the sitemap",
              status == 200 and "Sitemap: "
              "https://tenantcheck365.ca/sitemap.xml" in rb)
        descs = set()
        for pth in ("/how-to-export", "/live-connection"):
            _st, _hh, raw_p = request("GET", pth)
            mm = re.search(
                r'<meta name="description" content="([^"]*)"', raw_p)
            if mm:
                descs.add(mm.group(1))
        check("seo: export and live-connection pages carry distinct "
              "descriptions, different from the homepage",
              len(descs) == 2 and home_desc not in descs)

        # ---- demo scan flow ------------------------------------------
        status, _h, body = post_form("/scan/demo", {})
        check("demo scan returns 200", status == 200)
        check("demo: TenantFix finds the 10 planted findings",
              "10 hardening findings" in body)
        check("demo: TokenWatch flags 4 of 10 grants",
              "4 of 10 app grants flagged" in body)
        check("demo: InsureReady finds 23 gaps of 25 questions",
              "23 of 25 insurance questions" in body)
        check("demo: CopilotReady finds the 7 planted oversharing "
              "findings", "7 Copilot oversharing findings" in body)
        check("demo: CopilotReady surfaces the anonymous edit link "
              "on Payroll and HR",
              "Payroll and HR" in body and "CA-ANYONE-LINK" in body)
        check("demo: worst grant MailFlow Pro is surfaced",
              "MailFlow Pro" in body)
        check("demo: AI apps view lists the planted AI apps",
              "AI apps with access to this tenant" in body
              and "Otter.ai" in body and "Grammarly" in body)
        check("demo: AI identification is labelled name-based",
              "by app name" in body
              and "would not be flagged here" in body)
        check("demo: fix plan states it does NOT apply fixes",
              "does NOT apply" in body)
        check("demo: results carry the DRAFT stamp",
              "DRAFT" in body and "does not certify compliance" in body)
        check("demo: sign-in rules evidence section present with "
              "the policy-contents limit stated",
              "Sign-in rules evidence" in body
              and "contents of those policies are not in the "
                  "snapshot" in body)
        m = re.search(r"/report/([0-9a-f]{12})/tenantfix", body)
        check("demo: results link to downloadable reports", bool(m))
        scan_id = m.group(1) if m else "missing"

        status, _h, body = get(f"/results/{scan_id}")
        check("results page re-renders from the stored record",
              status == 200 and "10 hardening findings" in body)

        scans = json.load(open(os.path.join(DATA_DIR, "scans.json")))
        rec = next((s for s in scans if s["id"] == scan_id), None)
        check("scan record persisted with the expected summary",
              rec is not None
              and rec["summary"]["tenantfix_findings"] == 10
              and rec["summary"]["tokenwatch_flagged"] == 4
              and rec["summary"]["tokenwatch_grants"] == 10
              and rec["summary"]["insureready_gaps"] == 23
              and rec["summary"]["insureready_questions"] == 25)
        check("scan record persisted sign-in evidence and a "
              "changes block",
              rec is not None and rec.get("signin", {})
              .get("ca_policy_count") == 0
              and "changes" in rec)
        check("scan record persisted the CopilotReady summary",
              rec is not None
              and rec["summary"]["copilot_covered"] is True
              and rec["summary"]["copilot_items"] == 6
              and rec["summary"]["copilot_findings"] == 7)

        # ---- report downloads ----------------------------------------
        status, headers, body = get(f"/report/{scan_id}/tenantfix")
        check("TenantFix report downloads (200)", status == 200)
        check("TenantFix report is an attachment",
              "attachment" in headers.get("Content-Disposition", ""))
        check("TenantFix report carries the DRAFT stamp",
              "DRAFT" in body and "TenantFix 365" in body)
        status, _h, body = get(f"/report/{scan_id}/tokenwatch")
        check("TokenWatch report downloads with MailFlow Pro flagged",
              status == 200 and "MailFlow Pro" in body
              and "DRAFT" in body)
        check("TokenWatch report carries the AI apps section with "
              "the name-based caveat",
              "AI apps in this tenant" in body
              and "Otter.ai" in body and "Grammarly" in body
              and "identified by app name" in body)
        status, _h, body = get(f"/report/{scan_id}/insureready")
        check("InsureReady pack downloads with IR-Q01 and DRAFT stamp",
              status == 200 and "IR-Q01" in body and "DRAFT" in body)
        check("broker pack: restructured as a questionnaire pack "
              "with a 25-question summary",
              "Questionnaire Pack" in body
              and "Questions in this pack: 25" in body
              and "IR-Q25" in body)
        check("broker pack: plain answers derived from status, "
              "including owner-to-complete wording",
              "Yes — supported by scan evidence" in body
              and "Owner to complete — no evidence in this scan"
              in body)
        check("broker pack: closing owner-review and attestation "
              "warning section present",
              "Before you give this pack to a broker or insurer"
              in body and "as fact at claim time" in body)
        status, _h, body = get(f"/report/{scan_id}/signin")
        check("sign-in evidence report downloads with the CA count "
              "and DRAFT stamp",
              status == 200 and "Sign-in Rules Evidence" in body
              and "Policies present in the snapshot: 0" in body
              and "DRAFT" in body)
        status, _h, body = get(f"/report/{scan_id}/governance")
        check("governance pack downloads with inventory, "
              "oversharing summary, template and DRAFT stamp",
              status == 200 and "AI Governance Pack" in body
              and "Otter.ai" in body and "Payroll and HR" in body
              and "TEMPLATE" in body and "[Firm name]" in body
              and "DRAFT" in body
              and "not legal advice" in body)
        check("governance pack evidence page separates scan "
              "evidence from owner-to-state items",
              "Evidence page" in body and "Owner to state" in body)
        status, _h, body = get(f"/report/{scan_id}/copilot")
        check("CopilotReady report downloads with CA-ANYONE-LINK and "
              "DRAFT stamp",
              status == 200 and "CopilotReady" in body
              and "CA-ANYONE-LINK" in body and "DRAFT" in body
              and "does not certify compliance" in body)
        status, _h, _b = get("/report/000000000000/tenantfix")
        check("report for an unknown scan is 404", status == 404)

        # ---- upload flow ----------------------------------------------
        demo_bytes = open(os.path.join(APP_DIR, "demo_snapshot.json"),
                          "rb").read()
        status, _h, body = post_multipart("/scan/upload", "snapshot",
                                          "demo_snapshot.json", demo_bytes)
        check("upload of a valid snapshot returns 200", status == 200)
        check("upload: TenantFix finds the 10 planted findings",
              "10 hardening findings" in body)
        check("upload: TokenWatch flags 4 of 10 grants",
              "4 of 10 app grants flagged" in body)
        check("upload: InsureReady finds 23 gaps",
              "23 of 25 insurance questions" in body)
        check("upload: CopilotReady finds the 7 planted findings",
              "7 Copilot oversharing findings" in body)

        # A fixture in exactly the shape tools/tenantcheck-export.ps1
        # emits (same sections, fields and null conventions) must scan
        # end to end: 3 TenantFix findings, 1 of 2 grants flagged,
        # 12 of 25 InsureReady gaps on the fixture firm, and 2
        # CopilotReady findings (a company-wide link and a disabled
        # account owner's OneDrive) from its sharing inventory.
        fixture_bytes = open(os.path.join(
            APP_DIR, "tools", "sample-script-output.json"), "rb").read()
        status, _h, body = post_multipart(
            "/scan/upload", "snapshot", "tenantcheck-snapshot.json",
            fixture_bytes)
        check("script-shaped fixture upload returns 200", status == 200)
        check("fixture: TenantFix finds the 3 expected findings",
              "3 hardening findings" in body)
        check("fixture: TokenWatch flags 1 of 2 grants",
              "1 of 2 app grants flagged" in body)
        check("fixture: InsureReady finds 12 gaps of 25 questions",
              "12 of 25 insurance questions" in body)
        check("fixture: AI view identifies ChatPDF Helper as an "
              "AI app",
              "AI apps with access to this tenant" in body
              and "ChatPDF" in body)
        check("fixture: CopilotReady finds 2 oversharing findings",
              "2 Copilot oversharing findings" in body
              and "CA-DISABLED-OWNER" in body)

        # An older export without a sharing inventory still scans,
        # and the CopilotReady section must say NOT COVERED — never
        # render the absence as a pass.
        noinv = json.loads(demo_bytes)
        del noinv["sharingInventory"]
        status, _h, body = post_multipart(
            "/scan/upload", "snapshot", "older-export.json",
            json.dumps(noinv).encode())
        check("upload without a sharing inventory returns 200",
              status == 200)
        check("no-inventory upload: CopilotReady reports not covered",
              "Not covered by this snapshot" in body
              and "no sharing inventory" in body)

        # ---- drift report: baseline then a mutated re-scan -----
        drift_base = json.loads(demo_bytes)
        drift_base["_meta"]["firm_name"] = \
            "Drift Test Firm (fictional)"
        status, _h, body = post_multipart(
            "/scan/upload", "snapshot", "drift1.json",
            json.dumps(drift_base).encode())
        m = re.search(r"/report/([0-9a-f]{12})/tenantfix", body)
        drift_id_1 = m.group(1) if m else "missing"
        status, _h, body = get(f"/results/{drift_id_1}")
        check("drift: first scan of a firm is the baseline",
              status == 200 and "Baseline scan" in body
              and "no earlier scan of this firm" in body)
        drift_mut = json.loads(json.dumps(drift_base))
        for u in drift_mut["users"]:
            if u["displayName"] == "Bob Patel":
                u["mfaRegistered"] = True
        status, _h, body = post_multipart(
            "/scan/upload", "snapshot", "drift2.json",
            json.dumps(drift_mut).encode())
        m = re.search(r"/report/([0-9a-f]{12})/tenantfix", body)
        drift_id_2 = m.group(1) if m else "missing"
        check("drift: re-scan returns a fresh record",
              status == 200 and drift_id_2 != drift_id_1
              and drift_id_2 != "missing")
        status, _h, body = get(f"/results/{drift_id_2}")
        check("drift: change section names the resolved MFA "
              "finding and the IR-Q02 status change",
              "What changed since the last scan" in body
              and "TF-MFA — Bob Patel" in body
              and "IR-Q02" in body and "Gap → Supported" in body)
        check("drift: copy states there is no email alerting or "
              "scheduler",
              "does not send drift alert emails" in body)

        bare_gov = json.loads(demo_bytes)
        del bare_gov["sharingInventory"]
        bare_gov["oauthGrants"] = [
            g for g in bare_gov["oauthGrants"]
            if g["appDisplayName"] not in ("Otter.ai", "Grammarly")]
        status, _h, body = post_multipart(
            "/scan/upload", "snapshot", "bare-gov.json",
            json.dumps(bare_gov).encode())
        m = re.search(r"/report/([0-9a-f]{12})/governance", body)
        gov_id = m.group(1) if m else "missing"
        status, _h, body = get(f"/report/{gov_id}/governance")
        check("governance pack on a bare snapshot states no AI "
              "tools identified and NOT COVERED, never a pass",
              status == 200
              and "No connected app was identified as an AI tool"
              in body and "NOT COVERED" in body)

        status, _h, body = post_multipart("/scan/upload", "snapshot",
                                          "bad.json", b"this is not json")
        check("upload of invalid JSON is rejected with 400",
              status == 400)
        check("invalid-JSON rejection is clean (no traceback)",
              "Traceback" not in body)

        thin = json.dumps({"users": []}).encode()
        status, _h, body = post_multipart("/scan/upload", "snapshot",
                                          "thin.json", thin)
        check("upload missing sections is rejected with 400",
              status == 400)
        check("missing-sections rejection names the problem",
              "missing section" in body)

        status, _h, _b = post_multipart("/scan/upload", "snapshot",
                                        "empty.json", b"")
        check("upload of an empty file is rejected with 400",
              status == 400)

        # ---- Google Workspace companion --------------------------
        status, _h, body = get("/")
        check("landing carries the Google Workspace card",
              "TenantCheck for Google Workspace" in body
              and 'href="/google"' in body)
        status, _h, body = get("/google")
        check("google page returns 200 with an upload form",
              status == 200 and 'action="/google/scan/upload"' in body
              and "no Google sign-in" in body)
        status, _h, body = get("/google/how-to-export")
        check("google how-to-export returns 200 and documents the "
              "schema and collector",
              status == 200 and "Admin SDK" in body and "GAM" in body
              and "securityControls" in body
              and "conditionalAccessPolicyCount" in body)
        status, _h, body = post_form("/google/scan/demo", {})
        check("google demo scan returns 200", status == 200)
        check("google demo: 11 findings in the fix plan",
              "11 findings" in body)
        check("google demo: 1 of 3 third-party apps flagged",
              "1 of 3 third-party apps flagged" in body)
        check("google demo: InsureReady finds 18 gaps of 25",
              "18 of 25 insurance questions" in body)
        check("google demo: AI view identifies ChatGPT and "
              "Otter.ai, ChatGPT flagged",
              "AI apps with access to this tenant" in body
              and "ChatGPT" in body and "Otter.ai" in body)
        check("google demo: IR-Q04 answers Evidence missing "
              "honestly", "IR-Q04" in body
              and "Evidence missing" in body)
        m = re.search(r"/google/report/([0-9a-f]{12})/googlefix",
                      body)
        check("google demo: results link to Google reports", bool(m))
        google_id = m.group(1) if m else "missing"
        status, _h, body = get(f"/google/report/{google_id}/googlefix")
        check("google fix plan downloads with GG-2SV and DRAFT",
              status == 200 and "GG-2SV" in body and "DRAFT" in body)
        status, _h, body = get(
            f"/google/report/{google_id}/insureready")
        check("google broker pack downloads with IR-Q01, IR-Q25 "
              "and the owner-review section",
              status == 200 and "IR-Q01" in body and "IR-Q25" in body
              and "Before you give this pack" in body)
        status, _h, _b = get(f"/results/{google_id}")
        check("M365 results URL for a Google record redirects to "
              "the Google results page", status == 303)
        google_bytes = open(os.path.join(
            APP_DIR, "demo_google_snapshot.json"), "rb").read()
        status, _h, body = post_multipart(
            "/google/scan/upload", "snapshot", "google.json",
            google_bytes)
        check("google upload of the demo snapshot returns the same "
              "findings", status == 200 and "11 findings" in body)
        status, _h, body = post_multipart(
            "/google/scan/upload", "snapshot", "bad.json",
            b"not json")
        check("google upload of invalid JSON is 400", status == 400)
        status, _h, body = post_multipart(
            "/google/scan/upload", "snapshot", "thin.json",
            json.dumps({"users": []}).encode())
        check("google upload missing sections is 400 and names "
              "the problem", status == 400
              and "missing section" in body)
        import google_check
        gsummary = google_check.verify(json.loads(google_bytes))
        check("google engine verifies its planted manifest "
              "(17 checks)", gsummary["checks_passed"] == 17
              and gsummary["checks_failed"] == 0,
              f"{gsummary['checks_passed']}/"
              f"{gsummary['total_checks']}")

        # ---- Google live connection: PENDING state (server 1 has
        # no TENANTCHECK_GOOGLE_* env vars) -------------------------
        gconn_path = os.path.join(DATA_DIR, "google_connections.json")

        def read_google_connections():
            if not os.path.exists(gconn_path):
                return []
            return json.load(open(gconn_path))

        status, _h, body = get("/google/live-connection")
        check("google pending: live-connection says setup is "
              "pending", status == 200 and "setup is pending" in body)
        check("google pending: live-connection hides env names, "
              "setup file names and the host",
              "TENANTCHECK_GOOGLE_SA_EMAIL" not in body
              and "TENANTCHECK_GOOGLE_SA_KEY" not in body
              and "SETUP-GOOGLE" not in body
              and "Render" not in body
              and "environment variable" not in body.lower())
        check("google pending: live-connection explains domain-wide "
              "delegation", "Domain-wide delegation" in body
              or "domain-wide delegation" in body)
        status, _h, body = get("/google/connect")
        check("google pending: connect page returns 200 and refuses "
              "gracefully", status == 200
              and "Setup is pending" in body)
        check("google pending: connect page offers no registration "
              "form", 'action="/google/connect"' not in body)
        gbefore = read_google_connections()
        status, _h, body = post_form(
            "/google/connect",
            {"domain": "ghost.example", "admin_email":
             "admin@ghost.example"})
        check("google pending: registration attempt records nothing",
              status == 200 and "Setup is pending" in body
              and read_google_connections() == gbefore)
        status, _h, body = get("/google")
        check("google landing carries the live connection card in "
              "its pending state",
              "Live connection — connect your domain" in body
              and "setup is pending" in body)

        # ---- founding list ---------------------------------------------
        status, _h, _b = post_form("/founding", {
            "name": "Check Person",
            "email": "check@tenantcheck-test.ca",
            "company": "Check Co"})
        check("founding signup redirects (303)", status == 303)
        entries = json.load(open(os.path.join(DATA_DIR, "founding.json")))
        entry = next((e for e in entries
                      if e.get("email") == "check@tenantcheck-test.ca"),
                     None)
        check("founding signup persists name, email and company",
              entry is not None and entry.get("name") == "Check Person"
              and entry.get("company") == "Check Co")
        status, _h, _b = post_form("/founding", {
            "name": "Check Person", "email": "not-an-email",
            "company": "Check Co"})
        check("founding signup with a bad email is 400", status == 400)
        status, _h, body = get("/?joined=1")
        check("landing thanks a new founding member",
              status == 200 and "on the founding list" in body)

        # ---- misc -------------------------------------------------------
        status, _h, _b = get("/no-such-page")
        check("unknown page is 404", status == 404)

        sys.path.insert(0, APP_DIR)
        import m365
        snap = m365.load_snapshot(
            os.path.join(APP_DIR, "demo_snapshot.json"))
        summary = m365.verify(snap, None)
        check("copied engine still verifies 53/53 on the demo snapshot",
              summary["checks_passed"] == 53
              and summary["checks_failed"] == 0,
              f"{summary['checks_passed']}/{summary['total_checks']}")

        # ---- CopilotReady audit: in-process unit checks -----------
        import copilot_audit
        ca_demo = copilot_audit.copilotaudit(snap)
        planted_ca = {(p["check"], p["subject"])
                      for p in snap["_planted"]["copilotaudit"]}
        actual_ca = {(f["check"], f["subject"])
                     for f in ca_demo["findings"]}
        check("copilot: every planted oversharing case is caught",
              planted_ca <= actual_ca,
              f"missing: {sorted(planted_ca - actual_ca)}")
        check("copilot: no unexpected findings (clean item silent)",
              actual_ca == planted_ca,
              f"unexpected: {sorted(actual_ca - planted_ca)}")
        check("copilot: every finding has severity, why and fix steps",
              all(f["severity"] and f["why"] and f["fix_steps"]
                  for f in ca_demo["findings"]))
        bare = {k: v for k, v in snap.items()
                if k != "sharingInventory"}
        ca_bare = copilot_audit.copilotaudit(bare)
        check("copilot: a snapshot with no sharing inventory is not "
              "covered and yields no findings",
              ca_bare["covered"] is False
              and ca_bare["findings"] == [])
        ca_report = copilot_audit.render_copilotaudit(snap, ca_demo)
        ca_bare_report = copilot_audit.render_copilotaudit(bare, ca_bare)
        check("copilot: reports carry the DRAFT stamp, covered and "
              "not covered alike",
              "DRAFT" in ca_report and "DRAFT" in ca_bare_report
              and "NOT COVERED" in ca_bare_report)
        check("copilot: report states the per-file link limit",
              "individual files" in ca_report)

        # ---- TokenWatch AI view: in-process unit checks ---------
        import copy as _cp2
        _n2, _tf2, tw_demo, _ir2 = m365.run_scan(
            _cp2.deepcopy(snap))
        ai_demo = m365.ai_apps(tw_demo)
        check("tokenwatch ai: demo inventory identifies exactly the "
              "2 planted AI apps",
              {i["app"] for i in ai_demo} == {"Otter.ai", "Grammarly"})
        check("tokenwatch ai: the flagged AI app is Otter.ai and "
              "the benign one is Grammarly",
              {i["app"] for i in ai_demo if i["flagged"]}
              == {"Otter.ai"})
        check("tokenwatch ai: identification is by name only — a "
              "plain Zoom grant and a generic app are not AI, a "
              "ChatGPT-named one is",
              m365.ai_label_for("Zoom") is None
              and m365.ai_label_for("Totally Generic App") is None
              and m365.ai_label_for("ChatGPT Enterprise") is not None)
        check("tokenwatch ai: scopes are rendered in plain English",
              any("read email" in p
                  for i in ai_demo for p in i["scopes_plain"]))

        # ---- InsureReady expansion: in-process unit checks ------
        import copy as _copy
        old_snap = _copy.deepcopy(snap)
        for key in ("writtenSecurityPolicyDocumented",
                    "penetrationTestLastMonthsAgo",
                    "backupOfflineOrImmutableCopy"):
            old_snap["securityControls"].pop(key, None)
        _n, _tf, _tw, old_ir = m365.run_scan(old_snap)
        by_id = {r["id"]: r for r in old_ir}
        check("insureready: 25 questions returned in order",
              [r["id"] for r in old_ir]
              == [f"IR-Q{n:02d}" for n in range(1, 26)])
        check("insureready: new owner-stated questions on an older "
              "export answer Evidence missing, never a pass",
              by_id["IR-Q18"]["status"] == "Evidence missing"
              and by_id["IR-Q19"]["status"] == "Evidence missing"
              and by_id["IR-Q21"]["status"] == "Evidence missing")
        check("insureready: scan-only questions (claims history, "
              "data volumes, remote access, email auth) always "
              "answer Evidence missing",
              all(by_id[q]["status"] == "Evidence missing"
                  for q in ("IR-Q22", "IR-Q23", "IR-Q24", "IR-Q25")))

        # ---- live Graph connection: PENDING state (server 1 has no
        # TENANTCHECK_MS_* env vars) --------------------------------
        conn_path = os.path.join(DATA_DIR, "connections.json")

        def read_connections():
            if not os.path.exists(conn_path):
                return []
            return json.load(open(conn_path))

        status, _h, body = get("/live-connection")
        check("graph pending: live-connection says setup is pending",
              "setup is pending" in body)
        check("graph pending: live-connection hides env names, "
              "setup file names and the host",
              "TENANTCHECK_MS_CLIENT_ID" not in body
              and "TENANTCHECK_MS_CLIENT_SECRET" not in body
              and "SETUP-GRAPH" not in body
              and "Render" not in body
              and "environment variable" not in body.lower())
        status, _h, body = get("/connect")
        check("graph pending: connect page returns 200 and refuses "
              "gracefully", status == 200 and "Setup is pending" in body)
        check("graph pending: connect page offers no consent link",
              "adminconsent" not in body)
        status, _h, body = post_form("/connect/scan",
                                     {"tenant_id": "anything"})
        check("graph pending: scan attempt stays on the pending page",
              status == 200 and "Setup is pending" in body)
        before = read_connections()
        status, _h, body = get("/connect/callback?tenant=ghost"
                               "&state=" + "0" * 32)
        check("graph pending: callback is graceful and records nothing",
              status == 200 and "Nothing was recorded" in body
              and read_connections() == before)

        # ---- fix pass (2026-11-13): CAD, dormancy honesty,
        # founding copy, env names off public pages, export scope
        # + skipped mailboxes, headers/HEAD, CASL, nav, insurer
        # claim ------------------------------------------------------
        status, _h, body = get("/")
        check("fix: landing labels its prices in CAD",
              "$149 CAD" in body and "$39 CAD/month" in body
              and "$49 CAD/month" in body)
        check("fix: founding copy says checkout is open (no "
              "cohort-opens waitlist text)",
              "Checkout is open now at the founding prices above"
              in body and "cohort opens" not in body)
        check("fix: founding form carries the CASL consent line "
              "(operator named, unsubscribe any time)",
              "CanCheck is operated by Jeremy Gordon" in body
              and "unsubscribe at any time" in body)
        check("fix: insurer claim is the softened, cited form",
              "many cyber-insurance renewal questionnaires now ask "
              "for configuration" in body
              and "insurers have stopped accepting" not in body)
        check("fix: TokenWatch copy no longer ranks exports by "
              "time unused; the demo date is labelled demo data",
              "how long it has sat unused" not in body
              and "Time unused changes" in body
              and "demo snapshot" in body.lower()
              and "last use stays unknown" in body)
        check("fix: pages carry a skip link and an aria-labelled "
              "nav", 'class="skip"' in body
              and 'aria-label="Primary"' in body
              and '<main id="main">' in body)
        status, _h, body = get("/how-to-export")
        check("fix: how-to-export names the least-privilege scope, "
              "not Mail.Read, and no ExecutionPolicy Bypass",
              "MailboxSettings.Read" in body
              and "Mail.Read" not in body
              and "ExecutionPolicy Bypass" not in body)
        check("fix: how-to-export says grant last use is unknown "
              "and skipped mailboxes are counted",
              "last use as unknown" in body
              and "counted as skipped" in body)
        for pth in ("/connect", "/google/connect",
                    "/google/live-connection"):
            status, _h, body = get(pth)
            check(f"fix: {pth} hides env names, setup files and "
                  "the host", status == 200
                  and "TENANTCHECK_" not in body
                  and "SETUP-G" not in body
                  and "Render" not in body
                  and "environment variable" not in body.lower())
        status, headers, _raw = request("GET", "/")
        check("fix: responses carry the five security headers",
              status == 200
              and headers.get("Strict-Transport-Security")
              == "max-age=31536000"
              and headers.get("X-Content-Type-Options") == "nosniff"
              and headers.get("X-Frame-Options") == "DENY"
              and headers.get("Referrer-Policy") == "same-origin"
              and "default-src 'self'" in headers.get(
                  "Content-Security-Policy", ""))
        status, headers, hbody = request("HEAD", "/")
        check("fix: HEAD / answers like GET (200, headers, no "
              "body)", status == 200 and hbody == ""
              and headers.get("X-Frame-Options") == "DENY")
        status, _h, _b = request("HEAD", "/no-such-page")
        check("fix: HEAD on an unknown path is 404, not 501",
              status == 404)
        status, _h, body = get("/.well-known/security.txt")
        check("fix: security.txt published with the contact "
              "address", status == 200
              and "Contact: mailto:jeremygordon6@gmail.com" in body)
        script = open(os.path.join(
            APP_DIR, "tools", "tenantcheck-export.ps1"),
            encoding="utf-8").read()
        check("fix: export script asks for MailboxSettings.Read, "
              "not Mail.Read",
              '"MailboxSettings.Read"' in script
              and '"Mail.Read"' not in script)
        check("fix: export script counts skipped mailboxes and "
              "writes exportCoverage",
              "mailboxesSkipped" in script
              and "exportCoverage" in script
              and "ExecutionPolicy Bypass" not in script)
        # A snapshot whose export skipped mailboxes must read the
        # forwarding answer as evidence missing, never as a pass.
        fixture = json.loads(open(os.path.join(
            APP_DIR, "tools", "sample-script-output.json"),
            encoding="utf-8").read())
        fixture["exportCoverage"] = {"mailboxesChecked": 4,
                                     "mailboxesSkipped": 2}
        status, _h, body = post_multipart(
            "/scan/upload", "snapshot", "skipped.json",
            json.dumps(fixture).encode())
        check("fix: skipped mailboxes surface as evidence missing "
              "on IR-Q07",
              status == 200 and "Evidence missing" in body
              and "could not be read by the export" in body
              and "2 mailbox(es) could not be read" in body)

        # ---- live Graph connection: CONFIGURED server (fake env) ---
        port2 = 8797
        base2 = f"http://127.0.0.1:{port2}"
        env2 = dict(env, PORT=str(port2))
        env2.update({
            "TENANTCHECK_MS_CLIENT_ID": "check-client-id",
            "TENANTCHECK_MS_REDIRECT_URI":
                "https://tenantcheck365.ca/connect/callback",
            "TENANTCHECK_MS_CLIENT_SECRET": "check-secret-not-real",
            "TENANTCHECK_GOOGLE_SA_EMAIL":
                "check-sa@check-project.iam.gserviceaccount.com",
            "TENANTCHECK_GOOGLE_SA_CLIENT_ID":
                "123456789012345678901",
            "TENANTCHECK_GOOGLE_SA_KEY":
                "check-google-key-not-real"})
        proc2 = subprocess.Popen(
            [sys.executable, os.path.join(APP_DIR, "app.py")],
            env=env2, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        try:
            deadline = time.time() + 12
            ready2 = False
            while time.time() < deadline and proc2.poll() is None:
                try:
                    req = urllib.request.Request(base2 + "/")
                    with OPENER.open(req, timeout=5) as resp:
                        ready2 = resp.status == 200
                    if ready2:
                        break
                except Exception:
                    time.sleep(0.25)
            check("configured server starts", ready2)

            def get2(path):
                req = urllib.request.Request(base2 + path)
                try:
                    with OPENER.open(req, timeout=10) as resp:
                        return resp.status, norm(
                            resp.read().decode("utf-8", "replace"))
                except urllib.error.HTTPError as e:
                    return e.code, norm(
                        e.read().decode("utf-8", "replace"))

            status, body = get2("/live-connection")
            check("graph configured: live-connection says setup is "
                  "complete", "setup is complete" in body)
            status, body = get2("/connect")
            check("graph configured: connect page builds the admin "
                  "consent URL",
                  "login.microsoftonline.com/organizations/adminconsent"
                  in body and "client_id=check-client-id" in body)
            mstate = re.search(r"state=([0-9a-f]{32})", body)
            check("graph configured: consent URL carries a state",
                  bool(mstate))
            state = mstate.group(1) if mstate else "0" * 32
            status, body = get2("/connect/callback"
                                "?tenant=check-tenant-1"
                                "&admin_consent=True&state=" + state)
            conns = read_connections()
            check("graph configured: callback records the consent",
                  "Consent recorded" in body
                  and any(c.get("tenant_id") == "check-tenant-1"
                          for c in conns))
            status, body = get2("/connect/callback?error=access_denied"
                                "&error_description=Admin+refused")
            check("graph configured: a refused consent records nothing",
                  "Consent not recorded" in body
                  and len(read_connections()) == len(conns))
            raw_conn = open(conn_path).read() \
                if os.path.exists(conn_path) else ""
            check("graph configured: the client secret is never "
                  "written to the connections store",
                  "check-secret-not-real" not in raw_conn)

            def post2(path, fields):
                data = urllib.parse.urlencode(fields).encode()
                req = urllib.request.Request(
                    base2 + path, data=data, method="POST",
                    headers={"Content-Type":
                             "application/x-www-form-urlencoded"})
                try:
                    with OPENER.open(req, timeout=10) as resp:
                        return resp.status, norm(
                            resp.read().decode("utf-8", "replace"))
                except urllib.error.HTTPError as e:
                    return e.code, norm(
                        e.read().decode("utf-8", "replace"))

            status, body = get2("/google/live-connection")
            check("google configured: live-connection says setup is "
                  "complete", "setup is complete" in body)
            status, body = get2("/google/connect")
            check("google configured: connect page shows the client "
                  "ID customers must authorize",
                  "123456789012345678901" in body)
            check("google configured: connect page shows the exact "
                  "scope list",
                  "admin.directory.user.readonly" in body
                  and "admin.directory.user.security" in body)
            check("google configured: connect page offers the "
                  "registration form",
                  'action="/google/connect"' in body)
            status, body = post2(
                "/google/connect",
                {"domain": "unvalidatable.example",
                 "admin_email": "admin@unvalidatable.example"})
            check("google configured: a registration that cannot "
                  "validate records nothing",
                  status == 200 and "Not connected" in body
                  and "Nothing was recorded" in body
                  and not any(
                      c.get("domain") == "unvalidatable.example"
                      for c in read_google_connections()))
            raw_gconn = open(gconn_path).read() \
                if os.path.exists(gconn_path) else ""
            check("google configured: the service account key is "
                  "never written to the connections store",
                  "check-google-key-not-real" not in raw_gconn)
        finally:
            proc2.terminate()
            try:
                proc2.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc2.kill()

        # ---- live Graph connection: mocked tenant end to end -------
        import copy
        import datetime
        import graph_connect

        demo = json.load(open(os.path.join(APP_DIR,
                                           "demo_snapshot.json")))
        pinned_today = datetime.date(2026, 11, 9)  # demo snapshot_date

        def iso_days_ago(days):
            day = pinned_today - datetime.timedelta(days=days)
            return day.isoformat() + "T09:00:00Z"

        by_upn = {u["userPrincipalName"]: u for u in demo["users"]}
        domain = demo["users"][0]["userPrincipalName"].split("@")[1]

        sp_by_client = {}
        for g in demo["oauthGrants"]:
            sp_by_client.setdefault(g["clientId"], {
                "id": "spobj-" + g["clientId"],
                "appId": g["clientId"],
                "displayName": g["appDisplayName"],
                "verifiedPublisher": {"displayName": "publisher"}
                if g["publisherVerified"] else {}})
        sp_by_resource = {}
        for g in demo["oauthGrants"]:
            sp_by_resource.setdefault(g["resourceDisplayName"], {
                "id": "spobj-res-" + g["resourceDisplayName"]
                      .replace(" ", "-"),
                "appId": "app-res",
                "displayName": g["resourceDisplayName"],
                "verifiedPublisher": {"displayName": "Microsoft"}})
        all_sps = list(sp_by_client.values()) \
            + list(sp_by_resource.values())

        graph_users = [{
            "id": u["id"], "displayName": u["displayName"],
            "userPrincipalName": u["userPrincipalName"],
            "accountEnabled": u["accountEnabled"],
            "userType": "Guest" if u["accountType"] == "guest"
                        else "Member",
            "department": u.get("department"),
            "signInActivity": (
                {"lastSignInDateTime":
                 iso_days_ago(u["lastSignInDaysAgo"])}
                if u.get("lastSignInDaysAgo") is not None else {}),
        } for u in demo["users"]]
        reg_details = [{
            "userPrincipalName": u["userPrincipalName"],
            "isMfaRegistered": u["mfaRegistered"],
            "methodsRegistered": u.get("authMethods") or [],
        } for u in demo["users"]
            if u["accountType"] != "sharedMailbox"]
        role_assignments = [{
            "principalId": u["id"],
            "roleDefinition": {"displayName": role},
        } for u in demo["users"] for role in (u.get("roles") or [])]
        graph_grants = [{
            "id": g["id"],
            "clientId": sp_by_client[g["clientId"]]["id"],
            "resourceId": sp_by_resource[g["resourceDisplayName"]]["id"],
            "scope": " ".join(g["scopes"]),
            "consentType": g["consentType"],
            "principalId": (by_upn[g["consentedBy"]]["id"]
                            if g["consentType"] == "Principal"
                            and g["consentedBy"] in by_upn else None),
        } for g in demo["oauthGrants"]]
        rules_by_user = {}
        for r in demo["inboxRules"]:
            owner = by_upn[r["userPrincipalName"]]
            rules_by_user.setdefault(owner["id"], []).append({
                "id": r["id"], "displayName": r["name"],
                "isEnabled": r["enabled"],
                "actions": {
                    "forwardToRecipients": [
                        {"emailAddress": {"address": a}}
                        for a in r["forwardTo"]],
                    "redirectToRecipients": [
                        {"emailAddress": {"address": a}}
                        for a in r["redirectTo"]],
                    "deleteMessage": r["deleteMessage"]}})

        calls = []

        def mock_transport(method, url, headers=None, form=None):
            calls.append((method, url, form))
            if url.endswith("/oauth2/v2.0/token"):
                return 200, {"access_token": "mock-access-token",
                             "expires_in": 3600}
            if "/organization" in url:
                return 200, {"value": [{
                    "id": "mock-tenant-1",
                    "displayName": demo["_meta"]["firm_name"],
                    "verifiedDomains": [{"name": domain,
                                         "isDefault": True}]}]}
            if "messageRules" in url:
                uid = url.split("/users/")[1].split("/")[0]
                return 200, {"value": rules_by_user.get(uid, [])}
            if "/users?" in url:
                return 200, {"value": graph_users}
            if "userRegistrationDetails" in url:
                return 200, {"value": reg_details}
            if "roleAssignments" in url:
                return 200, {"value": role_assignments}
            if "/servicePrincipals" in url:
                return 200, {"value": all_sps}
            if "/oauth2PermissionGrants" in url:
                return 200, {"value": graph_grants}
            if "conditionalAccess/policies" in url:
                return 200, {"value": []}
            if "identitySecurityDefaultsEnforcementPolicy" in url:
                return 200, {"isEnabled":
                             not demo["tenantSettings"]
                                     ["legacyAuthenticationEnabled"]}
            if "sharepoint/settings" in url:
                return 200, {"sharingCapability":
                             "externalUserAndGuestSharing"}
            if "/auditLogs/signIns" in url:
                mapp = re.search(r"appId eq '([^']+)'",
                                 urllib.parse.unquote(url))
                grant = next((g for g in demo["oauthGrants"]
                              if g["clientId"] == mapp.group(1)), None)
                if grant is None \
                        or grant.get("lastUsedDaysAgo") is None:
                    return 200, {"value": []}
                return 200, {"value": [{
                    "createdDateTime":
                    iso_days_ago(grant["lastUsedDaysAgo"])}]}
            return 404, {"error": {"message": "mock: unmapped URL"}}

        saved_env = {k: os.environ.get(k) for k in (
            "TENANTCHECK_MS_CLIENT_ID", "TENANTCHECK_MS_REDIRECT_URI",
            "TENANTCHECK_MS_CLIENT_SECRET")}
        os.environ.update({
            "TENANTCHECK_MS_CLIENT_ID": "check-client-id",
            "TENANTCHECK_MS_REDIRECT_URI":
                "https://tenantcheck365.ca/connect/callback",
            "TENANTCHECK_MS_CLIENT_SECRET": "check-secret-not-real"})
        try:
            _rn, ref_tf_list, ref_tw_list, ref_ir_list = \
                m365.run_scan(copy.deepcopy(demo))
            owner_controls = {
                k: v for k, v in demo["securityControls"].items()
                if k != "conditionalAccessPolicyCount"}
            graph_connect.record_connection(
                "mock-tenant-1",
                {"security_controls": owner_controls,
                 "tenant_settings": {
                     "passwordPolicy":
                     demo["tenantSettings"]["passwordPolicy"]}})

            token = graph_connect.get_token(
                "mock-tenant-1", transport=mock_transport)
            token_forms = [f for (_m, u, f) in calls
                           if u.endswith("/oauth2/v2.0/token")]
            check("graph mock: token comes from the client "
                  "credentials flow",
                  token == "mock-access-token" and token_forms
                  and token_forms[0].get("grant_type")
                  == "client_credentials")
            check("graph mock: the secret travels only in the token "
                  "request", token_forms
                  and token_forms[0].get("client_secret")
                  == "check-secret-not-real")

            built = graph_connect.fetch_snapshot(
                "mock-tenant-1", transport=mock_transport,
                today=pinned_today)
            check("graph mock: fetch leaves nothing missing once "
                  "owner-stated facts are recorded",
                  built["missing"] == [])
            check("graph mock: all 18 demo users arrive in the "
                  "snapshot",
                  len(built["snapshot"]["users"]) == 18)

            _gn, got_tf_list, got_tw_list, got_ir_list = \
                m365.run_scan(copy.deepcopy(built["snapshot"]))
            from collections import Counter
            ref_tf = Counter(f["check"] for f in ref_tf_list)
            got_tf = Counter(f["check"] for f in got_tf_list)
            check("graph mock: TenantFix matches the export path "
                  "except TF-GUEST-BROAD (no Graph signal for guest "
                  "access breadth)",
                  ref_tf - got_tf == Counter({"TF-GUEST-BROAD": 1})
                  and got_tf - ref_tf == Counter()
                  and len(got_tf_list) == 9)
            check("graph mock: TokenWatch inventory is identical to "
                  "the export path",
                  got_tw_list == ref_tw_list)
            ref_ir = [(r["id"], r["status"], r["gap"])
                      for r in ref_ir_list if r["id"] != "IR-Q20"]
            got_ir = [(r["id"], r["status"], r["gap"])
                      for r in got_ir_list if r["id"] != "IR-Q20"]
            check("graph mock: InsureReady answers match the export "
                  "path (except IR-Q20, which rests on TF-GUEST-"
                  "BROAD — no Graph signal for guest breadth)",
                  got_ir == ref_ir)
            ref_q20 = next(r for r in ref_ir_list
                           if r["id"] == "IR-Q20")
            got_q20 = next(r for r in got_ir_list
                           if r["id"] == "IR-Q20")
            check("graph mock: IR-Q20 differs only by the documented "
                  "guest-breadth signal gap",
                  ref_q20["status"] == "Gap"
                  and got_q20["status"] == "Supported")

            outcome = graph_connect.scan_tenant(
                "mock-tenant-1", transport=mock_transport,
                today=pinned_today)
            check("graph mock: scan_tenant runs the engine end to "
                  "end", outcome["status"] == "scanned")

            graph_connect.record_connection("mock-tenant-3")
            outcome = graph_connect.scan_tenant(
                "mock-tenant-3", transport=mock_transport,
                today=pinned_today)
            check("graph mock: without owner-stated facts the scan "
                  "refuses and names what is missing",
                  outcome["status"] == "incomplete"
                  and "securityControls.backupEnabled"
                  in outcome["missing"]
                  and "tenantSettings.passwordPolicy"
                  in outcome["missing"])

            url, state = graph_connect.admin_consent_url()
            status, _detail = graph_connect.handle_callback(
                {"tenant": "unit-tenant", "admin_consent": "True",
                 "state": state})
            check("graph unit: a well-formed callback records the "
                  "tenant", status == "recorded"
                  and graph_connect.get_connection("unit-tenant")
                  is not None)
            status, _detail = graph_connect.handle_callback(
                {"tenant": "unit-tenant", "admin_consent": "True",
                 "state": "0" * 32})
            check("graph unit: a callback with a bad state records "
                  "nothing", status == "invalid_state")

            for var in saved_env:
                os.environ.pop(var, None)
            refused = False
            try:
                graph_connect.admin_consent_url()
            except graph_connect.GraphNotConfigured:
                refused = True
            status, _detail = graph_connect.handle_callback(
                {"tenant": "x", "state": "y"})
            check("graph unit: unconfigured, consent refuses and the "
                  "callback records nothing",
                  not graph_connect.config()["scan_ready"] and refused
                  and status == "not_configured")
        finally:
            for var, val in saved_env.items():
                if val is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = val

        # ---- live Google connection: mocked domain end to end -----
        import google_connect

        gdemo = json.loads(google_bytes)
        gpinned = datetime.date(2026, 11, 13)  # demo snapshot_date
        gdomain = gdemo["users"][0]["primaryEmail"].split("@")[1]
        gadmin = "admin@" + gdomain

        def giso(days):
            if days is None:
                return "1970-01-01T00:00:00.000Z"
            day = gpinned - datetime.timedelta(days=days)
            return day.isoformat() + "T09:00:00Z"

        gusers = [{
            "primaryEmail": u["primaryEmail"],
            "name": {"fullName": u["displayName"]},
            "suspended": u["suspended"],
            "isAdmin": u["isAdmin"],
            **({"isEnrolledIn2Sv": u["twoStepEnrolled"]}
               if u["twoStepEnrolled"] is not None else {}),
            "lastLoginTime": giso(u["lastLoginDaysAgo"]),
        } for u in gdemo["users"]]
        all_emails = [u["primaryEmail"] for u in gdemo["users"]
                      if not u["suspended"]]
        tokens_by_email = {}
        for app in gdemo["oauthApps"]:
            for email in all_emails[:app["usersWithAccess"]]:
                tokens_by_email.setdefault(email, []).append({
                    "clientId": app["clientId"],
                    "displayText": app["appName"],
                    "scopes": app["scopes"]})
        members_by_group = {}
        for g in gdemo["groups"]:
            internal = all_emails[:g["memberCount"]
                                  - g["externalMembers"]]
            external = [f"contractor{i + 1}@outside.example"
                        for i in range(g["externalMembers"])]
            members_by_group[g["email"]] = [
                {"email": e, "type": "USER", "role": "MEMBER"}
                for e in internal + external]

        gcalls = []

        def gmock(method, url, headers=None, form=None):
            gcalls.append((method, url, form))
            if url == google_connect.TOKEN_URL:
                return 200, {"access_token": "mock-google-token",
                             "expires_in": 3600}
            if "/customer/my_customer" in url:
                return 200, {
                    "alternateEmail": gadmin,
                    "postalAddress": {
                        "organizationName":
                            gdemo["_meta"]["firm_name"]}}
            if "/tokens" in url:
                email = urllib.parse.unquote(
                    url.split("/users/")[1].split("/")[0])
                return 200, {"items": tokens_by_email.get(email, [])}
            if "/groups/" in url and "/members" in url:
                gemail = urllib.parse.unquote(
                    url.split("/groups/")[1].split("/")[0])
                return 200, {"items":
                             members_by_group.get(gemail, [])}
            if "/groups?" in url:
                return 200, {"items": [{
                    "email": g["email"], "name": g["name"],
                    "directMembersCount": g["memberCount"]}
                    for g in gdemo["groups"]]}
            if "/users?" in url:
                if "maxResults=1" in url:
                    return 200, {"items": gusers[:1]}
                return 200, {"items": gusers}
            return 404, {"error": {"message": "mock: unmapped URL"}}

        def gmock_fail(method, url, headers=None, form=None):
            if url == google_connect.TOKEN_URL:
                return 200, {"access_token": "mock-google-token",
                             "expires_in": 3600}
            return 403, {"error": {"message": "not authorized"}}

        signer_keys = []

        def gsigner(signing_input, key_pem):
            signer_keys.append(key_pem)
            return "mock-signature"

        gvars = ("TENANTCHECK_GOOGLE_SA_EMAIL",
                 "TENANTCHECK_GOOGLE_SA_CLIENT_ID",
                 "TENANTCHECK_GOOGLE_SA_KEY")
        gsaved = {k: os.environ.get(k) for k in gvars}
        os.environ.update({
            "TENANTCHECK_GOOGLE_SA_EMAIL":
                "check-sa@check-project.iam.gserviceaccount.com",
            "TENANTCHECK_GOOGLE_SA_CLIENT_ID":
                "123456789012345678901",
            # The whole JSON key shape, to prove it is unwrapped
            # to its private_key and never stored.
            "TENANTCHECK_GOOGLE_SA_KEY": json.dumps({
                "type": "service_account",
                "private_key": "mock-pem-key-not-real",
                "client_email":
                    "check-sa@check-project.iam.gserviceaccount.com"})})
        try:
            check("google unit: configured() is true once all three "
                  "env vars are present",
                  google_connect.configured())
            _hdr, claims = google_connect.build_jwt_claims(
                gadmin, now=1700000000)
            check("google unit: JWT claims carry the impersonated "
                  "admin and exactly the shipped scope list",
                  claims["iss"] ==
                  "check-sa@check-project.iam.gserviceaccount.com"
                  and claims["sub"] == gadmin
                  and claims["scope"].split() ==
                  list(google_connect.READ_ONLY_SCOPES))

            ok, _detail = google_connect.validate_connection(
                "fail.example", "admin@fail.example",
                transport=gmock_fail, signer=gsigner)
            check("google mock: a validation Google refuses records "
                  "nothing", not ok
                  and google_connect.get_connection("fail.example")
                  is None)

            ok, entry = google_connect.validate_connection(
                gdomain, gadmin, transport=gmock, signer=gsigner)
            check("google mock: a successful validation records the "
                  "domain", ok
                  and entry.get("domain") == gdomain
                  and entry.get("admin_email") == gadmin)
            token_forms = [f for (_m, u, f) in gcalls
                           if u == google_connect.TOKEN_URL]
            check("google mock: the token exchange is the JWT "
                  "bearer flow, signed by the injected signer",
                  bool(token_forms)
                  and token_forms[0].get("grant_type")
                  == google_connect.JWT_GRANT_TYPE
                  and token_forms[0].get("assertion", "")
                  .endswith(".mock-signature")
                  and signer_keys
                  and signer_keys[0] == "mock-pem-key-not-real")
            raw_gstore = open(gconn_path).read() \
                if os.path.exists(gconn_path) else ""
            check("google mock: neither the key nor the access "
                  "token is written to the connections store",
                  "mock-pem-key-not-real" not in raw_gstore
                  and "mock-google-token" not in raw_gstore)

            google_connect.record_connection(
                gdomain, gadmin,
                {"security_controls": gdemo["securityControls"],
                 "domain_settings": gdemo["domainSettings"]})
            built = google_connect.fetch_snapshot(
                gdomain, transport=gmock, signer=gsigner,
                today=gpinned)
            check("google mock: fetch leaves nothing missing once "
                  "owner-stated facts are recorded",
                  built["missing"] == [])
            check("google mock: not-covered names mail forwarding "
                  "but not the owner-stated Drive setting",
                  any("mailForwarding" in n
                      for n in built["not_covered"])
                  and not any("driveExternalSharing" in n
                              for n in built["not_covered"]))

            exp_f, exp_inv, exp_ir, _ea = google_check.run_google_scan(
                copy.deepcopy(gdemo))
            got_f, got_inv, got_ir, _ga = \
                google_check.run_google_scan(
                    copy.deepcopy(built["snapshot"]))
            exp_pairs = {(f["check"], f["subject"]) for f in exp_f}
            got_pairs = {(f["check"], f["subject"]) for f in got_f}
            check("google mock: findings match the export path "
                  "except GG-GROUP-EXTERNAL (the Directory API "
                  "exposes membership, not the allows-external "
                  "setting)",
                  got_pairs == exp_pairs
                  - {("GG-GROUP-EXTERNAL", "Billing Contractors")})
            check("google mock: flagged and AI app sets match the "
                  "export path",
                  {i["app"] for i in got_inv if i["flagged"]}
                  == {i["app"] for i in exp_inv if i["flagged"]}
                  and {i["app"] for i in got_inv if i["is_ai"]}
                  == {i["app"] for i in exp_inv if i["is_ai"]})
            exp_status = {r["id"]: r["status"] for r in exp_ir}
            got_status = {r["id"]: r["status"] for r in got_ir}
            ir_diff = {q for q in exp_status
                       if exp_status[q] != got_status.get(q)}
            check("google mock: InsureReady answers match the "
                  "export path except IR-Q07 (mail forwarding not "
                  "read) and IR-Q20 (guest breadth rests on the "
                  "group finding above)",
                  ir_diff == {"IR-Q07", "IR-Q20"})

            outcome = google_connect.scan_domain(
                gdomain, transport=gmock, signer=gsigner,
                today=gpinned)
            check("google mock: scan_domain runs the engine end to "
                  "end", outcome["status"] == "scanned"
                  and len(outcome["findings"]) == len(got_f))

            for var in gvars:
                os.environ.pop(var, None)
            ok2, _d2 = google_connect.validate_connection(
                gdomain, gadmin, transport=gmock, signer=gsigner)
            raised = False
            try:
                google_connect.get_access_token(
                    gadmin, transport=gmock, signer=gsigner)
            except google_connect.GoogleNotConfigured:
                raised = True
            check("google unit: unconfigured, validation refuses "
                  "and the token flow raises GoogleNotConfigured",
                  not google_connect.configured() and not ok2
                  and raised)
        finally:
            for var, val in gsaved.items():
                if val is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = val
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        for path, blob in backups.items():
            if blob is None:
                if os.path.exists(path):
                    os.remove(path)
            else:
                with open(path, "wb") as fh:
                    fh.write(blob)

    passed = sum(1 for _n, ok in RESULTS if ok)
    print(f"\nChecks passed: {passed} / {len(RESULTS)} | "
          f"Failed: {len(RESULTS) - passed}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
