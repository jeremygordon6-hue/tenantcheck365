#!/usr/bin/env python3
"""
TenantCheck 365 — automated end-to-end checks.

Starts the app on a scratch port, then verifies over HTTP: landing
content and founding prices, explainer pages, the demo scan flow
against the prototype's expected findings (TenantFix 10, TokenWatch
3 flagged of 8, InsureReady 11 gaps of 13), report downloads with the
DRAFT stamp, the upload flow (valid, invalid, incomplete snapshots),
founding-list persistence, and 404 handling, plus the SEO layer
(per-page meta descriptions, Open Graph and canonical tags, homepage
JSON-LD, /sitemap.xml, /robots.txt). Also re-runs the copied
engine's own verification (40/40) so the app provably ships the
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
               os.path.join(DATA_DIR, "connections.json")]

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
                "TENANTCHECK_MS_CLIENT_SECRET"):
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
        check("landing shows TenantFix founding price $149 CAD",
              "$149 CAD" in body)
        check("landing shows monitoring founding price $39 CAD/month",
              "$39 CAD/month" in body)
        check("landing shows bundle founding price $49 CAD/month",
              "$49 CAD/month" in body)
        check("landing labels prices as founding prices",
              "Founding price" in body)
        # Checkout is the three Stripe Payment Links on the landing
        # page. The founding list records a contact; it does not say
        # the cohort is still closed.
        check("landing states checkout is open now",
              "checkout is open now" in body)
        check("landing does not say the cohort is still closed",
              "when the founding cohort opens" not in body)
        check("landing does not claim every grant is ranked by time unused",
              "how long it has sat unused" not in body)
        check("landing says time unused counts only with a real last-use date",
              "real last-use date" in body)
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
        check("how-to-export does not use ExecutionPolicy Bypass",
              "ExecutionPolicy Bypass" not in body
              and "-ExecutionPolicy Bypass" not in body)
        check("how-to-export uses Unblock-File and process scope",
              "Unblock-File" in body
              and "-Scope Process" in body
              and "RemoteSigned" in body)
        check("how-to-export says grant last use is not in the export",
              "Last use is not" in body
              and "do not include it" in body)

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
        check("export script does not instruct ExecutionPolicy Bypass",
              "ExecutionPolicy Bypass" not in disk_script
              and "Unblock-File" in disk_script
              and "-Scope Process" in disk_script)
        status, _h, body = get("/live-connection")
        check("live-connection returns 200", status == 200)
        check("live-connection names the Azure app registration",
              "app registration" in body)
        check("live-connection names tenant admin consent",
              "tenant admin consent" in body)
        check("live-connection states it is not switched on",
              "not switched on" in body)

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
                            "/live-connection", "/connect"])
              and sm.count("<url>") == 5
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
        check("demo: TokenWatch flags 3 of 8 grants",
              "3 of 8 app grants flagged" in body)
        check("demo: InsureReady finds 11 gaps of 13 questions",
              "11 of 13 insurance questions" in body)
        check("demo: worst grant MailFlow Pro is surfaced",
              "MailFlow Pro" in body)
        check("demo: planted last-use of 210 days is shown",
              "210 days ago" in body)
        check("demo: fix plan states it does NOT apply fixes",
              "does NOT apply" in body)
        check("demo: results carry the DRAFT stamp",
              "DRAFT" in body and "does not certify compliance" in body)
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
              and rec["summary"]["tokenwatch_flagged"] == 3
              and rec["summary"]["tokenwatch_grants"] == 8
              and rec["summary"]["insureready_gaps"] == 11)

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
        status, _h, body = get(f"/report/{scan_id}/insureready")
        check("InsureReady pack downloads with IR-Q01 and DRAFT stamp",
              status == 200 and "IR-Q01" in body and "DRAFT" in body)
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
        check("upload: TokenWatch flags 3 of 8 grants",
              "3 of 8 app grants flagged" in body)
        check("upload: InsureReady finds 11 gaps",
              "11 of 13 insurance questions" in body)

        # A fixture in exactly the shape tools/tenantcheck-export.ps1
        # emits (same sections, fields and null conventions) must scan
        # end to end: 3 TenantFix findings, 1 of 2 grants flagged,
        # 5 of 13 InsureReady gaps on the fixture firm.
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
        check("fixture: InsureReady finds 5 gaps of 13 questions",
              "5 of 13 insurance questions" in body)
        check("fixture: export last use is unknown, not a guessed dormancy",
              "<td>unknown</td>" in body and "None days" not in body)

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
        check("copied engine still verifies 40/40 on the demo snapshot",
              summary["checks_passed"] == 40
              and summary["checks_failed"] == 0,
              f"{summary['checks_passed']}/{summary['total_checks']}")

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
        check("graph pending: live-connection stays user-facing",
              "not switched on" in body
              and "read-only" in body
              and "Render" not in body
              and "TENANTCHECK_MS_" not in body
              and "CLIENT_SECRET" not in body
              and "environment variable" not in body.lower())
        status, _h, body = get("/connect")
        check("graph pending: connect page returns 200 and refuses "
              "gracefully", status == 200 and "Setup is pending" in body)
        check("graph pending: connect page does not name the host or "
              "env vars",
              "Render" not in body
              and "TENANTCHECK_MS_" not in body
              and "CLIENT_SECRET" not in body
              and "environment variable" not in body.lower())
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

        # ---- live Graph connection: CONFIGURED server (fake env) ---
        port2 = 8797
        base2 = f"http://127.0.0.1:{port2}"
        env2 = dict(env, PORT=str(port2))
        env2.update({
            "TENANTCHECK_MS_CLIENT_ID": "check-client-id",
            "TENANTCHECK_MS_REDIRECT_URI":
                "https://tenantcheck365.ca/connect/callback",
            "TENANTCHECK_MS_CLIENT_SECRET": "check-secret-not-real"})
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
            check("graph configured: live-connection does not leak "
                  "hosting or the secret",
                  "Render" not in body
                  and "TENANTCHECK_MS_" not in body
                  and "check-secret-not-real" not in body)
            status, body = get2("/connect")
            check("graph configured: connect page builds the admin "
                  "consent URL",
                  "login.microsoftonline.com/organizations/adminconsent"
                  in body and "client_id=check-client-id" in body)
            check("graph configured: connect page does not leak the "
                  "secret or env var names",
                  "check-secret-not-real" not in body
                  and "TENANTCHECK_MS_" not in body
                  and "Render" not in body
                  and "CLIENT_SECRET" not in body)
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
                      for r in ref_ir_list]
            got_ir = [(r["id"], r["status"], r["gap"])
                      for r in got_ir_list]
            check("graph mock: InsureReady answers match the export "
                  "path", got_ir == ref_ir)

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
