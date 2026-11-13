#!/usr/bin/env python3
"""
TenantCheck 365 — live Google Workspace connection (code side).

The Google companion to graph_connect.py. Same architecture and
the same honesty rules, adapted to how Google Workspace actually
grants a third party read access — which is NOT an OAuth consent
screen like Microsoft's:

  1. Domain-wide delegation (DWD). The product owner creates a
     Google Cloud project with a service account (see
     SETUP-GOOGLE.md). That service account has NO access to any
     customer domain by itself. Each CUSTOMER's own Workspace
     super admin authorizes the service account's client ID in
     their Admin console (Security -> Access and data control ->
     API controls -> Domain-wide delegation), pasting the exact
     read-only scope list below. Only then can the service account
     impersonate an admin email in that domain and call the Admin
     SDK Directory API. The customer can delete that delegation
     entry at any time, which ends all access immediately. There
     is no step at which TenantCheck can authorize itself.

  2. Tokens. For each read, the app builds a service-account JWT
     (RS256) claiming the authorized scopes and the admin email to
     impersonate ("sub"), and exchanges it at Google's token
     endpoint for a short-lived access token. The service-account
     key is read from the TENANTCHECK_GOOGLE_SA_KEY environment
     variable at signing time ONLY: it is never written to disk,
     never stored in data/google_connections.json or in any scan
     record, and never logged. Tokens are cached in memory only.

     RS256 signing needs RSA cryptography, which the Python
     standard library does not provide. The signer is therefore a
     pluggable step: when the `cryptography` package is importable
     it is used; otherwise signing raises GoogleSigningUnavailable
     and every flow that needs a token reports that plainly and
     records nothing. The token exchange itself sits behind the
     injectable HTTP transport, and tests drive the whole path —
     claims, exchange, validation, fetch — with a fake signer and
     a mocked transport. No test uses a real key. In production
     the service must run where an RSA signer is available (see
     SETUP-GOOGLE.md, Step 4 note).

  3. Fetch + transform. With a token, the fetch layer reads the
     Admin SDK Directory endpoints the Google snapshot schema
     consumes (customer, domains, users with their 2-Step
     Verification fields, per-user third-party tokens, groups and
     their members) and transforms them into the exact snapshot
     shape google_check.run_google_scan() expects. The verified
     Google engine is reused unchanged.

What the Directory API cannot supply stays ABSENT or NOT COVERED,
never fabricated — fetch_snapshot() returns the gaps by name:

  * Domain-level Drive sharing settings (driveExternalSharing,
    anyoneWithLinkFileCount), the less-secure-app-access setting
    and the password policy are Admin console settings with no
    Directory API equivalent. They are taken from the connection
    record when the customer has stated them (owner-stated, the
    same pattern as the Microsoft path's security controls), and
    reported as not covered when they have not.
  * Per-user mail forwarding settings live in the Gmail API,
    which is deliberately outside the authorized scope list, so
    forwarding is NOT read on the live path. Consequence, stated
    plainly: the InsureReady mail-forwarding answer (IR-Q07) and
    the guest-breadth answer (IR-Q20, whose group finding needs
    the allows-external-members setting the Directory API does
    not expose — membership IS read, the setting is not) can
    differ between the live path and the export path. Both are
    named in the snapshot's not-covered list.
  * The tokens endpoint exposes no last-used time and no
    domain-trust state for a third-party app, so live inventory
    rows carry lastUsedDaysAgo=None and the unverified-publisher
    loading — the same treatment the export path gives an app
    whose trust state was not recorded.
  * Owner-stated security controls (backup, EDR, encryption,
    training, plans) are read from the connection record exactly
    as on the Microsoft path; absent ones are named in "missing"
    and answer Evidence missing in the questionnaire, never
    guessed. (Unlike the Microsoft engine, google_check answers
    per-question, so a live Google scan still runs with gaps
    named rather than refusing outright.)

Configuration (environment variables, set by the product owner —
see SETUP-GOOGLE.md):

  TENANTCHECK_GOOGLE_SA_EMAIL     the service account's email
  TENANTCHECK_GOOGLE_SA_CLIENT_ID the service account's numeric
                                  client ID — the value a customer
                                  admin pastes into the DWD screen.
                                  Not a secret; shown on the
                                  connect page for exactly that.
  TENANTCHECK_GOOGLE_SA_KEY       the service account private key
                                  (PEM, or the full JSON key file
                                  contents — only its private_key
                                  field is read). A secret in every
                                  sense: env var only, owner's
                                  hand only.

With any of these absent the module reports setup as pending and
the connect flow refuses gracefully instead of erroring.

Stack: Python standard library only, same as app.py (plus the
optional `cryptography` package for RS256 signing when present).
The HTTP layer is an injectable transport callable so tests can
drive the whole Google path with mocked responses:

    transport(method, url, headers=None, form=None) -> (status, dict)
"""

import base64
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import google_check  # the verified Google engine, reused unchanged

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
CONNECTIONS_PATH = os.path.join(DATA_DIR, "google_connections.json")

ADMIN_BASE = "https://admin.googleapis.com/admin/directory/v1"
TOKEN_URL = "https://oauth2.googleapis.com/token"
JWT_AUDIENCE = TOKEN_URL
JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"

ENV_SA_EMAIL = "TENANTCHECK_GOOGLE_SA_EMAIL"
ENV_SA_CLIENT_ID = "TENANTCHECK_GOOGLE_SA_CLIENT_ID"
ENV_SA_KEY = "TENANTCHECK_GOOGLE_SA_KEY"
ALL_ENV_VARS = (ENV_SA_EMAIL, ENV_SA_CLIENT_ID, ENV_SA_KEY)

_SCOPE_BASE = "https://www.googleapis.com/auth/"
# The fixed scope list the customer admin authorizes on the DWD
# screen — shown verbatim on the connect page and in
# SETUP-GOOGLE.md. Verified against Google's published Admin SDK
# scope list (developers.google.com/identity/protocols/googlescopes)
# and the Directory API reference on 2026-11-13:
#   user.readonly        — users.list/get (accounts, suspended,
#                          super-admin flag, 2-Step Verification
#                          enrolment fields, last login time).
#   group.readonly       — groups.list/get.
#   group.member.readonly — members.list (external member counts).
#   customer.readonly    — customers.get (whose domain this is).
#   user.security        — users.tokens.list (the third-party apps
#                          each user has authorized). Google offers
#                          NO read-only variant of this scope: it
#                          can technically also revoke a user's
#                          tokens and sign them out. TenantCheck
#                          only ever calls tokens.list (a read);
#                          the scope is requested because there is
#                          no narrower way to read the token
#                          inventory, and customers are told so.
# Deliberately NOT requested: admin.reports.audit.readonly —
# Directory users.list already returns lastLoginTime, so an audit
# scope would widen access for nothing.
READ_ONLY_SCOPES = (
    _SCOPE_BASE + "admin.directory.user.readonly",
    _SCOPE_BASE + "admin.directory.group.readonly",
    _SCOPE_BASE + "admin.directory.group.member.readonly",
    _SCOPE_BASE + "admin.directory.customer.readonly",
    _SCOPE_BASE + "admin.directory.user.security",
)

# securityControls keys the questionnaire dereferences that the
# Directory API cannot supply — owner-stated, exactly as in the
# export path and on the Microsoft connection record.
GOOGLE_OWNER_CONTROL_KEYS = (
    "edrCoveragePercent",
    "backupEnabled",
    "backupLastSuccessfulDaysAgo",
    "backupLastTestRestoreDaysAgo",
    "securityTrainingLastMonthsAgo",
    "securityTrainingCompletionPercent",
    "incidentResponsePlanDocumented",
    "deviceEncryptionPercent",
    "automaticUpdatesEnabled",
    "writtenSecurityPolicyDocumented",
    "penetrationTestLastMonthsAgo",
    "backupOfflineOrImmutableCopy",
)

# domainSettings keys with no Directory API equivalent. Taken from
# the connection record when the customer has stated them;
# otherwise the snapshot carries None and names them not covered.
OWNER_DOMAIN_SETTING_KEYS = (
    "lessSecureAppAccess",
    "driveExternalSharing",
    "anyoneWithLinkFileCount",
    "passwordPolicy",
)

NOT_COVERED_LIVE = (
    "mailForwarding (per-user forwarding settings — the Gmail "
    "API is outside the authorized scope list, so forwarding is "
    "not read on the live path)",
    "groups.allowsExternalMembers (whether a group allows "
    "external members — a Groups Settings value the Directory "
    "API does not expose; external membership itself IS read)",
)


class GoogleError(Exception):
    """A Google API or token call failed. Messages never contain
    key material."""


class GoogleNotConfigured(GoogleError):
    """Raised when an operation needs configuration that is
    absent."""

    def __init__(self, missing):
        self.missing = list(missing)
        super().__init__(
            "TenantCheck Google service account is not configured; "
            "missing environment variable(s): "
            + ", ".join(self.missing))


class GoogleSigningUnavailable(GoogleError):
    """The runtime cannot produce an RS256 signature (the Python
    standard library has no RSA signing, and the `cryptography`
    package is not importable here)."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _key_material(raw):
    """Accept either a raw PEM private key or the full JSON key
    file contents; return the PEM string. The value itself is
    never logged or stored."""
    raw = (raw or "").strip()
    if raw.startswith("{"):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return raw
        return (parsed.get("private_key") or "").strip()
    return raw


def config(env=None):
    """Read the current configuration from the environment (fresh
    on every call, so tests and restarts behave predictably)."""
    env = os.environ if env is None else env
    values = {
        ENV_SA_EMAIL: (env.get(ENV_SA_EMAIL) or "").strip(),
        ENV_SA_CLIENT_ID: (env.get(ENV_SA_CLIENT_ID) or "").strip(),
        ENV_SA_KEY: (env.get(ENV_SA_KEY) or "").strip(),
    }
    missing = [name for name in ALL_ENV_VARS if not values[name]]
    return {
        "sa_email": values[ENV_SA_EMAIL],
        "sa_client_id": values[ENV_SA_CLIENT_ID],
        "sa_key": _key_material(values[ENV_SA_KEY]),
        "missing_config": missing,
        "configured": not missing,
    }


def configured(env=None):
    return config(env)["configured"]


# ---------------------------------------------------------------------------
# Connections store — domains and owner-stated facts ONLY.
# The service-account key and access tokens are never written here.
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


def load_connections():
    data = _load(CONNECTIONS_PATH, [])
    return data if isinstance(data, list) else []


def get_connection(domain):
    domain = (domain or "").strip().lower()
    return next((c for c in load_connections()
                 if c.get("domain") == domain), None)


def record_connection(domain, admin_email, extra=None):
    """Record (or refresh) a validated domain. `extra` may carry
    owner-stated facts (security_controls, domain_settings);
    existing owner-stated facts are preserved across a
    re-registration."""
    domain = (domain or "").strip().lower()
    connections = load_connections()
    entry = next((c for c in connections
                  if c.get("domain") == domain), None)
    if entry is None:
        entry = {"domain": domain}
        connections.append(entry)
    entry["admin_email"] = (admin_email or "").strip()
    entry["authorized_at"] = datetime.datetime.now().isoformat(
        timespec="seconds")
    entry["source"] = "google-domain-wide-delegation"
    for key, value in (extra or {}).items():
        entry[key] = value
    _save(CONNECTIONS_PATH, connections)
    return entry


# ---------------------------------------------------------------------------
# JWT construction + RS256 signing (pluggable) + token exchange
# ---------------------------------------------------------------------------

def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def build_jwt_claims(admin_email, now=None):
    """The JWT header + claims for the service-account token
    exchange, impersonating `admin_email` in the customer domain.
    Pure data — no key material involved."""
    now = int(time.time()) if now is None else int(now)
    cfg = config()
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {
        "iss": cfg["sa_email"],
        "sub": admin_email,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "scope": " ".join(READ_ONLY_SCOPES),
    }
    return header, claims


def jwt_signing_input(admin_email, now=None):
    header, claims = build_jwt_claims(admin_email, now=now)
    return ".".join([
        _b64url(json.dumps(header, separators=(",", ":")).encode()),
        _b64url(json.dumps(claims, separators=(",", ":")).encode()),
    ])


def sign_rs256(signing_input, key_pem):
    """Sign `signing_input` (str) with the service account's RSA
    private key, RS256 (RSASSA-PKCS1-v1_5 + SHA-256), returning the
    base64url signature.

    The Python standard library cannot do this. When the
    `cryptography` package is importable it is used; otherwise
    GoogleSigningUnavailable is raised — callers surface that
    plainly instead of pretending a token was requested."""
    try:
        from cryptography.hazmat.primitives import hashes, \
            serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        raise GoogleSigningUnavailable(
            "This server cannot sign the service-account request "
            "yet: RS256 signing needs the `cryptography` package, "
            "which is not available in this runtime (the Python "
            "standard library cannot sign). Nothing was sent to "
            "Google and nothing was recorded. See SETUP-GOOGLE.md.")
    key = serialization.load_pem_private_key(
        key_pem.encode("utf-8"), password=None)
    signature = key.sign(signing_input.encode("ascii"),
                         padding.PKCS1v15(), hashes.SHA256())
    return _b64url(signature)


def build_jwt_assertion(admin_email, signer=None, now=None):
    """Full signed JWT assertion for the token exchange. `signer`
    is injectable for tests: signer(signing_input, key_pem) ->
    base64url signature. The key is read from the environment
    here and passed only to the signer."""
    cfg = config()
    if not cfg["configured"]:
        raise GoogleNotConfigured(cfg["missing_config"])
    signer = signer or sign_rs256
    signing_input = jwt_signing_input(admin_email, now=now)
    return signing_input + "." + signer(signing_input, cfg["sa_key"])


def _default_transport(method, url, headers=None, form=None):
    """urllib-based transport. Returns (status, parsed_json_dict).
    Same shape as graph_connect's transport."""
    data = None
    hdrs = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(
                resp.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(
                exc.read().decode("utf-8", "replace") or "{}")
        except json.JSONDecodeError:
            payload = {}
        return exc.code, payload
    except urllib.error.URLError as exc:
        raise GoogleError(f"Could not reach Google: {exc.reason}")


_TOKEN_CACHE = {}   # admin_email -> (access_token, expiry epoch)


def get_access_token(admin_email, transport=None, signer=None,
                     now=None):
    """Exchange a signed JWT for an access token impersonating
    `admin_email`. The service-account key is read from the
    environment at this point and nowhere else, and travels only
    into the signature — never into the request body, the store,
    or a log."""
    cfg = config()
    if not cfg["configured"]:
        raise GoogleNotConfigured(cfg["missing_config"])
    now = time.time() if now is None else now
    cached = _TOKEN_CACHE.get(admin_email)
    if cached and cached[1] > now + 30:
        return cached[0]
    transport = transport or _default_transport
    assertion = build_jwt_assertion(admin_email, signer=signer,
                                    now=int(now))
    status, payload = transport("POST", TOKEN_URL, form={
        "grant_type": JWT_GRANT_TYPE,
        "assertion": assertion,
    })
    token = payload.get("access_token")
    if status != 200 or not token:
        err = (payload.get("error_description")
               or payload.get("error") or f"HTTP {status}")
        raise GoogleError(f"Token exchange failed: {err}")
    _TOKEN_CACHE[admin_email] = (
        token, now + int(payload.get("expires_in", 3600)))
    return token


# ---------------------------------------------------------------------------
# Registration + validation
# ---------------------------------------------------------------------------

def validate_connection(domain, admin_email, transport=None,
                        signer=None):
    """Validate that the service account can actually read the
    domain (the customer's admin has authorized the delegation),
    using one read-only users call. Returns (ok, detail): on
    success the connection is recorded and detail is the stored
    record; on any failure NOTHING is recorded and detail says
    why, in plain language."""
    cfg = config()
    if not cfg["configured"]:
        return (False,
                "Setup is pending: the service account is not "
                "configured on this server, so no connection can "
                "be validated or recorded.")
    domain = (domain or "").strip().lower()
    admin_email = (admin_email or "").strip()
    if "." not in domain or "@" not in admin_email:
        return (False,
                "Enter the domain (like firm.ca) and the admin "
                "email the connection should impersonate in that "
                "domain.")
    try:
        token = get_access_token(admin_email, transport=transport,
                                 signer=signer)
        _directory_get(transport, token,
                       "/users?customer=my_customer&maxResults=1"
                       "&projection=basic")
    except GoogleError as exc:
        return (False, f"Validation could not be completed: {exc}")
    entry = record_connection(domain, admin_email)
    return (True, entry)


# ---------------------------------------------------------------------------
# Directory reads
# ---------------------------------------------------------------------------

def _directory_get(transport, token, path):
    """GET an Admin SDK collection (following nextPageToken) or a
    single object. Returns the "items" list for collections, else
    the payload."""
    base = path if path.startswith("http") else ADMIN_BASE + path
    headers = {"Authorization": f"Bearer {token}"}
    items = []
    url = base
    while url:
        status, payload = transport("GET", url, headers=headers)
        if status != 200:
            err = (payload.get("error") or {}).get("message") \
                or f"HTTP {status}"
            raise GoogleError(
                f"Directory read failed for {path}: {err}")
        if "items" in payload or "nextPageToken" in payload:
            items.extend(payload.get("items") or [])
            nxt = payload.get("nextPageToken")
            if nxt:
                sep = "&" if "?" in base else "?"
                url = base + sep + "pageToken=" + \
                    urllib.parse.quote(nxt, safe="")
            else:
                url = None
        else:
            return payload
    return items


def _directory_try(transport, token, path):
    """Optional read: payload/value, or None when Google refuses
    or the endpoint is unavailable for this domain."""
    try:
        return _directory_get(transport, token, path)
    except GoogleError:
        return None


def _days_ago(iso_ts, today):
    """Days between an ISO timestamp and `today`. Google reports
    a never-signed-in account's lastLoginTime as the epoch
    (1970-01-01); that is returned as None (unknown), never as a
    five-figure day count."""
    if not iso_ts:
        return None
    try:
        day = datetime.datetime.fromisoformat(
            iso_ts.replace("Z", "+00:00")).date()
    except ValueError:
        return None
    if day.year <= 1970:
        return None
    return (today - day).days


# ---------------------------------------------------------------------------
# Fetch + transform into the google_check snapshot schema
# ---------------------------------------------------------------------------

def fetch_snapshot(domain, transport=None, signer=None, today=None,
                   token=None):
    """Read a validated domain from the Admin SDK and build the
    google_check snapshot.

    Returns {"snapshot": ..., "missing": [...], "not_covered":
    [...], "warnings": [...]}. "missing" names owner-stated items
    that are not on the connection record (the questionnaire
    answers Evidence missing for them). "not_covered" names the
    inputs the Directory API cannot supply at all on this path.
    Nothing is fabricated."""
    transport = transport or _default_transport
    today = today or datetime.date.today()
    domain = (domain or "").strip().lower()
    record = get_connection(domain)
    if record is None:
        raise GoogleError(
            "That domain has not been registered and validated, "
            "so there is no live connection to read. Register it "
            "from the Google connect page first.")
    admin_email = record.get("admin_email") or ""
    token = token or get_access_token(admin_email,
                                      transport=transport,
                                      signer=signer)
    warnings = []
    owner_controls = record.get("security_controls") or {}
    owner_settings = record.get("domain_settings") or {}

    # -- customer / domain -----------------------------------------
    customer = _directory_try(transport, token,
                              "/customer/my_customer") or {}
    firm_name = ((customer.get("postalAddress") or {})
                 .get("organizationName")
                 or customer.get("alternateEmail") or domain)

    # -- users -------------------------------------------------------
    raw_users = _directory_get(
        transport, token,
        "/users?customer=my_customer&maxResults=500"
        "&projection=full")
    users = []
    for u in raw_users:
        enrolled = u.get("isEnrolledIn2Sv")
        users.append({
            "primaryEmail": u.get("primaryEmail") or "",
            "displayName": (u.get("name") or {}).get("fullName")
            or u.get("primaryEmail") or "",
            "suspended": bool(u.get("suspended")),
            "isAdmin": bool(u.get("isAdmin")),
            "twoStepEnrolled": (bool(enrolled)
                                if enrolled is not None else None),
            "lastLoginDaysAgo": _days_ago(
                u.get("lastLoginTime"), today),
        })

    # -- third-party tokens per user ---------------------------------
    tokens_by_client = {}
    for u in users:
        if u["suspended"] or not u["primaryEmail"]:
            continue
        rows = _directory_try(
            transport, token,
            "/users/" + urllib.parse.quote(u["primaryEmail"],
                                           safe="")
            + "/tokens")
        if rows is None:
            warnings.append(
                "third-party app tokens unavailable for "
                + u["primaryEmail"])
            continue
        for t in rows:
            client = t.get("clientId") or t.get("displayText") or ""
            entry = tokens_by_client.setdefault(client, {
                "clientId": client,
                "appName": t.get("displayText") or client,
                "scopes": [],
                # The tokens endpoint exposes neither a domain
                # trust state nor a last-used time: both stay
                # absent, exactly as an export that did not
                # record them.
                "trusted": None,
                "lastUsedDaysAgo": None,
                "usersWithAccess": 0,
            })
            for scope in t.get("scopes") or []:
                if scope not in entry["scopes"]:
                    entry["scopes"].append(scope)
            entry["usersWithAccess"] += 1
    oauth_apps = [tokens_by_client[k]
                  for k in sorted(tokens_by_client)]
    if oauth_apps:
        warnings.append(
            "the tokens endpoint exposes no trust state or "
            "last-used time, so live app rows carry the "
            "unverified-publisher loading and no dormancy signal")

    # -- groups + members ---------------------------------------------
    groups = []
    raw_groups = _directory_get(
        transport, token,
        "/groups?customer=my_customer&maxResults=200")
    for g in raw_groups:
        members = _directory_try(
            transport, token,
            "/groups/" + urllib.parse.quote(
                g.get("email") or g.get("id") or "", safe="")
            + "/members?maxResults=200")
        external = None
        if members is not None:
            external = sum(
                1 for m in members
                if m.get("type", "USER") == "USER"
                and "@" in (m.get("email") or "")
                and (m.get("email") or "").split("@", 1)[1].lower()
                != domain)
        groups.append({
            "email": g.get("email") or "",
            "name": g.get("name") or g.get("email") or "",
            "memberCount": g.get("directMembersCount")
            if g.get("directMembersCount") is not None
            else (len(members) if members is not None else None),
            "externalMembers": external,
            # Groups Settings value; the Directory API does not
            # expose it (see NOT_COVERED_LIVE).
            "allowsExternalMembers": None,
        })

    # -- domain settings: owner-stated or not covered ------------------
    domain_settings = {key: None
                       for key in OWNER_DOMAIN_SETTING_KEYS}
    domain_settings["passwordPolicy"] = {}
    for key in OWNER_DOMAIN_SETTING_KEYS:
        if key in owner_settings:
            domain_settings[key] = owner_settings[key]
    not_covered = list(NOT_COVERED_LIVE)
    for key in OWNER_DOMAIN_SETTING_KEYS:
        value = domain_settings.get(key)
        if value is None or value == {}:
            not_covered.append(
                f"domainSettings.{key} (Admin console setting "
                "with no Directory API equivalent; owner-stated "
                "only, and not stated for this domain)")

    # -- security controls: owner-stated --------------------------------
    security_controls = {}
    for key in GOOGLE_OWNER_CONTROL_KEYS:
        if key in owner_controls:
            security_controls[key] = owner_controls[key]
    missing = [f"securityControls.{key}"
               for key in GOOGLE_OWNER_CONTROL_KEYS
               if key not in security_controls]

    snapshot = {
        "_meta": {
            "fictional": False,
            "firm_name": firm_name,
            "snapshot_date": today.isoformat(),
            "label": ("Live Google Workspace connection, read "
                      "through a service account authorized by "
                      "the domain's own admin (domain-wide "
                      "delegation). Findings cover only what "
                      "the connection returned; anything listed "
                      "as not covered was not read."),
            "tenant_domain": domain,
        },
        "users": users,
        "domainSettings": domain_settings,
        "oauthApps": oauth_apps,
        "groups": groups,
        # Gmail API is outside the authorized scopes: forwarding
        # is not read on this path (see NOT_COVERED_LIVE).
        "mailForwarding": [],
        "securityControls": security_controls,
    }
    return {"snapshot": snapshot, "missing": missing,
            "not_covered": not_covered, "warnings": warnings}


def scan_domain(domain, transport=None, signer=None, today=None):
    """Fetch a validated domain and run the verified Google
    engine on it. Returns {"status": "scanned", "snapshot": ...,
    "findings": ..., "inventory": ..., "insureready": ...,
    "missing": [...], "not_covered": [...], "warnings": [...]}.
    Owner-stated gaps do not block the scan (google_check answers
    Evidence missing per question); they are named in "missing"."""
    fetched = fetch_snapshot(domain, transport=transport,
                             signer=signer, today=today)
    findings, inventory, ir, _adapter = google_check.run_google_scan(
        fetched["snapshot"])
    return {"status": "scanned", **fetched, "findings": findings,
            "inventory": inventory, "insureready": ir}
