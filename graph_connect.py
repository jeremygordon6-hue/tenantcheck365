#!/usr/bin/env python3
"""
TenantCheck 365 — live Microsoft Graph connection (code side).

Implements the Microsoft identity platform flow that turns the
export-based scan into a live one:

  1. Admin consent. /connect builds the Microsoft admin-consent URL
     from environment configuration. A Global Administrator from the
     CUSTOMER's firm opens it, sees the exact read-only permission
     list, and grants or refuses consent. Microsoft redirects back to
     /connect/callback, and the consented tenant id is recorded in
     data/connections.json. Consent can never be granted by us.

  2. Tokens. After consent, access tokens are acquired on demand with
     the OAuth2 client-credentials flow against the consented tenant.
     The client secret is read from the TENANTCHECK_MS_CLIENT_SECRET
     environment variable at token time ONLY: it is never written to
     disk, never stored in data/connections.json or in any scan
     record, and never logged. Tokens are cached in memory only.

  3. Fetch + transform. With a token, the fetch layer reads the Graph
     endpoints the snapshot schema consumes (organization, users,
     authentication-methods registration report, directory role
     assignments, service principals, OAuth2 permission grants,
     per-mailbox inbox rules, Conditional Access policies, security
     defaults, SharePoint sharing settings) and transforms them into
     the exact snapshot shape m365.normalise()/run_scan() expect.
     The verified engine in m365.py is reused unchanged.

What Graph cannot supply stays ABSENT, never fabricated:

  * Owner-stated facts the export path also takes from the owner —
    password policy, backup state, EDR/encryption coverage, training,
    the incident-response plan — are read from the connection record
    (data/connections.json, recorded by the owner out of band) and
    reported as missing, by name, when they are not there. A scan
    with missing items is NOT run on guesses; scan_tenant() returns
    them as an "incomplete" result instead.
  * guestAccessLevel ("broad"/"limited") has no equivalent in Graph
    directory data, so it stays None and the TF-GUEST-BROAD check
    cannot fire on the Graph path. Documented limitation.
  * Per-app last use comes from service-principal sign-in logs,
    which need AuditLog.Read.All and an Entra ID premium licence on
    the customer tenant; when unavailable it stays None.

Configuration (environment variables, set by the product owner —
see SETUP-GRAPH.md):

  TENANTCHECK_MS_CLIENT_ID      the Entra app registration's client id
  TENANTCHECK_MS_REDIRECT_URI   must match the registered redirect URI
                                (https://tenantcheck365.ca/connect/callback)
  TENANTCHECK_MS_CLIENT_SECRET  the app registration's client secret

With any of these absent the module reports setup as pending and the
connect flow refuses gracefully instead of erroring.

Stack: Python standard library only, same as app.py. The HTTP layer
is an injectable transport callable so tests can drive the whole
Graph path with mocked responses:

    transport(method, url, headers=None, form=None) -> (status, dict)
"""

import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m365  # the verified engine, reused unchanged

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
CONNECTIONS_PATH = os.path.join(DATA_DIR, "connections.json")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

ENV_CLIENT_ID = "TENANTCHECK_MS_CLIENT_ID"
ENV_CLIENT_SECRET = "TENANTCHECK_MS_CLIENT_SECRET"
ENV_REDIRECT_URI = "TENANTCHECK_MS_REDIRECT_URI"
ALL_ENV_VARS = (ENV_CLIENT_ID, ENV_REDIRECT_URI, ENV_CLIENT_SECRET)

# The fixed, read-only application permissions the app registration
# requests. Shown to the customer's admin on Microsoft's own consent
# screen. Mail.Read is in the list only because the inbox message
# rules endpoint requires it; the fetch layer calls that endpoint for
# rule SETTINGS and never reads message contents.
READ_ONLY_PERMISSIONS = (
    "User.Read.All",
    "Directory.Read.All",
    "Reports.Read.All",
    "RoleManagement.Read.Directory",
    "AuditLog.Read.All",
    "Policy.Read.All",
    "Mail.Read (inbox rule settings only — never message contents)",
    "Sites.Read.All (SharePoint sharing settings)",
)

# securityControls keys the engine dereferences that Graph cannot
# supply — owner-stated, exactly as in the export path.
OWNER_CONTROL_KEYS = (
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

STATE_TTL_SECONDS = 900


class GraphError(Exception):
    """A Graph or token call failed. Messages never contain secrets."""


class GraphNotConfigured(GraphError):
    """Raised when an operation needs configuration that is absent."""

    def __init__(self, missing):
        self.missing = list(missing)
        super().__init__(
            "The live connection is not switched on yet. Setup on "
            "the product owner's side is not finished.")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def config(env=None):
    """Read the current configuration from the environment (fresh on
    every call, so tests and restarts behave predictably)."""
    env = os.environ if env is None else env
    values = {
        ENV_CLIENT_ID: (env.get(ENV_CLIENT_ID) or "").strip(),
        ENV_REDIRECT_URI: (env.get(ENV_REDIRECT_URI) or "").strip(),
        ENV_CLIENT_SECRET: (env.get(ENV_CLIENT_SECRET) or "").strip(),
    }
    missing = [name for name in ALL_ENV_VARS if not values[name]]
    return {
        "client_id": values[ENV_CLIENT_ID],
        "redirect_uri": values[ENV_REDIRECT_URI],
        "client_secret": values[ENV_CLIENT_SECRET],
        "missing_config": missing,
        # Consent needs the client id and redirect URI; actually
        # fetching tokens and scanning also needs the secret.
        "consent_ready": bool(values[ENV_CLIENT_ID]
                              and values[ENV_REDIRECT_URI]),
        "scan_ready": not missing,
    }


# ---------------------------------------------------------------------------
# Connections store — tenant ids and owner-stated facts ONLY.
# The client secret and access tokens are never written here.
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


def get_connection(tenant_id):
    return next((c for c in load_connections()
                 if c.get("tenant_id") == tenant_id), None)


def record_connection(tenant_id, extra=None):
    """Record (or refresh) a consented tenant. `extra` may carry
    owner-stated facts (security_controls, tenant_settings); existing
    owner-stated facts are preserved across a re-consent."""
    connections = load_connections()
    entry = next((c for c in connections
                  if c.get("tenant_id") == tenant_id), None)
    if entry is None:
        entry = {"tenant_id": tenant_id}
        connections.append(entry)
    entry["admin_consent"] = True
    entry["consented_at"] = datetime.datetime.now().isoformat(
        timespec="seconds")
    entry["source"] = "microsoft-admin-consent"
    for key, value in (extra or {}).items():
        entry[key] = value
    _save(CONNECTIONS_PATH, connections)
    return entry


# ---------------------------------------------------------------------------
# Admin consent flow
# ---------------------------------------------------------------------------

_PENDING_STATES = {}   # state -> expiry epoch (in memory only)


def admin_consent_url():
    """Build the Microsoft admin-consent URL. Returns (url, state).
    Raises GraphNotConfigured when the client id or redirect URI is
    not configured."""
    cfg = config()
    if not cfg["consent_ready"]:
        missing = []
        if not cfg["client_id"]:
            missing.append(ENV_CLIENT_ID)
        if not cfg["redirect_uri"]:
            missing.append(ENV_REDIRECT_URI)
        raise GraphNotConfigured(missing)
    state = uuid.uuid4().hex
    _PENDING_STATES[state] = time.time() + STATE_TTL_SECONDS
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "state": state,
        "scope": GRAPH_SCOPE,
    }
    return (LOGIN_BASE + "/organizations/adminconsent?"
            + urllib.parse.urlencode(params), state)


def handle_callback(params):
    """Handle the /connect/callback query params (flat str->str dict).

    Returns (status, detail) where status is one of:
    "recorded", "refused", "invalid_state", "not_configured".
    Only "recorded" writes to the connections store."""
    cfg = config()
    if not cfg["consent_ready"]:
        return ("not_configured",
                "Setup is pending: the app registration is not "
                "configured on this server, so no consent can be "
                "recorded.")
    if params.get("error"):
        detail = params.get("error_description") or params["error"]
        return ("refused",
                "Microsoft reported that consent was not granted: "
                + detail)
    tenant_id = (params.get("tenant") or "").strip()
    state = params.get("state") or ""
    expiry = _PENDING_STATES.pop(state, None)
    if not tenant_id or params.get("admin_consent") not in ("True", "true"):
        return ("refused",
                "Microsoft did not return a completed admin consent.")
    if expiry is None or expiry < time.time():
        return ("invalid_state",
                "That consent link was not started here or has "
                "expired. Start again from the connect page.")
    entry = record_connection(tenant_id)
    return ("recorded", entry)


# ---------------------------------------------------------------------------
# HTTP transport (injectable) and token acquisition
# ---------------------------------------------------------------------------

def _default_transport(method, url, headers=None, form=None):
    """urllib-based transport. Returns (status, parsed_json_dict)."""
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
        raise GraphError(f"Could not reach Microsoft: {exc.reason}")


_TOKEN_CACHE = {}   # tenant_id -> (access_token, expiry epoch); memory only


def get_token(tenant_id, transport=None, now=None):
    """Acquire (or reuse a cached) app-only access token for a
    consented tenant via the client-credentials flow. The secret is
    read from the environment here and nowhere else, and is passed
    only as the token request's form field."""
    cfg = config()
    if not cfg["scan_ready"]:
        raise GraphNotConfigured(cfg["missing_config"])
    now = time.time() if now is None else now
    cached = _TOKEN_CACHE.get(tenant_id)
    if cached and cached[1] > now + 30:
        return cached[0]
    transport = transport or _default_transport
    url = f"{LOGIN_BASE}/{tenant_id}/oauth2/v2.0/token"
    status, payload = transport("POST", url, form={
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "scope": GRAPH_SCOPE,
        "grant_type": "client_credentials",
    })
    token = payload.get("access_token")
    if status != 200 or not token:
        err = (payload.get("error_description")
               or payload.get("error") or f"HTTP {status}")
        raise GraphError(f"Token request for tenant failed: {err}")
    _TOKEN_CACHE[tenant_id] = (
        token, now + int(payload.get("expires_in", 3600)))
    return token


# ---------------------------------------------------------------------------
# Graph reads
# ---------------------------------------------------------------------------

def _graph_get(transport, token, path):
    """GET a Graph collection (following @odata.nextLink) or object.
    Returns the "value" list for collections, else the payload."""
    url = path if path.startswith("http") else GRAPH_BASE + path
    headers = {"Authorization": f"Bearer {token}"}
    items = []
    while url:
        status, payload = transport("GET", url, headers=headers)
        if status != 200:
            err = (payload.get("error") or {}).get("message") \
                or f"HTTP {status}"
            raise GraphError(f"Graph read failed for {path}: {err}")
        if isinstance(payload.get("value"), list):
            items.extend(payload["value"])
            url = payload.get("@odata.nextLink")
        else:
            return payload
    return items


def _graph_try(transport, token, path):
    """Optional read: returns the payload/value, or None when Graph
    refuses or the endpoint is unavailable (missing licence,
    permission not granted, beta surface absent)."""
    try:
        return _graph_get(transport, token, path)
    except GraphError:
        return None


def _days_ago(iso_ts, today):
    if not iso_ts:
        return None
    try:
        day = datetime.datetime.fromisoformat(
            iso_ts.replace("Z", "+00:00")).date()
    except ValueError:
        return None
    return (today - day).days


# ---------------------------------------------------------------------------
# Fetch + transform into the snapshot schema
# ---------------------------------------------------------------------------

def fetch_snapshot(tenant_id, transport=None, today=None, token=None):
    """Read a consented tenant from Graph and build the snapshot.

    Returns {"snapshot": ..., "missing": [...], "warnings": [...]}.
    "missing" names every engine-required, owner-stated item that is
    not on the connection record — the scan must not run until the
    owner supplies them. "warnings" lists optional Graph sources that
    were unavailable (their fields stay absent)."""
    transport = transport or _default_transport
    today = today or datetime.date.today()
    token = token or get_token(tenant_id, transport=transport)
    warnings = []
    record = get_connection(tenant_id) or {}
    owner_controls = record.get("security_controls") or {}
    owner_settings = record.get("tenant_settings") or {}

    # -- organization -------------------------------------------------
    orgs = _graph_get(transport, token, "/organization")
    org = orgs[0] if orgs else {}
    firm_name = org.get("displayName") or tenant_id
    tenant_domain_name = ""
    for dom in org.get("verifiedDomains") or []:
        if dom.get("isDefault"):
            tenant_domain_name = dom.get("name") or ""
            break
    if not tenant_domain_name and org.get("verifiedDomains"):
        tenant_domain_name = org["verifiedDomains"][0].get("name") or ""

    # -- users ----------------------------------------------------------
    base_select = ("id,displayName,userPrincipalName,accountEnabled,"
                   "userType,department")
    try:
        raw_users = _graph_get(
            transport, token,
            "/users?$select=" + urllib.parse.quote(
                base_select + ",signInActivity", safe=","))
    except GraphError:
        # signInActivity needs an Entra ID premium licence on the
        # customer tenant; without it the whole $select is refused.
        raw_users = _graph_get(
            transport, token,
            "/users?$select=" + urllib.parse.quote(base_select,
                                                   safe=","))
        warnings.append(
            "signInActivity unavailable (needs an Entra ID premium "
            "licence): lastSignInDaysAgo stays absent")

    registration = _graph_try(
        transport, token,
        "/reports/authenticationMethods/userRegistrationDetails")
    reg_by_upn = {}
    if registration is None:
        warnings.append(
            "authentication methods registration report unavailable: "
            "mfaRegistered defaults to False (not registered)")
    else:
        for row in registration:
            reg_by_upn[(row.get("userPrincipalName") or "").lower()] = row

    assignments = _graph_get(
        transport, token,
        "/roleManagement/directory/roleAssignments"
        "?$expand=roleDefinition")
    roles_by_principal = {}
    for a in assignments:
        role_def = a.get("roleDefinition") or {}
        if a.get("principalId") and role_def.get("displayName"):
            roles_by_principal.setdefault(a["principalId"], []).append(
                role_def["displayName"])

    users = []
    users_by_id = {}
    for u in raw_users:
        reg = reg_by_upn.get((u.get("userPrincipalName") or "").lower(),
                             {})
        activity = u.get("signInActivity") or {}
        user = {
            "id": u.get("id"),
            "displayName": u.get("displayName") or "",
            "userPrincipalName": u.get("userPrincipalName") or "",
            "accountEnabled": bool(u.get("accountEnabled")),
            # Graph exposes Member/Guest only; a shared mailbox is
            # indistinguishable and lands as "member" (it is disabled
            # for sign-in, so the engine treats it the same).
            "accountType": ("guest" if u.get("userType") == "Guest"
                            else "member"),
            "mfaRegistered": bool(reg.get("isMfaRegistered")),
            "authMethods": reg.get("methodsRegistered") or [],
            "roles": roles_by_principal.get(u.get("id"), []),
            # Graph directory data has no broad/limited guest-access
            # signal: stays absent (None) on this path.
            "guestAccessLevel": None,
            "lastSignInDaysAgo": _days_ago(
                activity.get("lastSignInDateTime"), today),
            "department": u.get("department"),
        }
        users.append(user)
        users_by_id[user["id"]] = user

    # -- service principals + OAuth2 permission grants ------------------
    principals = _graph_get(
        transport, token,
        "/servicePrincipals?$select=id,appId,displayName,"
        "verifiedPublisher")
    sp_by_id = {sp.get("id"): sp for sp in principals}

    grants_raw = _graph_get(transport, token, "/oauth2PermissionGrants")
    last_use_cache = {}

    def grant_last_used(app_id):
        """Most recent service-principal sign-in for an app, as days
        ago. Optional: audit logs need AuditLog.Read.All and a
        premium licence on the customer tenant."""
        if app_id in last_use_cache:
            return last_use_cache[app_id]
        result = None
        filt = urllib.parse.quote(f"appId eq '{app_id}'", safe="")
        rows = _graph_try(
            transport, token,
            f"/auditLogs/signIns?$filter={filt}&$top=1"
            "&$orderby=createdDateTime desc")
        if rows:
            result = _days_ago(rows[0].get("createdDateTime"), today)
        else:
            warnings.append(
                f"sign-in logs unavailable for app {app_id}: "
                "lastUsedDaysAgo stays absent")
        last_use_cache[app_id] = result
        return result

    grants = []
    for g in grants_raw:
        # In Graph, a grant's clientId/resourceId are service
        # principal OBJECT ids; the snapshot wants app ids + names.
        client_sp = sp_by_id.get(g.get("clientId")) or {}
        resource_sp = sp_by_id.get(g.get("resourceId")) or {}
        app_id = client_sp.get("appId") or g.get("clientId")
        verified = client_sp.get("verifiedPublisher") or {}
        if g.get("consentType") == "Principal":
            principal = users_by_id.get(g.get("principalId")) or {}
            consented_by = principal.get("userPrincipalName") \
                or g.get("principalId") or ""
        else:
            consented_by = "admin (tenant-wide)"
        grants.append({
            "id": g.get("id"),
            "clientId": app_id,
            "appDisplayName": client_sp.get("displayName")
            or g.get("clientId"),
            "scopes": (g.get("scope") or "").split(),
            "consentType": g.get("consentType"),
            "consentedBy": consented_by,
            "publisherVerified": bool(
                verified.get("displayName")),
            "lastUsedDaysAgo": grant_last_used(app_id),
            "resourceDisplayName": resource_sp.get("displayName") or "",
        })

    # -- inbox rules (settings only, never message contents) ------------
    rules = []
    for u in users:
        if u["accountType"] != "member":
            continue
        rows = _graph_try(
            transport, token,
            f"/users/{u['id']}/mailFolders/inbox/messageRules")
        if rows is None:
            warnings.append(
                f"inbox rules unavailable for {u['userPrincipalName']}")
            continue
        for r in rows:
            actions = r.get("actions") or {}

            def addresses(key):
                return [((rcpt.get("emailAddress") or {}).get("address")
                         or "")
                        for rcpt in actions.get(key) or []]
            rules.append({
                "id": r.get("id"),
                "name": r.get("displayName") or "",
                "enabled": bool(r.get("isEnabled")),
                "userDisplayName": u["displayName"],
                "userPrincipalName": u["userPrincipalName"],
                "forwardTo": addresses("forwardToRecipients"),
                "redirectTo": addresses("redirectToRecipients"),
                "deleteMessage": bool(actions.get("deleteMessage")),
            })

    # -- tenant settings / policies --------------------------------------
    ca_policies = _graph_get(
        transport, token, "/identity/conditionalAccess/policies") or []
    sec_defaults = _graph_try(
        transport, token,
        "/policies/identitySecurityDefaultsEnforcementPolicy")
    legacy_blocked = bool(sec_defaults and sec_defaults.get("isEnabled"))
    if not legacy_blocked:
        for pol in ca_policies:
            controls = pol.get("grantControls") or {}
            built_ins = controls.get("builtInControls") or []
            client_apps = (pol.get("conditions") or {}).get(
                "clientAppTypes") or []
            if (pol.get("state") == "enabled"
                    and "block" in built_ins
                    and set(client_apps) & {"exchangeActiveSync",
                                            "other"}):
                legacy_blocked = True
                break
    legacy_enabled = not legacy_blocked

    sharing = _graph_try(transport, token,
                         "/admin/sharepoint/settings")
    sharing_map = {
        "externalUserAndGuestSharing": "Anyone",
        "existingExternalUserSharingOnly":
            "ExistingExternalUserSharingOnly",
        "externalUserSharingOnly": "ExternalUserSharingOnly",
        "disabled": "Disabled",
    }
    if sharing is None:
        external_sharing = None
        warnings.append(
            "SharePoint sharing settings unavailable: "
            "externalSharingCapability stays absent")
    else:
        external_sharing = sharing_map.get(
            sharing.get("sharingCapability"))

    password_policy = (owner_settings.get("passwordPolicy") or {})
    tenant_settings = {
        "legacyAuthenticationEnabled": legacy_enabled,
        # Graph does not enumerate which legacy protocols a tenant
        # still allows; keep the evidence text honest instead of
        # inventing a protocol list.
        "legacyAuthProtocols": (
            [] if not legacy_enabled
            else ["legacy protocols (detail not exposed by Graph)"]),
        "externalSharingCapability": external_sharing,
        "passwordPolicy": password_policy,
    }

    # -- security controls ------------------------------------------------
    security_controls = {
        "conditionalAccessPolicyCount": len(ca_policies),
    }
    for key in OWNER_CONTROL_KEYS:
        if key in owner_controls:
            security_controls[key] = owner_controls[key]

    missing = [f"securityControls.{key}" for key in OWNER_CONTROL_KEYS
               if key not in security_controls]
    if not (password_policy.get("minimumLength") is not None
            and password_policy.get("complexityRequired") is not None):
        missing.append("tenantSettings.passwordPolicy")

    snapshot = {
        "_meta": {
            "fictional": False,
            "firm_name": firm_name,
            "snapshot_date": today.isoformat(),
            "label": ("Live Microsoft Graph connection, read with the "
                      "tenant admin's consent. Findings cover only "
                      "what the connection returned."),
        },
        "users": users,
        "inboxRules": rules,
        "tenantSettings": tenant_settings,
        "oauthGrants": grants,
        "securityControls": security_controls,
    }
    if not tenant_domain_name:
        tenant_domain_name = m365.tenant_domain(snapshot)
    snapshot["_meta"]["tenant_domain"] = tenant_domain_name
    return {"snapshot": snapshot, "missing": missing,
            "warnings": warnings}


def scan_tenant(tenant_id, transport=None, today=None):
    """Fetch a consented tenant and run the verified engine on it.

    Returns {"status": "scanned", "results": (norm, tf, tw, ir), ...}
    or {"status": "incomplete", "missing": [...], ...} when
    owner-stated items Graph cannot supply are absent — the scan is
    never run on guessed values."""
    fetched = fetch_snapshot(tenant_id, transport=transport,
                             today=today)
    if fetched["missing"]:
        return {"status": "incomplete", **fetched, "results": None}
    norm, tf, tw, ir = m365.run_scan(fetched["snapshot"])
    return {"status": "scanned", **fetched,
            "results": (norm, tf, tw, ir)}
