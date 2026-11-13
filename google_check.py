#!/usr/bin/env python3
"""
TenantCheck for Google Workspace — export-based companion module.

A self-contained companion to the Microsoft 365 engine in m365.py
(which is NOT modified by this build, beyond one honesty change:
IR-Q04 now answers "Evidence missing" when a snapshot records no
Conditional Access policy count, instead of failing).

The pattern mirrors TenantCheck 365 exactly: this engine runs on
a snapshot JSON — produced either from an EXPORTED file the firm's
own admin made (Google Admin SDK / GAM-style export), from the
fictional demo tenant bundled with the app, or from the live
connection in google_connect.py, which builds the same snapshot
shape through a service account the domain's own admin authorized
(domain-wide delegation; code built, owner setup pending — see
SETUP-GOOGLE.md). There is no Google sign-in anywhere in the app,
and no Google password is ever collected.

Google snapshot schema (documented for customers on
/google/how-to-export):

  _meta            firm_name, snapshot_date, label (as in m365)
  users[]          primaryEmail, displayName, suspended,
                   isAdmin (super admin), twoStepEnrolled
                   (true / false / null = not recorded),
                   lastLoginDaysAgo (int / null)
  domainSettings   lessSecureAppAccess (bool — password-only app
                   sign-in still allowed), driveExternalSharing
                   ("allowed" | "allowedWithWarning" | "blocked"),
                   anyoneWithLinkFileCount (int — domain-level
                   count of files shared to anyone with the link),
                   passwordPolicy {minimumLength,
                   complexityRequired}
  oauthApps[]      appName, scopes (Google scope strings),
                   trusted (bool — domain-trusted / verified),
                   lastUsedDaysAgo (int / null), usersWithAccess
  groups[]         email, name, memberCount, externalMembers,
                   allowsExternalMembers
  mailForwarding[] userEmail, forwardTo[] — mail forwarding the
                   export recorded (settings, never contents)
  securityControls the same owner-stated facts section as the
                   Microsoft export (backup, EDR, encryption,
                   training, plans, the 2026-11-13 additions),
                   EXCEPT conditionalAccessPolicyCount: Google has
                   no Conditional Access, so the field is omitted
                   and IR-Q04 honestly answers "Evidence missing".

InsureReady reuse: an adapter reshapes the Google snapshot into
the Microsoft-shaped snapshot m365.insureready consumes, so the
same 25-question questionnaire (and the broker pack) serves both
platforms wherever a question honestly maps. The mapping is
explicit in to_m365_snapshot() and in the marker findings below;
questions with no Google evidence source answer exactly as they
do on the Microsoft path.

Honesty rule (product requirement): this module prepares
evidence; it does not certify compliance and is not legal or
insurance advice. Every report carries the engine's DRAFT stamp.
Python standard library only.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m365  # shared STAMP/header, InsureReady, AI identification

MODULE = "GoogleFix"
ADMIN_LIMIT = 3
DORMANT_DAYS = 90

GOOGLE_SCOPE_WEIGHTS = {
    "https://www.googleapis.com/auth/drive": 10,
    "https://www.googleapis.com/auth/gmail.modify": 10,
    "https://www.googleapis.com/auth/admin.directory.user": 10,
    "https://www.googleapis.com/auth/drive.readonly": 6,
    "https://www.googleapis.com/auth/gmail.readonly": 6,
    "https://www.googleapis.com/auth/calendar": 3,
    "https://www.googleapis.com/auth/contacts.readonly": 3,
    "https://www.googleapis.com/auth/userinfo.profile": 1,
}
GOOGLE_SCOPE_PLAIN = {
    "https://www.googleapis.com/auth/drive":
        "read and change all Drive files",
    "https://www.googleapis.com/auth/gmail.modify":
        "read and change email",
    "https://www.googleapis.com/auth/admin.directory.user":
        "manage user accounts in the directory",
    "https://www.googleapis.com/auth/drive.readonly":
        "read all Drive files",
    "https://www.googleapis.com/auth/gmail.readonly": "read email",
    "https://www.googleapis.com/auth/calendar": "read and change "
                                                "calendars",
    "https://www.googleapis.com/auth/contacts.readonly":
        "read contacts",
    "https://www.googleapis.com/auth/userinfo.profile":
        "read the signed-in user's profile",
}
DEFAULT_GOOGLE_SCOPE_WEIGHT = 3


# ---------------------------------------------------------------- checks ---
def googlefix(snap):
    findings = []

    def add(check, subject, severity, title, why, fix):
        findings.append({
            "module": MODULE, "check": check, "subject": subject,
            "severity": severity, "title": title, "why": why,
            "fix_steps": fix})

    users = snap.get("users") or []
    active = [u for u in users if not u.get("suspended")]
    admins = [u for u in active if u.get("isAdmin")]

    for u in active:
        name = u.get("displayName") or u.get("primaryEmail") or "user"
        enrolled = u.get("twoStepEnrolled")
        if enrolled is False:
            is_admin = bool(u.get("isAdmin"))
            add("GG-2SV", name,
                "Critical" if is_admin else "High",
                f"No 2-Step Verification: {name}",
                "This account signs in with a password alone."
                + (" It is also a super admin account, so one "
                   "password hands over the whole Workspace."
                   if is_admin else ""),
                ["Have the user turn on 2-Step Verification.",
                 "Confirm enrolment in the admin console.",
                 "Then enforce 2-Step Verification for the whole "
                 "organization (production step, owner approved)."])
        elif enrolled is None:
            add("GG-2SV-UNKNOWN", name, "Medium",
                f"2-Step Verification status not recorded: {name}",
                "The export records no 2-Step Verification state "
                "for this account, so the scan cannot say whether "
                "it is protected. Unknown is reported as unknown — "
                "never as enrolled.",
                ["Check the account's 2-Step Verification state in "
                 "the admin console and record it in the next "
                 "export."])

        days = u.get("lastLoginDaysAgo")
        if days is not None and days > DORMANT_DAYS:
            if u.get("isAdmin"):
                add("GG-DORMANT-ADMIN", name, "High",
                    f"Dormant super admin account: {name}",
                    f"This super admin account has not signed in "
                    f"for {days} days. Nobody is watching it, so a "
                    f"compromise could go unnoticed while the "
                    f"access stays fully powerful.",
                    ["Confirm whether this person still needs "
                     "super admin access.",
                     "Remove the role if they do not (production "
                     "step, owner approved)."])
            else:
                add("GG-DORMANT", name, "Medium",
                    f"Dormant account: {name}",
                    f"This account has not signed in for {days} "
                    f"days. Dormant accounts keep working "
                    f"credentials nobody watches.",
                    ["Confirm the account is still needed.",
                     "Suspend accounts nobody can explain until "
                     "their owner confirms (production step, owner "
                     "approved)."])

    if len(admins) > ADMIN_LIMIT:
        names = ", ".join(u.get("displayName") or u.get("primaryEmail")
                          for u in admins)
        add("GG-ADMIN-SPRAWL", "domain", "High",
            f"Too many super admins ({len(admins)})",
            f"This domain has {len(admins)} super admins "
            f"({names}). Every extra one is another account that "
            f"can take over the whole business if compromised. "
            f"The checklist target for a domain this size is at "
            f"most {ADMIN_LIMIT}.",
            [f"Keep at most {ADMIN_LIMIT} super admins, used only "
             "for admin work.",
             "Give day-to-day helpers a narrower admin role "
             "instead (production step, owner approved)."])

    ds = snap.get("domainSettings") or {}
    if ds.get("lessSecureAppAccess"):
        add("GG-LEGACY", "domain", "High",
            "Less secure app sign-in is still allowed",
            "Apps that sign in with a password alone (older mail "
            "clients and devices) bypass 2-Step Verification "
            "entirely — the Google equivalent of legacy "
            "authentication on Microsoft 365.",
            ["Find any device or app that still needs password-"
             "only sign-in.",
             "Replace it or move it to a modern sign-in.",
             "Turn off less secure app access (production step, "
             "owner approved)."])

    if ds.get("driveExternalSharing") == "allowed":
        add("GG-DRIVE-SHARING", "domain", "High",
            "Drive files can be shared with anyone outside the "
            "domain",
            "Domain settings let users share Drive files "
            "externally with no restriction, including public "
            "links that need no sign-in.",
            ["Restrict external Drive sharing to named guests or "
             "warn-and-confirm at most.",
             "Keep anyone-with-the-link sharing off for sensitive "
             "folders (production step, owner approved)."])
    anyone_files = ds.get("anyoneWithLinkFileCount")
    if anyone_files:
        add("GG-ANYONE-FILES", "domain", "High",
            f"{anyone_files} files shared with anyone who has the "
            f"link",
            "The export's domain-level count shows files whose "
            "link opens them for literally anyone, with no "
            "sign-in. Links get forwarded, guessed and left in old "
            "emails. (The count is a domain aggregate from the "
            "export; the scan does not see the files themselves.)",
            ["Review the anyone-with-the-link files in Drive and "
             "remove links nobody can explain.",
             "Share to named people instead."])

    for g in snap.get("groups") or []:
        if g.get("allowsExternalMembers") \
                and (g.get("externalMembers") or 0) > 0:
            gname = g.get("name") or g.get("email") or "group"
            add("GG-GROUP-EXTERNAL", gname, "Medium",
                f"Group with external members: {gname}",
                f"This group allows external members and currently "
                f"has {g['externalMembers']} — everything shared "
                f"with the group reaches people outside the firm, "
                f"and group membership tends to outlive the job it "
                f"was granted for.",
                ["Confirm each external member still needs access.",
                 "Remove finished engagements and re-check "
                 "quarterly."])
    return findings


# -------------------------------------------------------------- inventory --
def google_inventory(snap):
    inventory = []
    for a in snap.get("oauthApps") or []:
        scopes = a.get("scopes") or []
        ss = sum(GOOGLE_SCOPE_WEIGHTS.get(
            s, DEFAULT_GOOGLE_SCOPE_WEIGHT) for s in scopes)
        dorm = m365.dormancy_factor(a.get("lastUsedDaysAgo"))
        trust_factor = 1.0 if a.get("trusted") else 1.25
        risk = round(ss * dorm * trust_factor, 1)
        reasons = []
        if not a.get("trusted") and ss >= 15:
            reasons.append("untrusted app with high-value scopes")
        if dorm >= 1.5 and ss >= 15:
            reasons.append(
                f"high-value scopes unused for "
                f"{a.get('lastUsedDaysAgo')} days")
        if risk >= 35:
            reasons.append(f"combined risk score {risk}")
        flagged = bool(reasons) and (risk >= 25 or ss >= 15)
        ai_label = m365.ai_label_for(a.get("appName"))
        inventory.append({
            "module": "GoogleWatch", "app": a.get("appName") or "",
            "scopes": scopes, "scope_score": ss,
            "scopes_plain": [GOOGLE_SCOPE_PLAIN.get(
                s, f"{s} (scope name as granted)") for s in scopes],
            "last_used_days_ago": a.get("lastUsedDaysAgo"),
            "consent_type": "admin-governed (domain third-party "
                             "access)",
            "consented_by": "",
            "publisher_verified": bool(a.get("trusted")),
            "users_with_access": a.get("usersWithAccess"),
            "risk": risk, "flagged": flagged,
            "flag_reasons": reasons,
            "is_ai": ai_label is not None, "ai_label": ai_label,
        })
    inventory.sort(key=lambda x: x["risk"], reverse=True)
    return inventory


# --------------------------------------------------------------- adapter ---
def _domain(snap):
    for u in snap.get("users") or []:
        email = u.get("primaryEmail") or ""
        if "@" in email:
            return email.split("@", 1)[1]
    return ""


def to_m365_snapshot(snap):
    """Reshape a Google snapshot into the Microsoft-shaped
    snapshot m365.insureready consumes. The mapping is the whole
    honesty story, so it is deliberately explicit:

    - 2-Step Verification enrolment -> mfaRegistered;
      super admin -> the Global Administrator role.
    - less secure app access -> legacy authentication (the direct
      equivalent: password-only sign-in bypassing the second
      factor).
    - Drive external sharing -> externalSharingCapability:
      allowed -> "Anyone", allowedWithWarning ->
      "ExternalUserAndGuestSharing", blocked ->
      "ExistingExternalUserSharingOnly".
    - mailForwarding entries -> inboxRules (settings only).
    - securityControls are copied across EXCEPT
      conditionalAccessPolicyCount, which is dropped: Google has
      no Conditional Access, so IR-Q04 answers Evidence missing
      rather than borrowing a number that means something else.
    - No sharingInventory is synthesised: Drive item-level
      permission lists are not in this export, so CopilotReady-
      style questions rest on the domain sharing settings only.
    """
    domain = _domain(snap)
    ds = snap.get("domainSettings") or {}
    users = []
    for u in snap.get("users") or []:
        users.append({
            "userPrincipalName": u.get("primaryEmail") or "",
            "displayName": u.get("displayName") or "",
            "accountEnabled": not u.get("suspended"),
            "accountType": "member",
            "mfaRegistered": u.get("twoStepEnrolled") is True,
            "roles": (["Global Administrator"]
                      if u.get("isAdmin") else []),
            "lastSignInDaysAgo": u.get("lastLoginDaysAgo"),
            "guestAccessLevel": None,
        })
    rules = []
    for i, f in enumerate(snap.get("mailForwarding") or []):
        rules.append({
            "id": f"gf{i}", "name": "Forwarding (from export)",
            "enabled": True,
            "forwardTo": f.get("forwardTo") or [],
            "redirectTo": [],
            "deleteMessage": False,
            "userDisplayName": f.get("userEmail") or "",
            "userPrincipalName": f.get("userEmail") or "",
        })
    apps = []
    for i, a in enumerate(snap.get("oauthApps") or []):
        apps.append({
            "id": f"ga{i}", "clientId": a.get("clientId") or f"g{i}",
            "appDisplayName": a.get("appName") or "",
            "scopes": a.get("scopes") or [],
            "consentType": "AllPrincipals",
            "consentedBy": "admin (tenant-wide)",
            "publisherVerified": bool(a.get("trusted")),
            "lastUsedDaysAgo": a.get("lastUsedDaysAgo"),
            "resourceDisplayName": "Google Workspace",
        })
    controls = {k: v for k, v in
                (snap.get("securityControls") or {}).items()
                if k != "conditionalAccessPolicyCount"}
    sharing_map = {"allowed": "Anyone",
                   "allowedWithWarning":
                       "ExternalUserAndGuestSharing",
                   "blocked": "ExistingExternalUserSharingOnly"}
    return {
        "_meta": snap.get("_meta") or {},
        "users": users,
        "inboxRules": rules,
        "oauthGrants": apps,
        "tenantSettings": {
            "legacyAuthenticationEnabled":
                bool(ds.get("lessSecureAppAccess")),
            "legacyAuthProtocols":
                (["less secure app sign-in"]
                 if ds.get("lessSecureAppAccess") else []),
            "externalSharingCapability": sharing_map.get(
                ds.get("driveExternalSharing"),
                "ExistingExternalUserSharingOnly"),
            "passwordPolicy": ds.get("passwordPolicy") or
            {"minimumLength": 0, "complexityRequired": False},
        },
        "securityControls": controls,
    }


def marker_findings(snap, findings):
    """Translate Google findings into the TenantFix check ids
    m365.insureready keys on, so each mapped insurance question
    reads the Google evidence for the same concept."""
    by_check = {f["check"] for f in findings}
    markers = []
    if "GG-LEGACY" in by_check:
        markers.append({"check": "TF-LEGACY-AUTH"})
    domain = _domain(snap)
    if any(t for f in snap.get("mailForwarding") or []
           for t in (f.get("forwardTo") or [])
           if "@" in t and t.split("@", 1)[1] != domain):
        markers.append({"check": "TF-FORWARD-EXTERNAL"})
    if "GG-DRIVE-SHARING" in by_check or "GG-ANYONE-FILES" in by_check:
        markers.append({"check": "TF-SHARING"})
    if "GG-ADMIN-SPRAWL" in by_check:
        markers.append({"check": "TF-ADMIN-SPRAWL"})
    if "GG-DORMANT-ADMIN" in by_check:
        markers.append({"check": "TF-DORMANT-ADMIN"})
    if "GG-GROUP-EXTERNAL" in by_check:
        markers.append({"check": "TF-GUEST-BROAD"})
    return markers


def run_google_scan(snap):
    findings = googlefix(snap)
    inventory = google_inventory(snap)
    # Flagged third-party apps also surface as findings.
    for i in inventory:
        if i["flagged"]:
            findings.append({
                "module": MODULE, "check": "GG-APP-RISK",
                "subject": i["app"], "severity": "High",
                "title": f"Third-party app with risky access: "
                         f"{i['app']}",
                "why": "This connected app holds broad access "
                       "that TokenWatch-style scoring flags: "
                       + "; ".join(i["flag_reasons"])
                       + ". Connected apps keep their access long "
                         "after everyone forgot approving them.",
                "fix_steps": ["Confirm the app is still needed "
                              "and who owns it.",
                              "Reduce its scopes or remove its "
                              "access if it is not (production "
                              "step, owner approved)."]})
    adapter = to_m365_snapshot(snap)
    norm = m365.normalise(adapter)
    markers = marker_findings(snap, findings)
    ir = m365.insureready(adapter, norm, markers, inventory)
    return findings, inventory, ir, adapter


# -------------------------------------------------------------- rendering ---
def render_googlefix(snap, findings):
    out = m365.header(snap, "TenantCheck for Google Workspace - "
                            "Fix Plan")
    out += [f"**{m365.FIX_PLAN_NOTE}**", "",
            "Platform note: this report covers a Google Workspace "
            "domain. It is the Google companion to TenantCheck "
            "365; the snapshot label above states whether these "
            "findings came from an export or from the live "
            "connection.", "",
            f"Findings: {len(findings)}", ""]
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for f in sorted(findings, key=lambda x: order[x["severity"]]):
        out += [f"## [{f['severity']}] {f['title']}",
                f"Check: {f['check']} | Subject: {f['subject']}", "",
                f"Why it matters: {f['why']}", "", "Fix steps:"]
        out += [f"{i}. {s}" for i, s in enumerate(f["fix_steps"], 1)]
        out += [""]
    if not findings:
        out += ["No findings from the deterministic checks. That "
                "is not a guarantee the domain is secure.", ""]
    return "\n".join(out)


def render_google_inventory(snap, inventory):
    out = m365.header(snap, "TenantCheck for Google Workspace - "
                            "Third-Party App Inventory")
    out += ["Third-party apps with access to the domain, ranked by "
            "scope sensitivity x dormancy, with a loading for "
            "untrusted apps.", ""]
    for i in inventory:
        flag = "FLAGGED" if i["flagged"] else "ok"
        out += [f"## {i['app']} - risk {i['risk']} [{flag}]",
                "Scopes in plain English: "
                + "; ".join(i["scopes_plain"]),
                f"Last used: {i['last_used_days_ago']} days ago | "
                f"Users with access: {i['users_with_access']} | "
                f"Trusted by the domain: "
                f"{i['publisher_verified']}"]
        if i["flag_reasons"]:
            out += ["Flag reasons: " + "; ".join(i["flag_reasons"])]
        out += [""]
    ais = m365.ai_apps(inventory)
    out += ["## AI apps in this domain", "",
            m365.AI_IDENTIFICATION_NOTE, "",
            f"AI apps identified: {len(ais)}", ""]
    if not ais:
        out += ["No connected app was identified as an AI tool by "
                "name. That is not proof the firm uses no AI "
                "tools.", ""]
    for i in ais:
        out += [f"### {i['app']} — identified as {i['ai_label']}",
                "What it can do: "
                + "; ".join(i["scopes_plain"]) + ".", ""]
    return "\n".join(out)


# ------------------------------------------------------------ verification --
def verify(snap):
    findings, inventory, ir, _adapter = run_google_scan(snap)
    planted = snap["_planted"]
    results = []

    def check(name, ok, detail=""):
        results.append({"check": name, "pass": bool(ok),
                        "detail": detail})

    actual = {(f["check"], f["subject"]) for f in findings}
    for p in planted["googlefix"]:
        check(f"GoogleFix planted caught: {p['check']} / "
              f"{p['subject']}",
              (p["check"], p["subject"]) in actual)
    expected = {(p["check"], p["subject"]) for p in planted["googlefix"]}
    check("GoogleFix: no unexpected findings", actual == expected,
          f"unexpected: {sorted(actual - expected)}")
    flagged = {i["app"] for i in inventory if i["flagged"]}
    check("GoogleWatch: flagged set matches the manifest",
          flagged == set(planted["tokenwatch_flagged"]),
          f"flagged: {sorted(flagged)}")
    ai_apps_found = {i["app"] for i in m365.ai_apps(inventory)}
    check("GoogleWatch: AI apps identified match the manifest",
          ai_apps_found == set(planted["ai_apps"]),
          f"ai: {sorted(ai_apps_found)}")
    gap_ids = {r["id"] for r in ir if r["status"] != "Supported"}
    check("InsureReady (Google): gaps match the manifest",
          gap_ids == set(planted["insureready_gaps"]),
          f"gaps: {sorted(gap_ids)}")
    q04 = next(r for r in ir if r["id"] == "IR-Q04")
    check("InsureReady (Google): IR-Q04 honestly answers Evidence "
          "missing (no Conditional Access on Google)",
          q04["status"] == "Evidence missing")
    fix_md = render_googlefix(snap, findings)
    inv_md = render_google_inventory(snap, inventory)
    ir_md = m365.render_insureready(snap, ir)
    check("output: DRAFT stamp on all three Google reports",
          all(m365.STAMP in doc for doc in (fix_md, inv_md, ir_md)))
    passed = sum(1 for r in results if r["pass"])
    return {"total_checks": len(results), "checks_passed": passed,
            "checks_failed": len(results) - passed,
            "results": results,
            "findings": len(findings),
            "insureready_gaps": len(gap_ids)}


def main(argv):
    if len(argv) < 3 or argv[1] != "verify":
        print("Usage: python3 google_check.py verify "
              "<google-snapshot.json>")
        return 2
    import json as _json
    with open(argv[2], encoding="utf-8") as fh:
        snap = _json.load(fh)
    summary = verify(snap)
    for r in summary["results"]:
        print(f"{'PASS' if r['pass'] else 'FAIL'} - {r['check']}"
              + (f" ({r['detail']})" if r["detail"] else ""))
    print(f"\nChecks passed: {summary['checks_passed']} / "
          f"{summary['total_checks']} | Failed: "
          f"{summary['checks_failed']}")
    return 0 if summary["checks_failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
