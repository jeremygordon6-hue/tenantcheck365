#!/usr/bin/env python3
"""
M365 Cluster prototype - one tenant scan engine, three paid outputs.

Modules:
  TenantFix 365   - deterministic hardening checks + owner-approved fix plan
  TokenWatch      - OAuth grant inventory ranked by scope x dormancy x consent
  InsureReady 365 - scan results mapped to a cyber-insurance evidence pack

Python standard library only. Offline snapshot prototype: it reads an
EXPORTED tenant snapshot (JSON shaped like Microsoft Graph responses).
It does NOT connect to any live tenant, and it does NOT apply fixes.
The fix-application step is production work behind app registration and
tenant admin consent.

All demo data is fabricated for a fictional business and labelled as such.
"""
import json
import sys
from pathlib import Path

STAMP = ("DRAFT \u2014 prepared for the owner's review. This tool prepares "
         "evidence; it does not certify compliance and is not legal advice.")
FIX_PLAN_NOTE = ("Owner-approved fix plan only. This prototype does NOT apply "
                 "fixes to any tenant. Applying a fix is production work that "
                 "happens only after the owner approves each step and a live "
                 "connection exists behind app registration and tenant admin "
                 "consent.")

SCOPE_WEIGHTS = {
    "Directory.ReadWrite.All": 10,
    "Mail.ReadWrite": 10,
    "Files.ReadWrite.All": 10,
    "User.ReadWrite.All": 10,
    "Sites.ReadWrite.All": 9,
    "Mail.Send": 8,
    "Directory.Read.All": 6,
    "Mail.Read": 6,
    "Files.Read.All": 6,
    "offline_access": 4,
    "Calendars.Read": 3,
    "Chat.Read": 3,
    "User.Read": 1,
}
DEFAULT_SCOPE_WEIGHT = 3
GLOBAL_ADMIN_LIMIT = 3          # for a tenant of this size, per checklist
DORMANT_ADMIN_DAYS = 90
PASSWORD_MIN_LENGTH = 12

# Plain-English meanings for the scopes TokenWatch reports, so the
# AI-apps view (and the broker pack) can say what an app can actually
# do without the reader knowing Graph scope names. Unknown scopes are
# shown as-is and labelled uninterpreted — never paraphrased wrongly.
SCOPE_PLAIN = {
    "Directory.ReadWrite.All": "read and change the whole directory "
                               "(accounts, groups, roles)",
    "Mail.ReadWrite": "read and change email",
    "Files.ReadWrite.All": "read and change all files",
    "User.ReadWrite.All": "read and change all user accounts",
    "Sites.ReadWrite.All": "read and change all SharePoint sites",
    "Mail.Send": "send email as the user",
    "Directory.Read.All": "read the whole directory",
    "Mail.Read": "read email",
    "Files.Read.All": "read all files",
    "offline_access": "keep access when the user is signed out "
                      "(refresh tokens)",
    "Calendars.Read": "read calendars",
    "Chat.Read": "read chat messages",
    "User.Read": "read the signed-in user's profile",
}

# Known AI services, identified by NAME only (see ai_label_for).
# This is a maintained list, not a detection technology: an AI tool
# whose app name matches none of these keys is not identified, and
# the reports say exactly that. Keys are matched case-insensitively
# as substrings of the grant's app display name.
AI_APP_KEYS = [
    ("chatgpt", "ChatGPT (OpenAI)"),
    ("openai", "OpenAI"),
    ("chatpdf", "ChatPDF (AI document chat)"),
    ("copilot", "Microsoft Copilot"),
    ("claude", "Claude (Anthropic)"),
    ("anthropic", "Anthropic"),
    ("gemini", "Google Gemini"),
    ("perplexity", "Perplexity AI"),
    ("grammarly", "Grammarly (AI writing assistant)"),
    ("otter", "Otter.ai (meeting transcription)"),
    ("fireflies", "Fireflies.ai (meeting notes)"),
    ("read ai", "Read AI (meeting notes)"),
    ("notion", "Notion (incl. Notion AI)"),
    ("zoom ai", "Zoom AI Companion"),
    ("jasper", "Jasper AI"),
    ("writesonic", "Writesonic"),
    ("deepl", "DeepL (AI translation)"),
    ("midjourney", "Midjourney"),
]

AI_IDENTIFICATION_NOTE = (
    "AI tools are identified by app name against a maintained list "
    "of known AI services. An AI tool whose name does not match the "
    "list would not be flagged here, and a non-AI app with an "
    "AI-sounding name could be listed — the owner confirms each "
    "one.")


def ai_label_for(app_display_name):
    """Return the AI service label for an app display name, or None.
    Name-based identification only — see AI_IDENTIFICATION_NOTE."""
    name = (app_display_name or "").lower()
    for key, label in AI_APP_KEYS:
        if key in name:
            return label
    return None


def scopes_plain(scopes):
    return [SCOPE_PLAIN.get(s, f"{s} (scope name as granted)")
            for s in scopes]


# ---------------------------------------------------------------- engine ----
def load_snapshot(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def tenant_domain(snap):
    for u in snap["users"]:
        if u["accountType"] == "member" and "@" in u["userPrincipalName"]:
            return u["userPrincipalName"].split("@", 1)[1]
    return ""


def normalise(snap):
    users = snap["users"]
    enabled_members = [u for u in users
                       if u["accountEnabled"] and u["accountType"] == "member"]
    global_admins = [u for u in users
                     if "Global Administrator" in u.get("roles", [])
                     and u["accountEnabled"]]
    return {
        "users": users,
        "enabled_members": enabled_members,
        "guests": [u for u in users if u["accountType"] == "guest"],
        "global_admins": global_admins,
        "domain": tenant_domain(snap),
    }


def is_external(address, domain):
    return "@" in address and address.split("@", 1)[1] != domain


# ------------------------------------------------------------ TenantFix ----
def tenantfix(snap, norm):
    findings = []

    def add(check, subject, severity, title, why, fix):
        findings.append({
            "module": "TenantFix", "check": check, "subject": subject,
            "severity": severity, "title": title, "why": why, "fix_steps": fix,
        })

    # TF-MFA: enabled member accounts without MFA (admins are critical)
    for u in norm["enabled_members"]:
        if not u["mfaRegistered"]:
            is_admin = "Global Administrator" in u.get("roles", [])
            add("TF-MFA", u["displayName"],
                "Critical" if is_admin else "High",
                f"No MFA registered: {u['displayName']}",
                "A stolen password alone is enough to sign in to this "
                "account." + (" This account is also a Global Administrator, "
                              "so one password hands over the whole tenant."
                              if is_admin else ""),
                ["Have the user register the Microsoft Authenticator app.",
                 "Confirm the registration in the admin centre.",
                 "Then enforce MFA for everyone with a Conditional Access "
                 "policy (production step, owner approved)."])

    # TF-LEGACY-AUTH
    if snap["tenantSettings"]["legacyAuthenticationEnabled"]:
        add("TF-LEGACY-AUTH", "tenant", "High",
            "Legacy authentication is still enabled",
            "Old mail protocols (POP3, IMAP4, authenticated SMTP) sign in "
            "with a password only and skip MFA entirely. They are one of the "
            "leading routes into business email compromise.",
            ["List any device or app that still uses these protocols.",
             "Move it to a modern sign-in or replace it.",
             "Block legacy authentication in Conditional Access / "
             "authentication policies (production step, owner approved)."])

    # TF-FORWARD-EXTERNAL
    for r in snap["inboxRules"]:
        if not r["enabled"]:
            continue
        targets = r.get("forwardTo", []) + r.get("redirectTo", [])
        external = [t for t in targets if is_external(t, norm["domain"])]
        if external:
            add("TF-FORWARD-EXTERNAL", r["userDisplayName"], "Critical",
                f"Inbox rule forwards mail outside the business: "
                f"{r['userDisplayName']}",
                "This rule sends a copy of incoming mail to "
                + ", ".join(external)
                + ". Hidden forwarding rules are a classic sign an account "
                  "was compromised, and they quietly leak invoices and "
                  "customer mail even when they were set up innocently.",
                ["Ask the account owner to confirm they created this rule.",
                 "Delete the rule if it is not explained.",
                 "Change the account password and review its sign-ins.",
                 "Turn on the tenant setting that blocks automatic external "
                 "forwarding (production step, owner approved)."])

    # TF-SHARING
    if snap["tenantSettings"]["externalSharingCapability"] == "Anyone":
        add("TF-SHARING", "tenant", "High",
            "File sharing is open to anyone with a link",
            "Anyone who gets a sharing link can open the file, with no "
            "sign-in and no expiry by default. Links get forwarded, guessed "
            "and left in old emails.",
            ["Set external sharing to named guests only.",
             "Keep anonymous links off, or allow them only with a short "
             "expiry on specific folders (production step, owner approved)."])

    # TF-ADMIN-SPRAWL
    if len(norm["global_admins"]) > GLOBAL_ADMIN_LIMIT:
        names = ", ".join(u["displayName"] for u in norm["global_admins"])
        add("TF-ADMIN-SPRAWL", "tenant", "High",
            f"Too many Global Administrators ({len(norm['global_admins'])})",
            f"This tenant has {len(norm['global_admins'])} Global "
            f"Administrators ({names}). Every extra one is another account "
            f"that can take over the whole business if it is compromised. "
            f"For a tenant this size the checklist target is at most "
            f"{GLOBAL_ADMIN_LIMIT}.",
            ["Keep at most "
             f"{GLOBAL_ADMIN_LIMIT} Global Administrators, used only for "
             "admin work.",
             "Give day-to-day helpers a narrower role instead (for example "
             "Helpdesk or User Administrator).",
             "Make everyone else a standard user (production step, owner "
             "approved)."])

    # TF-DORMANT-ADMIN
    for u in norm["global_admins"]:
        days = u.get("lastSignInDaysAgo")
        if days is not None and days > DORMANT_ADMIN_DAYS:
            add("TF-DORMANT-ADMIN", u["displayName"], "High",
                f"Dormant admin account: {u['displayName']}",
                f"This Global Administrator account has not signed in for "
                f"{days} days. Nobody is watching it, so a compromise could "
                f"go unnoticed for months while the access stays fully "
                f"powerful.",
                ["Confirm whether this person still needs admin access.",
                 "Remove the admin role if they do not (production step, "
                 "owner approved).",
                 "Review admin accounts every quarter."])

    # TF-GUEST-BROAD
    for g in norm["guests"]:
        if g.get("guestAccessLevel") == "broad" and g["accountEnabled"]:
            add("TF-GUEST-BROAD", g["displayName"], "Medium",
                f"Guest account with broad internal access: "
                f"{g['displayName']}",
                "This external guest can reach internal sites and files "
                "broadly, not just the specific items they were invited to. "
                "Guest access tends to outlive the job it was granted for.",
                ["Confirm what this guest actually still needs.",
                 "Reduce them to access to those specific items only.",
                 "Set guest access to expire and be reviewed (production "
                 "step, owner approved)."])

    # TF-PASSWORD-POLICY
    pol = snap["tenantSettings"]["passwordPolicy"]
    gaps = []
    if pol["minimumLength"] < PASSWORD_MIN_LENGTH:
        gaps.append(f"minimum length is {pol['minimumLength']} characters "
                    f"(checklist target {PASSWORD_MIN_LENGTH})")
    if not pol["complexityRequired"]:
        gaps.append("complexity is not required")
    if gaps:
        add("TF-PASSWORD-POLICY", "tenant", "Medium",
            "Password policy is weaker than the checklist",
            "The tenant password policy has gaps: " + "; ".join(gaps) + ". "
            "Weak minimums matter most for the few accounts and services "
            "that still rely on passwords alone.",
            ["Raise the minimum password length to "
             f"{PASSWORD_MIN_LENGTH} and require complexity.",
             "Keep MFA as the real protection; passwords are the backstop "
             "(production step, owner approved)."])
    return findings


# ------------------------------------------------------------ TokenWatch ----
def scope_score(scopes):
    return sum(SCOPE_WEIGHTS.get(s, DEFAULT_SCOPE_WEIGHT) for s in scopes)


def dormancy_factor(days):
    if days is None:
        return 1.0
    if days >= 180:
        return 2.0
    if days >= 90:
        return 1.5
    if days >= 30:
        return 1.2
    return 1.0


def tokenwatch(snap):
    inventory = []
    for g in snap["oauthGrants"]:
        ss = scope_score(g["scopes"])
        dorm = dormancy_factor(g["lastUsedDaysAgo"])
        consent_factor = 1.3 if g["consentType"] == "Principal" else 1.0
        publisher_factor = 1.0 if g["publisherVerified"] else 1.25
        risk = round(ss * dorm * consent_factor * publisher_factor, 1)
        reasons = []
        if not g["publisherVerified"] and ss >= 15:
            reasons.append("unverified publisher with high-value scopes")
        if dorm >= 1.5 and ss >= 15:
            reasons.append(
                f"high-value scopes unused for {g['lastUsedDaysAgo']} days")
        if risk >= 35:
            reasons.append(f"combined risk score {risk}")
        if g["consentType"] == "Principal" and ss >= 15:
            reasons.append("high-value scopes consented by one user, "
                           "not reviewed by an admin")
        flagged = bool(reasons) and (risk >= 25 or ss >= 15)
        ai_label = ai_label_for(g["appDisplayName"])
        inventory.append({
            "module": "TokenWatch", "app": g["appDisplayName"],
            "scopes": g["scopes"], "scope_score": ss,
            "scopes_plain": scopes_plain(g["scopes"]),
            "last_used_days_ago": g["lastUsedDaysAgo"],
            "consent_type": ("user-consented (single user)"
                             if g["consentType"] == "Principal"
                             else "admin-consented (tenant-wide)"),
            "consented_by": g.get("consentedBy") or "",
            "publisher_verified": g["publisherVerified"],
            "risk": risk, "flagged": flagged, "flag_reasons": reasons,
            "is_ai": ai_label is not None, "ai_label": ai_label,
        })
    inventory.sort(key=lambda x: x["risk"], reverse=True)
    return inventory


def ai_apps(inventory):
    """The AI-identified subset of a TokenWatch inventory."""
    return [i for i in inventory if i.get("is_ai")]


# ----------------------------------------------------------- InsureReady ----
def insureready(snap, norm, tf_findings, tw_inventory):
    c = snap["securityControls"]
    checks = {f["check"] for f in tf_findings}
    members = norm["enabled_members"]
    mfa_ok = [u for u in members if u["mfaRegistered"]]
    mfa_pct = round(100 * len(mfa_ok) / max(1, len(members)))
    admins_no_mfa = [u["displayName"] for u in norm["global_admins"]
                     if not u["mfaRegistered"]]
    flagged_apps = [i["app"] for i in tw_inventory if i["flagged"]]

    def row(qid, question, status, evidence, gap=""):
        return {"module": "InsureReady", "id": qid, "question": question,
                "status": status, "evidence": evidence, "gap": gap}

    rows = []
    rows.append(row(
        "IR-Q01", "Is MFA enabled for all user accounts?",
        "Supported" if mfa_pct == 100 else "Gap",
        f"Scan evidence: {len(mfa_ok)} of {len(members)} enabled member "
        f"accounts have MFA registered ({mfa_pct}%).",
        "" if mfa_pct == 100 else
        "Accounts without MFA: " + ", ".join(
            u["displayName"] for u in members if not u["mfaRegistered"])
        + ". Insurers treat an attested 'yes' here as fact at claim time."))
    rows.append(row(
        "IR-Q02", "Is MFA enforced for administrator accounts?",
        "Supported" if not admins_no_mfa else "Gap",
        "Scan evidence: Global Administrators without MFA: "
        + (", ".join(admins_no_mfa) if admins_no_mfa else "none") + ".",
        "" if not admins_no_mfa else
        "An admin account with password-only sign-in is the most common "
        "reason answers on this question fail at claim time."))
    rows.append(row(
        "IR-Q03", "Is legacy authentication (POP3/IMAP/basic auth) disabled?",
        "Gap" if "TF-LEGACY-AUTH" in checks else "Supported",
        "Scan evidence: legacy authentication is "
        + ("ENABLED (" + ", ".join(
            snap["tenantSettings"]["legacyAuthProtocols"]) + ")."
           if "TF-LEGACY-AUTH" in checks else "disabled."),
        "" if "TF-LEGACY-AUTH" not in checks else
        "Legacy protocols bypass MFA; most questionnaires ask this directly."))
    ca_count = c.get("conditionalAccessPolicyCount")
    if ca_count is None:
        rows.append(row(
            "IR-Q04", "Are Conditional Access policies in place?",
            "Evidence missing",
            "Scan evidence: no Conditional Access policy count was "
            "recorded in this snapshot, so the question cannot be "
            "answered from evidence. (Exports from platforms without "
            "a Conditional Access equivalent record nothing here.)",
            "Owner to complete: if the platform in use has an "
            "equivalent sign-in policy system, record its policy "
            "count in the export; otherwise answer from the admin "
            "console directly."))
    else:
        rows.append(row(
            "IR-Q04", "Are Conditional Access policies in place?",
            "Supported" if ca_count >= 1 else "Gap",
            f"Scan evidence: {ca_count} Conditional "
            f"Access policies found in the snapshot.",
            "" if ca_count >= 1 else
            "No policy enforces the MFA and legacy-auth answers above; "
            "they rest on user behaviour only."))
    rows.append(row(
        "IR-Q05", "Is endpoint detection and response (EDR) deployed on "
                  "all endpoints?",
        "Supported" if c["edrCoveragePercent"] >= 95 else "Gap",
        f"Scan evidence: EDR coverage reported at "
        f"{c['edrCoveragePercent']}% of endpoints.",
        "" if c["edrCoveragePercent"] >= 95 else
        "Coverage below ~95% is normally answered 'no' or qualified by "
        "underwriters."))
    rows.append(row(
        "IR-Q06", "Are backups enabled and is restoration tested?",
        "Supported" if (c["backupEnabled"]
                        and c["backupLastTestRestoreDaysAgo"] <= 90)
        else "Gap",
        f"Scan evidence: backups enabled: {c['backupEnabled']}; last "
        f"successful backup {c['backupLastSuccessfulDaysAgo']} day(s) ago; "
        f"last test restore {c['backupLastTestRestoreDaysAgo']} days ago.",
        "" if (c["backupEnabled"]
               and c["backupLastTestRestoreDaysAgo"] <= 90) else
        "Backups exist but a restore has not been tested within 90 days, "
        "which is what the question actually asks."))
    rows.append(row(
        "IR-Q07", "Is automatic forwarding of email to external addresses "
                  "controlled?",
        "Gap" if "TF-FORWARD-EXTERNAL" in checks else "Supported",
        "Scan evidence: "
        + ("an active inbox rule forwards mail to an external address."
           if "TF-FORWARD-EXTERNAL" in checks
           else "no external forwarding rules found."),
        "" if "TF-FORWARD-EXTERNAL" not in checks else
        "An uncontrolled forwarding rule contradicts a 'yes' answer here."))
    rows.append(row(
        "IR-Q08", "Is external file sharing restricted to identified "
                  "guests?",
        "Gap" if "TF-SHARING" in checks else "Supported",
        "Scan evidence: external sharing capability is '"
        + snap["tenantSettings"]["externalSharingCapability"] + "'.",
        "" if "TF-SHARING" not in checks else
        "Anonymous-link sharing is broader than the restricted sharing "
        "this question describes."))
    rows.append(row(
        "IR-Q09", "Is administrative access limited and reviewed?",
        "Gap" if ("TF-ADMIN-SPRAWL" in checks
                  or "TF-DORMANT-ADMIN" in checks) else "Supported",
        f"Scan evidence: {len(norm['global_admins'])} Global "
        f"Administrators; dormant admin findings: "
        f"{sum(1 for f in tf_findings if f['check'] == 'TF-DORMANT-ADMIN')}.",
        "" if not ("TF-ADMIN-SPRAWL" in checks
                   or "TF-DORMANT-ADMIN" in checks) else
        "Admin sprawl or a dormant admin account undermines a 'limited "
        "and reviewed' answer."))
    rows.append(row(
        "IR-Q10", "Have staff completed security awareness training in "
                  "the last 12 months?",
        "Supported" if (c["securityTrainingLastMonthsAgo"] <= 12
                        and c["securityTrainingCompletionPercent"] >= 80)
        else "Gap",
        f"Scan evidence: last training "
        f"{c['securityTrainingLastMonthsAgo']} months ago, "
        f"{c['securityTrainingCompletionPercent']}% completion.",
        "" if (c["securityTrainingLastMonthsAgo"] <= 12
               and c["securityTrainingCompletionPercent"] >= 80) else
        "Training is stale or incomplete against the 12-month wording "
        "of the question."))
    rows.append(row(
        "IR-Q11", "Is there a documented incident response plan?",
        "Supported" if c["incidentResponsePlanDocumented"]
        else "Evidence missing",
        "Scan evidence: the snapshot records incidentResponsePlan"
        "Documented = "
        + str(c["incidentResponsePlanDocumented"]) + ".",
        "" if c["incidentResponsePlanDocumented"] else
        "No evidence in the tenant data supports a 'yes'. This must be "
        "answered from a document outside the tenant, or answered 'no' "
        "until one exists."))
    rows.append(row(
        "IR-Q12", "Are endpoints encrypted at rest?",
        "Supported" if c["deviceEncryptionPercent"] >= 95 else "Gap",
        f"Scan evidence: device encryption reported at "
        f"{c['deviceEncryptionPercent']}% of endpoints.",
        "" if c["deviceEncryptionPercent"] >= 95 else
        "Encryption coverage is below the level a plain 'yes' implies."))
    rows.append(row(
        "IR-Q13", "Are operating system and application updates applied "
                  "automatically?",
        "Supported" if c["automaticUpdatesEnabled"] else "Gap",
        f"Scan evidence: automatic updates enabled: "
        f"{c['automaticUpdatesEnabled']}.",
        "" if c["automaticUpdatesEnabled"] else
        "Manual updating is not the automatic patching this question "
        "describes."))

    # ---- Expansion (2026-11-13): IR-Q14..Q25 -------------------------
    # Every question below is mapped to exactly one honest evidence
    # source: an existing snapshot field or module result, a new
    # owner-stated securityControls field (read with .get() so older
    # exports answer "Evidence missing" rather than failing), or no
    # source at all — in which case the answer is always "Evidence
    # missing" with owner guidance. Nothing is inferred from data
    # that does not speak to the question.

    pol = snap["tenantSettings"]["passwordPolicy"]
    pw_ok = pol["minimumLength"] >= PASSWORD_MIN_LENGTH \
        and pol["complexityRequired"]
    rows.append(row(
        "IR-Q14", "Does the password policy require long, complex "
                  "passwords (at least 12 characters, with complexity)?",
        "Supported" if pw_ok else "Gap",
        f"Scan evidence: tenant password policy requires a minimum "
        f"length of {pol['minimumLength']} characters; complexity "
        f"required: {pol['complexityRequired']}.",
        "" if pw_ok else
        "The tenant policy is weaker than the wording of this "
        "question (see the TenantFix password-policy finding). "
        "MFA is the real protection; this is the backstop."))

    dormant = [u for u in members
               if u.get("lastSignInDaysAgo") is not None
               and u["lastSignInDaysAgo"] > DORMANT_ADMIN_DAYS]
    rows.append(row(
        "IR-Q15", "Are accounts that have not signed in for over 90 "
                  "days disabled or removed promptly?",
        "Gap" if dormant else "Supported",
        "Scan evidence: enabled accounts with no sign-in for over "
        f"{DORMANT_ADMIN_DAYS} days: "
        + (", ".join(f"{u['displayName']} "
                     f"({u['lastSignInDaysAgo']} days)"
                     for u in dormant) if dormant else "none") + ".",
        "" if not dormant else
        "Dormant accounts keep working credentials nobody watches. "
        "An account the firm cannot explain should be disabled "
        "until its owner confirms it is still needed."))

    rows.append(row(
        "IR-Q16", "Are third-party applications connected to your "
                  "systems reviewed and approved before use?",
        "Gap" if flagged_apps else "Supported",
        "Scan evidence: TokenWatch flagged "
        f"{len(flagged_apps)} connected app(s) for risky grants: "
        + (", ".join(flagged_apps) if flagged_apps else "none")
        + f". Total grants inventoried: {len(tw_inventory)}.",
        "" if not flagged_apps else
        "Flagged grants were approved without the review this "
        "question describes, or have outlived it. Each one should "
        "be confirmed by its owner or revoked."))

    inventory = snap.get("sharingInventory")
    anyone_links = None
    if isinstance(inventory, list):
        anyone_links = sum((i.get("anyoneLinks") or 0)
                           for i in inventory if isinstance(i, dict))
    sharing_gap = "TF-SHARING" in checks \
        or (anyone_links is not None and anyone_links > 0)
    if anyone_links is None:
        sharing_evidence = (
            "Scan evidence: external sharing capability is '"
            + snap["tenantSettings"]["externalSharingCapability"]
            + "'. This snapshot has no sharing inventory, so "
              "anonymous links on individual sites were not counted.")
    else:
        sharing_evidence = (
            "Scan evidence: external sharing capability is '"
            + snap["tenantSettings"]["externalSharingCapability"]
            + f"'; anonymous (\"anyone with the link\") links found "
              f"in the site and library permission lists: "
              f"{anyone_links}.")
    rows.append(row(
        "IR-Q17", "Is external file sharing restricted and reviewed, "
                  "including anonymous sharing links?",
        "Gap" if sharing_gap else "Supported",
        sharing_evidence,
        "" if not sharing_gap else
        "Sharing broader than named, identified guests — and any "
        "anonymous link — is wider than the restricted sharing this "
        "question describes. See the CopilotReady audit for the "
        "per-site detail."))

    policy_doc = c.get("writtenSecurityPolicyDocumented")
    rows.append(row(
        "IR-Q18", "Is there a written information security policy "
                  "that staff can point to?",
        "Supported" if policy_doc else "Evidence missing",
        "Owner-stated in the snapshot: writtenSecurityPolicy"
        f"Documented = {policy_doc}.",
        "" if policy_doc else
        "No written policy is evidenced in the snapshot. Answer "
        "this from the document itself: if the firm has one, record "
        "it in the export answers; if it does not, the honest "
        "answer to the broker is 'no' until one is adopted."))

    pentest_months = c.get("penetrationTestLastMonthsAgo")
    if pentest_months is None:
        pentest_status = "Evidence missing"
        pentest_evidence = ("Owner-stated in the snapshot: no "
                            "penetration test or vulnerability "
                            "assessment date was recorded.")
        pentest_gap = ("The snapshot records no test date, so this "
                       "cannot be answered from evidence. If a test "
                       "or assessment was done, record when; if "
                       "none was done, the honest answer is 'no'.")
    elif pentest_months <= 12:
        pentest_status = "Supported"
        pentest_evidence = (f"Owner-stated in the snapshot: last "
                            f"penetration test or vulnerability "
                            f"assessment {pentest_months} month(s) "
                            f"ago.")
        pentest_gap = ""
    else:
        pentest_status = "Gap"
        pentest_evidence = (f"Owner-stated in the snapshot: last "
                            f"penetration test or vulnerability "
                            f"assessment {pentest_months} month(s) "
                            f"ago.")
        pentest_gap = ("The last test is older than the 12 months "
                       "this question asks about, so a plain 'yes' "
                       "would overstate it.")
    rows.append(row(
        "IR-Q19", "Has an independent penetration test or "
                  "vulnerability assessment been completed in the "
                  "last 12 months?",
        pentest_status, pentest_evidence, pentest_gap))

    rows.append(row(
        "IR-Q20", "Is guest and external user access limited to what "
                  "each guest needs, and reviewed?",
        "Gap" if "TF-GUEST-BROAD" in checks else "Supported",
        f"Scan evidence: {len(norm['guests'])} guest account(s) in "
        f"the tenant; guests recorded with broad internal access: "
        f"{sum(1 for f in tf_findings if f['check'] == 'TF-GUEST-BROAD')}.",
        "" if "TF-GUEST-BROAD" not in checks else
        "A guest with broad internal access can reach far more than "
        "the work they were invited for, which contradicts a "
        "'limited and reviewed' answer."))

    immutable = c.get("backupOfflineOrImmutableCopy")
    if immutable is None:
        immutable_status = "Evidence missing"
        immutable_evidence = ("Owner-stated in the snapshot: "
                              "whether a backup copy is offline or "
                              "immutable was not recorded.")
        immutable_gap = ("Backups are covered at IR-Q06, but this "
                         "question asks about a copy ransomware "
                         "cannot reach or alter. Record the answer "
                         "in the export; until then it cannot be "
                         "evidenced.")
    else:
        immutable_status = "Supported" if immutable else "Gap"
        immutable_evidence = ("Owner-stated in the snapshot: an "
                              "offline or immutable backup copy "
                              f"exists: {immutable}.")
        immutable_gap = ("" if immutable else
                         "All backup copies are reachable from the "
                         "live environment, so ransomware that owns "
                         "the tenant could encrypt or delete them "
                         "too — the exact scenario this question "
                         "probes.")
    rows.append(row(
        "IR-Q21", "Is at least one backup copy kept offline or in "
                  "immutable storage that ransomware cannot alter?",
        immutable_status, immutable_evidence, immutable_gap))

    rows.append(row(
        "IR-Q22", "Has the business had a cyber incident, data "
                  "breach, or cyber-insurance claim in the last "
                  "3 years?",
        "Evidence missing",
        "No scan evidence: a tenant snapshot holds current settings "
        "and accounts. It cannot show incident or claims history, "
        "and nothing here should be read as 'none'.",
        "Owner to complete from the firm's own records before "
        "submitting. Insurers ask this directly and check claims "
        "history independently — an inaccurate answer here can void "
        "a policy, so this one is never answered from a scan."))
    rows.append(row(
        "IR-Q23", "What sensitive data does the business hold — "
                  "personal records, health or financial data, "
                  "payment card data — and roughly how much?",
        "Evidence missing",
        "No scan evidence: the scan reads permissions and settings, "
        "never file contents, so it cannot count records or tell "
        "whether payment card data is stored.",
        "Owner to complete from the firm's data inventory. If the "
        "firm takes payment cards directly rather than through a "
        "payment provider, say so — underwriters price that "
        "differently and may ask about PCI duties."))
    rows.append(row(
        "IR-Q24", "Is MFA required for remote access to the "
                  "business network (VPN, remote desktop, cloud "
                  "admin portals)?",
        "Evidence missing",
        "No scan evidence: the snapshot shows MFA registration for "
        "Microsoft 365 accounts (IR-Q01), but it contains nothing "
        "about VPN, remote-desktop or network-level access, which "
        "may be separate systems.",
        "Owner to complete for each remote-access route into the "
        "business. Do not let the Microsoft 365 MFA answer stand in "
        "for a VPN or remote-desktop answer unless the same system "
        "genuinely covers both."))
    rows.append(row(
        "IR-Q25", "Is email authentication enforced for the "
                  "business domain (SPF, DKIM and a DMARC policy "
                  "that rejects spoofed mail)?",
        "Evidence missing",
        "No scan evidence: email authentication lives in the "
        "domain's public DNS records, which a tenant snapshot does "
        "not contain. This scan does not read DNS.",
        "Owner to complete from the domain's DNS records, or run a "
        "dedicated email-authentication check and attach it. "
        "Underwriters increasingly test this themselves from the "
        "same public records."))
    return rows


# -------------------------------------------------------------- rendering ---
def header(snap, title):
    m = snap["_meta"]
    return [f"# {title}", "",
            f"Firm (fictional demo data): {m['firm_name']}",
            f"Snapshot date: {m['snapshot_date']}",
            f"{m['label']}", "", f"**{STAMP}**", ""]


def render_tenantfix(snap, findings):
    out = header(snap, "TenantFix 365 - Owner-Approved Fix Plan")
    out += [f"**{FIX_PLAN_NOTE}**", "",
            f"Findings: {len(findings)}", ""]
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for f in sorted(findings, key=lambda x: order[x["severity"]]):
        out += [f"## [{f['severity']}] {f['title']}",
                f"Check: {f['check']} | Subject: {f['subject']}", "",
                f"Why it matters: {f['why']}", "", "Fix steps:"]
        out += [f"{i}. {s}" for i, s in enumerate(f["fix_steps"], 1)]
        out += [""]
    return "\n".join(out)


def render_tokenwatch(snap, inventory):
    out = header(snap, "TokenWatch - OAuth Grant Risk Inventory")
    out += ["Risk = scope sensitivity x dormancy x consent type, with a "
            "loading for unverified publishers. Grants are ranked highest "
            "risk first.", ""]
    for i in inventory:
        flag = "FLAGGED" if i["flagged"] else "ok"
        out += [f"## {i['app']} - risk {i['risk']} [{flag}]",
                f"Scopes: {', '.join(i['scopes'])} "
                f"(scope score {i['scope_score']})",
                f"Last used: {i['last_used_days_ago']} days ago | "
                f"Consent: {i['consent_type']} | "
                f"Publisher verified: {i['publisher_verified']}"]
        if i["flag_reasons"]:
            out += ["Flag reasons: " + "; ".join(i["flag_reasons"]),
                    "Recommended action: confirm the owner still needs "
                    "this app; if not, revoke the grant (production step, "
                    "owner approved)."]
        out += [""]
    ais = ai_apps(inventory)
    out += ["## AI apps in this tenant", "",
            AI_IDENTIFICATION_NOTE, "",
            f"AI apps identified: {len(ais)} "
            f"(flagged by TokenWatch risk: "
            f"{sum(1 for i in ais if i['flagged'])})", ""]
    if not ais:
        out += ["No connected app was identified as an AI tool by "
                "name. That is not proof the firm uses no AI tools — "
                "only that none of the connected app names matched "
                "the known list.", ""]
    for i in ais:
        last = i["last_used_days_ago"]
        last_txt = ("last used unknown" if last is None
                    else f"last used {last} days ago")
        flag = "FLAGGED" if i["flagged"] else "not flagged"
        out += [f"### {i['app']} — identified as {i['ai_label']}",
                f"Consent: {i['consent_type']}"
                + (f" ({i['consented_by']})" if i["consented_by"]
                   else "")
                + f" | {last_txt} | Risk {i['risk']} [{flag}]",
                "What it can do: "
                + "; ".join(i["scopes_plain"]) + "."]
        if i["flag_reasons"]:
            out += ["Flag reasons: " + "; ".join(i["flag_reasons"])]
        out += [""]
    return "\n".join(out)


ANSWER_WORDING = {
    "Supported": "Yes — supported by scan evidence",
    "Gap": "No / not fully — see the gap note below",
    "Evidence missing": "Owner to complete — no evidence in this scan",
}


def render_insureready(snap, rows):
    """The broker pack: the InsureReady questionnaire restructured as
    a document the owner can hand to a cyber-insurance broker —
    plain answers first, scan evidence behind each one, and an
    owner-review section at the end. It stays a representative
    questionnaire, never a specific insurer's form."""
    out = header(snap, "InsureReady 365 - Cyber Insurance "
                       "Questionnaire Pack")
    supported = sum(1 for r in rows if r["status"] == "Supported")
    gaps = sum(1 for r in rows if r["status"] == "Gap")
    missing = sum(1 for r in rows if r["status"] == "Evidence missing")
    out += [
        "Prepared for the firm's cyber-insurance broker or insurer "
        "at renewal. Representative questionnaire: the questions a "
        "typical Canadian SMB cyber-insurance application asks, not "
        "a specific insurer's form. Every answer below is tied to "
        "scan evidence from the same snapshot, or is marked for the "
        "owner to complete — nothing is answered from a guess.", "",
        "## Summary", "",
        f"- Questions in this pack: {len(rows)}",
        f"- \"Yes — supported by scan evidence\": {supported}",
        f"- \"No / not fully\": {gaps}",
        f"- \"Owner to complete\": {missing}", "",
        "## The questionnaire", ""]
    for r in rows:
        out += [f"### {r['id']} — {r['question']}",
                f"**Answer: {ANSWER_WORDING[r['status']]}**",
                f"Evidence: {r['evidence']}"]
        if r["gap"]:
            out += [f"Gap: {r['gap']}"]
        out += [""]
    out += [
        "## Before you give this pack to a broker or insurer", "",
        "This pack is evidence prepared for the owner's review — "
        "it is not a submitted application and nothing in it has "
        "been attested. Before handing it over:", "",
        "1. Read every answer and confirm it is true for your firm "
        "today. If a scan answer no longer matches reality, correct "
        "the answer, not the evidence.",
        "2. Complete every \"Owner to complete\" item from your own "
        "records. Those questions are ones a scan cannot answer, "
        "and leaving them blank is better than guessing.",
        "3. Insurers treat answers on an application as fact at "
        "claim time. An answer that was wrong when given — even "
        "from an honest mistake — can give an insurer grounds to "
        "deny a claim, so the owner, not this tool, owns every "
        "answer that leaves the firm.", ""]
    return "\n".join(out)


def run_scan(snap):
    norm = normalise(snap)
    tf = tenantfix(snap, norm)
    tw = tokenwatch(snap)
    ir = insureready(snap, norm, tf, tw)
    return norm, tf, tw, ir


# ------------------------------------------------------------ verification --
def verify(snap, out_dir):
    norm, tf, tw, ir = run_scan(snap)
    planted = snap["_planted"]
    results = []

    def check(name, ok, detail=""):
        results.append({"check": name, "pass": bool(ok), "detail": detail})

    meta = snap["_meta"]
    check("engine: snapshot loads and is labelled fictional",
          meta.get("fictional") is True)
    check("engine: users normalised", len(norm["users"]) == 18,
          f"{len(norm['users'])} users")
    check("engine: OAuth grants normalised", len(tw) == 10,
          f"{len(tw)} grants")
    check("engine: global admins counted",
          len(norm["global_admins"]) == 4,
          f"{len(norm['global_admins'])} global admins")
    mfa_missing = [u["displayName"] for u in norm["enabled_members"]
                   if not u["mfaRegistered"]]
    check("engine: MFA gap count", len(mfa_missing) == 3,
          f"missing MFA: {', '.join(mfa_missing)}")

    # TenantFix planted vs caught
    actual_tf = {(f["check"], f["subject"]) for f in tf}
    for p in planted["tenantfix"]:
        key = (p["check"], p["subject"])
        check(f"TenantFix planted caught: {p['check']} / {p['subject']}",
              key in actual_tf)
    expected_tf = {(p["check"], p["subject"]) for p in planted["tenantfix"]}
    check("TenantFix: no unexpected findings",
          actual_tf == expected_tf,
          f"unexpected: {sorted(actual_tf - expected_tf)}")
    check("TenantFix: every finding has severity, why and fix steps",
          all(f["severity"] and f["why"] and f["fix_steps"] for f in tf))

    # TokenWatch planted vs caught
    flagged = {i["app"] for i in tw if i["flagged"]}
    for app in planted["tokenwatch_flagged"]:
        check(f"TokenWatch planted flagged: {app}", app in flagged)
    check("TokenWatch: no unexpected flagged grants",
          flagged == set(planted["tokenwatch_flagged"]),
          f"flagged: {sorted(flagged)}")
    check("TokenWatch: inventory covers every grant", len(tw) == 10)
    risks = [i["risk"] for i in tw]
    check("TokenWatch: inventory ranked by risk descending",
          risks == sorted(risks, reverse=True), f"risks: {risks}")
    check("TokenWatch: highest-risk grant is MailFlow Pro",
          tw[0]["app"] == "MailFlow Pro", f"top risk {tw[0]['risk']}")

    # InsureReady planted vs caught
    gap_ids = {r["id"] for r in ir if r["status"] in ("Gap",
                                                      "Evidence missing")}
    for qid in planted["insureready_gaps"]:
        check(f"InsureReady planted gap caught: {qid}", qid in gap_ids)
    for qid in planted["insureready_supported"]:
        row = next(r for r in ir if r["id"] == qid)
        check(f"InsureReady supported answer correct: {qid}",
              row["status"] == "Supported")
    check("InsureReady: no unexpected gaps",
          gap_ids == set(planted["insureready_gaps"]),
          f"gaps: {sorted(gap_ids)}")

    # Output honesty checks
    tf_md = render_tenantfix(snap, tf)
    tw_md = render_tokenwatch(snap, tw)
    ir_md = render_insureready(snap, ir)
    check("output: DRAFT stamp on all three reports",
          all(STAMP in doc for doc in (tf_md, tw_md, ir_md)))
    check("output: fix plan states it does NOT apply fixes",
          "does NOT apply" in tf_md)

    passed = sum(1 for r in results if r["pass"])
    summary = {
        "total_checks": len(results),
        "checks_passed": passed,
        "checks_failed": len(results) - passed,
        "tenantfix": {
            "planted": len(planted["tenantfix"]),
            "caught": sum(1 for p in planted["tenantfix"]
                          if (p["check"], p["subject"]) in actual_tf),
            "total_findings": len(tf)},
        "tokenwatch": {
            "planted_flagged": len(planted["tokenwatch_flagged"]),
            "caught_flagged": sum(1 for a in planted["tokenwatch_flagged"]
                                  if a in flagged),
            "grants_inventoried": len(tw)},
        "insureready": {
            "planted_gaps": len(planted["insureready_gaps"]),
            "caught_gaps": sum(1 for q in planted["insureready_gaps"]
                               if q in gap_ids),
            "questions_total": len(ir)},
        "results": results,
    }
    if out_dir:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "tenantfix_report.md").write_text(tf_md, encoding="utf-8")
        (out / "tokenwatch_report.md").write_text(tw_md, encoding="utf-8")
        (out / "insureready_evidence_pack.md").write_text(
            ir_md, encoding="utf-8")
        (out / "combined_scan.json").write_text(json.dumps(
            {"tenantfix_findings": tf, "tokenwatch_inventory": tw,
             "insureready_rows": ir}, indent=2), encoding="utf-8")
        (out / "verification.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8")
        lines = ["# Verification report", "", f"**{STAMP}**", "",
                 f"Checks passed: {summary['checks_passed']} / "
                 f"{summary['total_checks']}  |  "
                 f"Failed: {summary['checks_failed']}", ""]
        lines += [f"- {'PASS' if r['pass'] else 'FAIL'} - {r['check']}"
                  + (f" ({r['detail']})" if r["detail"] else "")
                  for r in results]
        (out / "verification_report.md").write_text(
            "\n".join(lines), encoding="utf-8")
    return summary


def main(argv):
    if len(argv) < 3 or argv[1] not in ("scan", "verify"):
        print("Usage: python3 m365.py scan|verify <snapshot.json> "
              "[--out DIR]")
        return 2
    mode, snap_path = argv[1], argv[2]
    out_dir = None
    if "--out" in argv:
        out_dir = argv[argv.index("--out") + 1]
    snap = load_snapshot(snap_path)
    if mode == "scan":
        norm, tf, tw, ir = run_scan(snap)
        if out_dir:
            verify(snap, out_dir)  # scan reuses verify's report writers
        print(f"TenantFix findings: {len(tf)}")
        print(f"TokenWatch grants inventoried: {len(tw)} "
              f"(flagged: {sum(1 for i in tw if i['flagged'])})")
        print(f"InsureReady questions: {len(ir)} "
              f"(gaps: {sum(1 for r in ir if r['status'] != 'Supported')})")
        return 0
    summary = verify(snap, out_dir)
    for r in summary["results"]:
        print(f"{'PASS' if r['pass'] else 'FAIL'} - {r['check']}"
              + (f" ({r['detail']})" if r["detail"] else ""))
    print(f"\nChecks passed: {summary['checks_passed']} / "
          f"{summary['total_checks']} | Failed: {summary['checks_failed']}")
    print(f"TenantFix: planted {summary['tenantfix']['planted']}, "
          f"caught {summary['tenantfix']['caught']}")
    print(f"TokenWatch: planted flagged "
          f"{summary['tokenwatch']['planted_flagged']}, caught "
          f"{summary['tokenwatch']['caught_flagged']}")
    print(f"InsureReady: planted gaps "
          f"{summary['insureready']['planted_gaps']}, caught "
          f"{summary['insureready']['caught_gaps']}")
    return 0 if summary["checks_failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
