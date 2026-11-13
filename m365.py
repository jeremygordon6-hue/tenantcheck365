#!/usr/bin/env python3
"""
M365 Cluster prototype - one tenant scan engine, three paid outputs.

Modules:
  TenantFix 365   - deterministic hardening checks + owner-approved fix plan
  TokenWatch      - OAuth grant inventory ranked by scope sensitivity and
                    consent. Time unused changes the rank only when a
                    real last-use date is present.
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
        inventory.append({
            "module": "TokenWatch", "app": g["appDisplayName"],
            "scopes": g["scopes"], "scope_score": ss,
            "last_used_days_ago": g["lastUsedDaysAgo"],
            "consent_type": ("user-consented (single user)"
                             if g["consentType"] == "Principal"
                             else "admin-consented (tenant-wide)"),
            "publisher_verified": g["publisherVerified"],
            "risk": risk, "flagged": flagged, "flag_reasons": reasons,
        })
    inventory.sort(key=lambda x: x["risk"], reverse=True)
    return inventory


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
    rows.append(row(
        "IR-Q04", "Are Conditional Access policies in place?",
        "Supported" if c["conditionalAccessPolicyCount"] >= 1 else "Gap",
        f"Scan evidence: {c['conditionalAccessPolicyCount']} Conditional "
        f"Access policies found in the snapshot.",
        "" if c["conditionalAccessPolicyCount"] >= 1 else
        "No policy enforces the MFA and legacy-auth answers above; they "
        "rest on user behaviour only."))
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
    out += ["Ranked by scope sensitivity, whether one user approved the "
            "grant, and whether the publisher is verified. Time unused "
            "raises the score only when a last-use date is present. An "
            "unknown last use does not change the rank. Grants are "
            "ranked highest risk first.", ""]
    for i in inventory:
        flag = "FLAGGED" if i["flagged"] else "ok"
        last = i["last_used_days_ago"]
        last_txt = "unknown" if last is None else f"{last} days ago"
        out += [f"## {i['app']} - risk {i['risk']} [{flag}]",
                f"Scopes: {', '.join(i['scopes'])} "
                f"(scope score {i['scope_score']})",
                f"Last used: {last_txt} | "
                f"Consent: {i['consent_type']} | "
                f"Publisher verified: {i['publisher_verified']}"]
        if i["flag_reasons"]:
            out += ["Flag reasons: " + "; ".join(i["flag_reasons"]),
                    "Recommended action: confirm the owner still needs "
                    "this app; if not, revoke the grant (production step, "
                    "owner approved)."]
        out += [""]
    return "\n".join(out)


def render_insureready(snap, rows):
    out = header(snap, "InsureReady 365 - Cyber Insurance Evidence Pack")
    out += ["Representative questionnaire: a typical Canadian SMB cyber "
            "insurance evidence questionnaire, not a specific insurer's "
            "form. Each answer below is tied to scan evidence from the "
            "same snapshot.", ""]
    for r in rows:
        out += [f"## {r['id']} - {r['question']}",
                f"Answer supported by evidence: **{r['status']}**",
                r["evidence"]]
        if r["gap"]:
            out += [f"Gap: {r['gap']}"]
        out += [""]
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
    check("engine: OAuth grants normalised", len(tw) == 8,
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
    check("TokenWatch: inventory covers every grant", len(tw) == 8)
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
