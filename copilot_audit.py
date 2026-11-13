#!/usr/bin/env python3
"""
CopilotReady — the Copilot oversharing audit for TenantCheck 365.

A companion module to the verified engine in m365.py (which is NOT
modified by this build). Where TenantFix checks tenant-level sharing
toggles, this audit reads the per-site / per-library permission
inventory in the snapshot's "sharingInventory" section and reports,
in plain English, what Microsoft Copilot could surface to staff who
should not see it.

Why this matters: Copilot answers only from content the asking user
is already allowed to read — which means every broad grant that has
quietly accumulated in SharePoint and OneDrive (an "anyone with the
link" link, an "Everyone except external users" grant, a company-wide
link) becomes content Copilot can quote back to anyone in that broad
audience, instantly, in answer form. Oversharing that used to require
browsing and luck to find becomes a question away.

Snapshot section consumed (all fields are a normalised digest of
Microsoft Graph site / drive permission lists — see
tools/tenantcheck-export.ps1 for how each is produced):

  sharingInventory: list of items, one per SharePoint site or
  OneDrive drive, each:
    id                            snapshot-local id
    kind                          "sharepoint-site" | "onedrive"
    displayName                   site / drive name
    webUrl                        URL, or null
    ownerDisplayName              an owner found in the item's
                                  permission lists or drive ownership,
                                  or null when none was found
    ownerAccountEnabled           true / false / null (unknown)
    anyoneLinks                   count of anonymous ("anyone with
                                  the link") link permissions found
    anyoneLinkAccess              "edit" | "view" | null — the
                                  broadest access those links grant
    organizationLinks             count of company-wide link
                                  permissions found
    organizationLinkAccess        "edit" | "view" | null
    everyoneAccess                "edit" | "read" | null — access
                                  granted to the "Everyone" claim,
                                  which can include people outside
                                  the staff list
    everyoneExceptExternalUsersAccess
                                  "edit" | "read" | null — access
                                  granted to every staff member
    guestCount                    distinct guest accounts in the
                                  item's permission lists, or null
    guestReshareAllowed           true / false / null — whether
                                  guests may re-share. Graph does
                                  not expose this; the export writes
                                  null and the check stays silent.

HONEST LIMITS (also printed in every report):
  * The export reads site-level and library-root permission lists.
    Sharing links attached to individual files or folders below that
    level are NOT enumerated — that needs a per-item crawl of every
    file, which no export snapshot contains. A clean audit is
    therefore not proof that no file-level link exists.
  * The audit sees permissions, never file contents, so it cannot
    judge how sensitive a site's contents are; the owner judges
    that from the names and findings.
  * The snapshot does not record whether the firm has bought
    Copilot licences. Findings are stated as exposure IF Copilot
    (or any broad-audience reader) is used — the underlying grants
    are worth fixing either way.
  * If a snapshot has no "sharingInventory" section (older exports,
    the live-Graph path today), the audit reports itself NOT
    COVERED and produces no findings — never a silent pass.

Like the rest of TenantCheck 365, this module prepares evidence; it
does not certify compliance and is not legal or insurance advice.
Reports carry the engine's DRAFT stamp. Nothing here connects to a
live tenant or changes anything.

Python standard library only.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import m365  # for the shared STAMP and report header; engine untouched

MODULE = "CopilotReady"

NOT_COVERED_NOTE = (
    "This snapshot contains no sharing inventory (the "
    "\"sharingInventory\" section), so the Copilot oversharing "
    "audit did not run. That is not a pass: the audit needs an "
    "export that includes site and library permission lists — the "
    "current export script produces one. Nothing was guessed to "
    "fill the gap.")

LIMITS = [
    "The export reads site-level and library-root permission lists. "
    "Sharing links attached to individual files or folders below "
    "that level are not enumerated — that needs a per-item crawl of "
    "every file, which no export snapshot contains. No finding here "
    "is not proof that no file-level link exists.",
    "The audit sees permissions, never file contents, so it cannot "
    "judge how sensitive a site's contents are. The owner judges "
    "that from the names and findings.",
    "The snapshot does not record whether the firm has bought "
    "Copilot licences. Findings describe exposure if Copilot is "
    "used — and the same grants are readable today by anyone in "
    "the audience they name, Copilot or not.",
    "Whether guests can re-share is not exposed by Microsoft "
    "Graph, so the export records it as unknown and that check "
    "stays silent rather than guessing.",
]


def _access_word(access):
    return {"edit": "edit", "read": "read", "view": "open"}.get(
        access, access or "")


def copilotaudit(snap):
    """Run the oversharing audit on a snapshot.

    Returns {"covered": bool, "items_reviewed": int,
             "findings": [finding, ...]} where each finding mirrors
    the TenantFix finding shape (module, check, subject, severity,
    title, why, fix_steps)."""
    inventory = snap.get("sharingInventory")
    if not isinstance(inventory, list):
        return {"covered": False, "items_reviewed": 0, "findings": []}

    findings = []

    def add(check, item, severity, title, why, fix):
        findings.append({
            "module": MODULE, "check": check,
            "subject": item.get("displayName") or item.get("id")
            or "unnamed item",
            "severity": severity, "title": title, "why": why,
            "fix_steps": fix,
        })

    for item in inventory:
        if not isinstance(item, dict):
            continue
        name = item.get("displayName") or item.get("id") \
            or "unnamed item"
        kind_word = ("OneDrive drive" if item.get("kind") == "onedrive"
                     else "SharePoint site")

        # CA-ANYONE-LINK: anonymous links found in the permission
        # lists. No sign-in, no expiry by default; and the content
        # behind them sits in Copilot's reach for staff too.
        anyone = item.get("anyoneLinks") or 0
        if anyone > 0:
            access = item.get("anyoneLinkAccess")
            add("CA-ANYONE-LINK", item,
                "Critical" if access == "edit" else "High",
                f"Anonymous sharing link(s) on {name}: {anyone} found",
                f"The permission lists for this {kind_word} include "
                f"{anyone} \"anyone with the link\" link(s)"
                + (f", and at least one of them allows editing"
                   if access == "edit" else "")
                + ". Anyone who gets the link can open the content "
                  "with no sign-in, and links get forwarded and left "
                  "in old emails. The same content is also inside "
                  "Copilot's reach: because the link makes it broadly "
                  "readable, Copilot can surface it in answers to "
                  "staff who would never have gone looking for it.",
                ["Review each anonymous link on this site and remove "
                 "the ones nobody can explain.",
                 "Share to named people instead of links wherever "
                 "possible.",
                 "If a link must stay, give it an expiry date and "
                 "view-only access (production step, owner "
                 "approved)."])

        # CA-EVERYONE-EXTERNAL: the "Everyone" claim can include
        # people beyond the staff list (guests included).
        everyone = item.get("everyoneAccess")
        if everyone:
            add("CA-EVERYONE-EXTERNAL", item, "High",
                f"Shared with \"Everyone\": {name}",
                f"This {kind_word} grants {_access_word(everyone)} "
                f"access to the \"Everyone\" group. In many tenants "
                f"that group reaches beyond your own staff — guests "
                f"can be included — so the real audience may be "
                f"wider than the name suggests. Everyone in that "
                f"audience can also have Copilot quote this content "
                f"back to them in answers.",
                ["Confirm who \"Everyone\" actually includes in "
                 "this tenant.",
                 "Replace the grant with a named group of the "
                 "people who need this site.",
                 "Re-check after the change that the content is no "
                 "longer broadly readable (production step, owner "
                 "approved)."])

        # CA-EVERYONE-STAFF: "Everyone except external users" =
        # every single staff member, and therefore Copilot for
        # every single staff member.
        eeeu = item.get("everyoneExceptExternalUsersAccess")
        if eeeu:
            add("CA-EVERYONE-STAFF", item,
                "High" if eeeu == "edit" else "Medium",
                f"Shared with every staff member: {name}",
                f"This {kind_word} grants {_access_word(eeeu)} "
                f"access to \"Everyone except external users\" — "
                f"literally every staff account. That may be "
                f"intended for a general team site, but it also "
                f"means Copilot can read this content and quote it "
                f"to any employee who asks, including new starters "
                f"and people in unrelated roles. Payroll, client and "
                f"owner material does not belong in front of that "
                f"audience.",
                ["Confirm this site is genuinely meant for every "
                 "staff member.",
                 "If not, narrow the grant to the team or group "
                 "that owns the content.",
                 "Move sensitive libraries to their own restricted "
                 "site (production step, owner approved)."])

        # CA-ORG-LINK: company-wide links ("people in your
        # organization with the link").
        org_links = item.get("organizationLinks") or 0
        if org_links > 0:
            add("CA-ORG-LINK", item, "Medium",
                f"Company-wide sharing link(s) on {name}: "
                f"{org_links} found",
                f"The permission lists for this {kind_word} include "
                f"{org_links} company-wide link(s): anyone in the "
                f"organization who gets the link can open the "
                f"content, and links travel — forwarded, pasted into "
                f"chats, left in old threads. The audience is the "
                f"whole firm, not the people the owner picked, and "
                f"Copilot's answers respect the same audience.",
                ["Review each company-wide link and remove the "
                 "ones nobody can explain.",
                 "Prefer sharing to named people or a named group.",
                 "If a link must stay, give it an expiry date "
                 "(production step, owner approved)."])

        # CA-OWNERLESS: a site with no owner found has nobody
        # accountable for reviewing exactly these grants.
        if item.get("kind") == "sharepoint-site" \
                and not item.get("ownerDisplayName"):
            add("CA-OWNERLESS", item, "Medium",
                f"No owner found for site: {name}",
                "No owner was found in this site's permission lists "
                "or drive ownership. An ownerless site has nobody "
                "accountable for reviewing who can read it, so broad "
                "grants on it tend to survive for years — and "
                "Copilot keeps surfacing its content to everyone "
                "those grants allow.",
                ["Assign a named owner who actually uses the site.",
                 "Have that owner review the site's sharing and "
                 "confirm it is still needed.",
                 "Delete or archive sites nobody owns (production "
                 "step, owner approved)."])

        # CA-DISABLED-OWNER: the owner's account is disabled (a
        # leaver, typically) but their content and its grants live
        # on, unreviewed.
        if item.get("ownerAccountEnabled") is False:
            owner = item.get("ownerDisplayName") or "its owner"
            add("CA-DISABLED-OWNER", item, "Medium",
                f"Owner's account is disabled: {name}",
                f"This {kind_word} belongs to {owner}, whose "
                f"account is disabled. Content owned by people who "
                f"have left keeps whatever sharing it had, with "
                f"nobody watching it — and Copilot can still "
                f"surface it to everyone the old grants allow.",
                ["Transfer ownership to a current staff member.",
                 "Review the sharing on the transferred content "
                 "before the old owner's access is fully removed.",
                 "Add owned-content transfer to the leaving "
                 "checklist (production step, owner approved)."])

        # CA-GUEST-RESHARE: guests who can pass access on to people
        # the owner never chose. Silent when the export could not
        # tell (Graph does not expose it → null).
        if item.get("guestReshareAllowed") is True:
            guests = item.get("guestCount")
            guest_txt = (f" It currently has {guests} guest "
                         f"account(s) in its permission lists."
                         if guests else "")
            add("CA-GUEST-RESHARE", item, "Medium",
                f"Guests can re-share: {name}",
                f"Guests on this {kind_word} are allowed to share "
                f"its content onward, to people the owner never "
                f"chose or reviewed.{guest_txt} Every onward share "
                f"widens the audience Copilot and search can reach "
                f"the content through.",
                ["Turn off guest re-sharing for this site unless "
                 "there is a documented reason for it.",
                 "Review the current guest list and remove anyone "
                 "whose work has finished (production step, owner "
                 "approved)."])
    return {"covered": True, "items_reviewed": len(inventory),
            "findings": findings}


def render_copilotaudit(snap, result):
    out = m365.header(snap, "CopilotReady - Oversharing Audit")
    out += ["This audit reads the per-site and per-library "
            "permission inventory in the snapshot and reports what "
            "Microsoft Copilot could surface to staff who should "
            "not see it. Copilot answers only from what the asking "
            "user may already read — broad grants are therefore the "
            "exposure. Findings are issues to review; the owner "
            "makes the call.", ""]
    if not result["covered"]:
        out += ["**NOT COVERED BY THIS SNAPSHOT**", "",
                NOT_COVERED_NOTE, ""]
        return "\n".join(out)
    findings = result["findings"]
    broad = len({f["subject"] for f in findings})
    out += [f"Sites and drives reviewed: {result['items_reviewed']}",
            f"Findings: {len(findings)} across {broad} item(s)", ""]
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for f in sorted(findings, key=lambda x: order[x["severity"]]):
        out += [f"## [{f['severity']}] {f['title']}",
                f"Check: {f['check']} | Subject: {f['subject']}", "",
                f"Why it matters: {f['why']}", "", "Fix steps:"]
        out += [f"{i}. {s}" for i, s in enumerate(f["fix_steps"], 1)]
        out += [""]
    if not findings:
        out += ["No oversharing findings in the permission lists "
                "this snapshot contains. That is not a guarantee — "
                "see the limits below.", ""]
    out += ["## What this audit cannot see", ""]
    out += [f"- {limit}" for limit in LIMITS]
    out += [""]
    return "\n".join(out)
