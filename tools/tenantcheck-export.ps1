<#
.SYNOPSIS
  TenantCheck 365 - guided tenant export helper.

.DESCRIPTION
  Run this script on a Windows machine, signed in as your own firm's
  Microsoft 365 administrator. It connects to Microsoft Graph with the
  Microsoft Graph PowerShell SDK using READ-ONLY permissions, reads the
  tenant settings a TenantCheck 365 scan needs, asks you a short set of
  questions only you can answer, and writes ONE local file:

      tenantcheck-snapshot.json

  You then upload that file yourself on the TenantCheck 365 scan page.
  The script sends nothing anywhere: its only network activity is the
  Graph sign-in and reads performed by Microsoft's own SDK, in your
  session, under your account.

  HONESTY RULES THIS SCRIPT FOLLOWS
  * It never asks for, stores, or transmits your password or any other
    credential. Sign-in happens in the SDK's own browser window,
    between you and Microsoft.
  * Every value in the file comes from your tenant via Graph, from
    Microsoft Entra platform behaviour (labelled as such below), or
    from answers YOU type during the run.
  * Where Graph cannot supply something the scan asks about, the
    script either asks you, or writes a fail-safe "no evidence" value
    and tells you on screen exactly which answers defaulted, so the
    report shows a gap to review instead of an invented pass.

  WHAT GRAPH CANNOT SUPPLY (and how this script handles it)
  * EDR coverage, device encryption coverage, backup state and restore
    tests, security training currency, a written incident plan, and
    whether updates are automatic are facts about your firm's devices
    and documents, not tenant settings. The script ASKS you for them.
    Pressing Enter ("don't know") records the fail-safe value and the
    final summary lists every default.
  * SharePoint's external sharing level lives in the SharePoint admin
    settings, not in Graph. The script asks you to pick the level you
    see under SharePoint admin centre > Policies > Sharing. If you are
    not sure, it records the middle option and flags it for you to
    verify before trusting the sharing result.
  * How long ago each third-party app grant was last used is not
    exposed by Graph. lastUsedDaysAgo is written as null for every
    grant; the scan then scores dormancy neutrally instead of guessing.
  * If a mailbox's inbox rules cannot be read (no mailbox on the
    account, or no access to it), the script counts that mailbox as
    skipped and writes the count into the export as exportCoverage.
    The scan reports the forwarding answer for those mailboxes as
    evidence missing, never as "no rules found".
  * How broadly a guest account can reach inside the tenant is not
    exposed by Graph. guestAccessLevel is written as null; the scan
    never flags a guest on a guess. Review guest access manually.
  * For the Copilot oversharing audit, the script reads site-level
    and library-root (drive root) permission lists only. Sharing
    links attached to individual files or folders below that level
    are NOT enumerated - that needs a per-item crawl of every file.
    A clean audit is therefore not proof that no file-level link
    exists, and the report says so.
  * Whether guests may re-share a site's content is not exposed by
    Graph. guestReshareAllowed is written as null in every sharing
    inventory item; that check stays silent rather than guessing.
  * A cloud tenant's password length/complexity values are not
    tenant-configurable in Microsoft Entra ID, so Graph does not
    return them. The script writes the Entra platform values
    (minimum length 8, complexity required, smart lockout 10).
  * Each user's last sign-in needs an Entra ID P1/P2 licence for the
    signInActivity data. Without it, lastSignInDaysAgo is null and the
    dormant-account checks simply stay silent for that account.

.PARAMETER OutFile
  Where to write the snapshot. Default: tenantcheck-snapshot.json in
  the current folder.

.EXAMPLE
  Unblock-File -LiteralPath .\tenantcheck-export.ps1
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
  .\tenantcheck-export.ps1

.NOTES
  Requirements: Windows PowerShell 5.1 or PowerShell 7, the Microsoft
  Graph PowerShell SDK (the script prints install instructions if it
  is missing), and a Global Administrator (or Global Reader plus the
  reports permissions) account in the tenant being exported.
#>
[CmdletBinding()]
param(
    [string]$OutFile = "tenantcheck-snapshot.json"
)

$ErrorActionPreference = "Continue"

# Read-only delegated scopes. Nothing here can change your tenant, and
# the script only ever reads: it calls no update or remove cmdlet.
$Scopes = @(
    "User.Read.All",
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "Policy.Read.All",
    "AuditLog.Read.All",
    "Organization.Read.All",
    "Sites.Read.All",    # site and library PERMISSION LISTS for the
                         # Copilot oversharing audit. Permission
                         # settings only - never file contents.
    "MailboxSettings.Read"  # inbox rules only (rule settings such as
                         # forwarding targets). MailboxSettings.Read is
                         # the least-privileged permission that covers
                         # listing a mailbox's inbox rules - it exposes
                         # rule settings, never message contents.
)

# Fields that ended up as fail-safe defaults because the owner answered
# "don't know" or a Graph read failed. Printed in the final summary.
$DefaultedAnswers = New-Object System.Collections.Generic.List[string]

function ConvertTo-DaysAgo {
    param($DateTime)
    if ($null -eq $DateTime) { return $null }
    try {
        $days = [int][Math]::Floor(((Get-Date) - [datetime]$DateTime).TotalDays)
        if ($days -lt 0) { return 0 }
        return $days
    } catch { return $null }
}

function ConvertTo-SnapshotMethod {
    param([string]$Method)
    switch -Regex ($Method) {
        "microsoftAuthenticator" { return "microsoftAuthenticator" }
        "fido2"                  { return "fido2" }
        "phone|mobilePhone|sms|voice" { return "phone" }
        default                  { return $Method }
    }
}

function Ask-OptionalInt {
    param([string]$Prompt)
    $raw = Read-Host $Prompt
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $value = 0
    if ([int]::TryParse($raw.Trim(), [ref]$value)) { return $value }
    Write-Host "  (not a number - treated as don't know)"
    return $null
}

function Ask-YesNo {
    param([string]$Prompt)
    while ($true) {
        $raw = (Read-Host "$Prompt (y/n, Enter = don't know)").Trim().ToLower()
        if ($raw -eq "") { return $null }
        if ($raw -eq "y") { return $true }
        if ($raw -eq "n") { return $false }
        Write-Host "  Please answer y or n, or press Enter."
    }
}

Write-Host ""
Write-Host "TenantCheck 365 - guided tenant export"
Write-Host "======================================"
Write-Host "This writes ONE local file ($OutFile) and sends nothing anywhere."
Write-Host ""

# ---------------------------------------------------------------- module --
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "The Microsoft Graph PowerShell SDK is not installed yet."
    Write-Host "Install it once, in this window, with:"
    Write-Host ""
    Write-Host "    Install-Module Microsoft.Graph -Scope CurrentUser"
    Write-Host ""
    Write-Host "Then run this script again."
    exit 1
}

# ---------------------------------------------------------------- sign-in -
Write-Host "Step 1 of 4 - sign in. A Microsoft sign-in window opens; sign in"
Write-Host "with YOUR OWN admin account. This script never sees your password."
try {
    Connect-MgGraph -Scopes $Scopes -Welcome -ErrorAction Stop
} catch {
    Write-Host "Sign-in did not complete: $($_.Exception.Message)"
    exit 1
}
$context = Get-MgContext
if ($null -eq $context -or $null -eq $context.Account) {
    Write-Host "No signed-in context. Nothing was exported."
    exit 1
}
Write-Host "Signed in as $($context.Account)."
Write-Host ""

# ------------------------------------------------------------------- org --
Write-Host "Step 2 of 4 - reading your tenant (read only)..."
$org = $null
try { $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1 } catch {}
$firmName = $null
if ($null -ne $org) { $firmName = $org.DisplayName }

# ------------------------------------------------------------------ users -
$graphUsers = @()
try {
    $graphUsers = @(Get-MgUser -All -ErrorAction Stop -Property @("Id","DisplayName","UserPrincipalName","AccountEnabled","UserType","Department","SignInActivity"))
} catch {
    Write-Host "Could not read the user list: $($_.Exception.Message)"
    Write-Host "The scan needs at least the user list, so nothing was written."
    Disconnect-MgGraph | Out-Null
    exit 1
}
if ($graphUsers.Count -eq 0) {
    Write-Host "Graph returned no users. Nothing was written."
    Disconnect-MgGraph | Out-Null
    exit 1
}

# MFA registration state, from the authentication methods report.
$mfaByUpn = @{}
try {
    $details = @(Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop)
    foreach ($d in $details) {
        $methods = @()
        foreach ($m in @($d.MethodsRegistered)) {
            if ($null -ne $m -and "$m" -ne "") {
                $methods += ConvertTo-SnapshotMethod "$m"
            }
        }
        $mfaByUpn[("$($d.UserPrincipalName)").ToLower()] = @{
            Registered = [bool]$d.IsMfaRegistered
            Methods    = @($methods | Select-Object -Unique)
        }
    }
} catch {
    Write-Host "  Note: the MFA registration report could not be read"
    Write-Host "  ($($_.Exception.Message)). Accounts will show as having"
    Write-Host "  no MFA method in the export - the scan errs on the safe side."
    $DefaultedAnswers.Add("mfaRegistered for all accounts (registration report unreadable)")
}

# Directory role assignments: principal id -> role display names.
$roleNamesById = @{}
try {
    $defs = @(Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop)
    foreach ($def in $defs) { $roleNamesById[$def.Id] = $def.DisplayName }
} catch {}
$rolesByPrincipal = @{}
try {
    $assignments = @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop `
        -Property @("PrincipalId","RoleDefinitionId"))
    foreach ($a in $assignments) {
        if (-not $rolesByPrincipal.ContainsKey($a.PrincipalId)) {
            $rolesByPrincipal[$a.PrincipalId] = New-Object System.Collections.Generic.List[string]
        }
        $name = $roleNamesById[$a.RoleDefinitionId]
        if ($null -ne $name) { $rolesByPrincipal[$a.PrincipalId].Add($name) }
    }
} catch {
    Write-Host "  Note: directory role assignments could not be read; roles"
    Write-Host "  will be empty in the export and admin checks stay silent."
}

$usersOut = New-Object System.Collections.Generic.List[object]
foreach ($u in $graphUsers) {
    $upnKey = ("$($u.UserPrincipalName)").ToLower()
    $mfa = $mfaByUpn[$upnKey]
    $roles = @()
    if ($rolesByPrincipal.ContainsKey($u.Id)) {
        $roles = @($rolesByPrincipal[$u.Id])
    }
    $lastSignIn = $null
    if ($null -ne $u.SignInActivity) {
        $lastSignIn = ConvertTo-DaysAgo $u.SignInActivity.LastSignInDateTime
    }
    $accountType = "member"
    if ("$($u.UserType)" -eq "Guest") { $accountType = "guest" }
    $usersOut.Add([ordered]@{
        accountEnabled    = [bool]$u.AccountEnabled
        accountType       = $accountType
        authMethods       = @($(if ($null -ne $mfa) { $mfa.Methods } else { @() }))
        department        = $u.Department
        displayName       = $u.DisplayName
        # Graph does not expose how broadly a guest can reach inside
        # the tenant; null means the scan never flags a guest on a guess.
        guestAccessLevel  = $null
        id                = $u.Id
        lastSignInDaysAgo = $lastSignIn
        mfaRegistered     = [bool]$(if ($null -ne $mfa) { $mfa.Registered } else { $false })
        roles             = @($roles)
        userPrincipalName = $u.UserPrincipalName
    })
}
$enabledMembers = @($usersOut | Where-Object { $_.accountEnabled -and $_.accountType -eq "member" })
Write-Host "  Users: $($usersOut.Count) accounts ($($enabledMembers.Count) enabled members)."

# ------------------------------------------------------------- inbox rules -
# Mailboxes the script cannot read are COUNTED, not passed over
# silently: the counts go into the snapshot as exportCoverage, and
# the scan reports the forwarding answer as evidence missing for
# skipped mailboxes - never as "no rules found".
$rulesOut = New-Object System.Collections.Generic.List[object]
$mailboxesChecked = 0
$mailboxesSkipped = 0
foreach ($u in $graphUsers) {
    if ("$($u.UserType)" -eq "Guest") { continue }
    $mailboxRules = @()
    try {
        $mailboxRules = @(Get-MgUserMailFolderMessageRule -UserId $u.Id `
            -MailFolderId "inbox" -All -ErrorAction Stop)
        $mailboxesChecked++
    } catch {
        $mailboxesSkipped++
        continue   # no mailbox on this account, or no access to it
    }
    foreach ($r in $mailboxRules) {
        $forward = @()
        $redirect = @()
        $delete = $false
        if ($null -ne $r.Actions) {
            foreach ($t in @($r.Actions.ForwardTo)) {
                if ($null -ne $t.EmailAddress -and $null -ne $t.EmailAddress.Address) {
                    $forward += $t.EmailAddress.Address
                }
            }
            foreach ($t in @($r.Actions.RedirectTo)) {
                if ($null -ne $t.EmailAddress -and $null -ne $t.EmailAddress.Address) {
                    $redirect += $t.EmailAddress.Address
                }
            }
            if ($null -ne $r.Actions.DeleteMessage) { $delete = [bool]$r.Actions.DeleteMessage }
        }
        $enabled = $true
        if ($null -ne $r.IsEnabled) { $enabled = [bool]$r.IsEnabled }
        $rulesOut.Add([ordered]@{
            deleteMessage     = $delete
            enabled           = $enabled
            forwardTo         = @($forward)
            id                = $r.Id
            name              = "$($r.DisplayName)"
            redirectTo        = @($redirect)
            userDisplayName   = $u.DisplayName
            userPrincipalName = $u.UserPrincipalName
        })
    }
}
Write-Host "  Inbox rules: $($rulesOut.Count) read from $mailboxesChecked mailboxes (rule settings only, never message contents); $mailboxesSkipped mailboxes could not be read and are recorded as skipped in the export."

# -------------------------------------------------------------- oauth grants -
$spById = @{}
function Get-ServicePrincipalCached {
    param([string]$ObjectId)
    if ([string]::IsNullOrWhiteSpace($ObjectId)) { return $null }
    if (-not $spById.ContainsKey($ObjectId)) {
        $sp = $null
        try {
            $sp = Get-MgServicePrincipal -ServicePrincipalId $ObjectId -ErrorAction Stop `
                -Property @("Id","AppId","DisplayName","VerifiedPublisher")
        } catch {}
        $spById[$ObjectId] = $sp
    }
    return $spById[$ObjectId]
}
$userUpnById = @{}
foreach ($u in $graphUsers) { $userUpnById[$u.Id] = $u.UserPrincipalName }

$grantsOut = New-Object System.Collections.Generic.List[object]
try {
    $grants = @(Get-MgOauth2PermissionGrant -All -ErrorAction Stop `
        -Property @("Id","ClientId","ConsentType","PrincipalId","ResourceId","Scope"))
    foreach ($g in $grants) {
        $clientSp = Get-ServicePrincipalCached $g.ClientId
        $resourceSp = Get-ServicePrincipalCached $g.ResourceId
        $appName = $null
        $verified = $false
        if ($null -ne $clientSp) {
            $appName = $clientSp.DisplayName
            if ($null -ne $clientSp.VerifiedPublisher -and
                -not [string]::IsNullOrWhiteSpace($clientSp.VerifiedPublisher.VerifiedPublisherId)) {
                $verified = $true
            }
        }
        if ([string]::IsNullOrWhiteSpace($appName)) {
            $appName = "Unresolved app $($g.ClientId)"
        }
        $resourceName = ""
        if ($null -ne $resourceSp) { $resourceName = $resourceSp.DisplayName }
        $consentedBy = $null
        if ("$($g.ConsentType)" -eq "Principal" -and $null -ne $g.PrincipalId) {
            $consentedBy = $userUpnById[$g.PrincipalId]
        }
        $scopes = @()
        if ($null -ne $g.Scope) {
            $scopes = @("$($g.Scope)".Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries))
        }
        $grantsOut.Add([ordered]@{
            appDisplayName      = $appName
            clientId            = $g.ClientId
            consentType         = "$($g.ConsentType)"
            consentedBy         = $consentedBy
            id                  = $g.Id
            # Graph does not expose when a grant was last used; null
            # keeps the dormancy score neutral instead of guessed.
            lastUsedDaysAgo     = $null
            publisherVerified   = $verified
            resourceDisplayName = $resourceName
            scopes              = @($scopes)
        })
    }
} catch {
    Write-Host "  Note: OAuth permission grants could not be read"
    Write-Host "  ($($_.Exception.Message)). The grant inventory will be empty."
}
Write-Host "  App grants: $($grantsOut.Count) inventoried."

# -------------------------------------------------------- sharing inventory -
# Per-site / per-library permission digest for the Copilot
# oversharing audit. Reads site permission lists and each site's
# default library (drive) root permission list, plus drive ownership
# and the OneDrive root permissions of DISABLED accounts (a leaver's
# drive keeps its sharing after the account is switched off).
# Permission settings only - file contents are never read, and
# sharing links on individual files below the library root are not
# enumerated (see the header notes).
function Get-GraphProp {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) {
        if ($Obj.Contains($Name)) { return $Obj[$Name] }
        return $null
    }
    $prop = $Obj.PSObject.Properties[$Name]
    if ($null -ne $prop) { return $prop.Value }
    return $null
}

function Get-GraphCollection {
    param([string]$Uri)
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $next -ErrorAction Stop
        foreach ($v in @(Get-GraphProp $resp "value")) {
            if ($null -ne $v) { $items.Add($v) }
        }
        $next = Get-GraphProp $resp "@odata.nextLink"
    }
    return $items
}

$userEnabledById = @{}
$guestIdSet = New-Object System.Collections.Generic.HashSet[string]
foreach ($u in $graphUsers) {
    $userEnabledById[$u.Id] = [bool]$u.AccountEnabled
    if ("$($u.UserType)" -eq "Guest") { [void]$guestIdSet.Add($u.Id) }
}

function Read-SharingDigest {
    param([object[]]$Permissions)
    $digest = @{
        AnyoneLinks = 0; AnyoneAccess = $null
        OrgLinks = 0; OrgAccess = $null
        EveryoneAccess = $null; EeeuAccess = $null
        Owners = New-Object System.Collections.Generic.List[object]
        GuestIds = New-Object System.Collections.Generic.HashSet[string]
    }
    foreach ($p in @($Permissions)) {
        if ($null -eq $p) { continue }
        $roles = @(Get-GraphProp $p "roles")
        $link = Get-GraphProp $p "link"
        if ($null -ne $link) {
            $scope = "$(Get-GraphProp $link 'scope')"
            $access = if ("$(Get-GraphProp $link 'type')" -eq "edit") { "edit" } else { "view" }
            if ($scope -eq "anonymous") {
                $digest.AnyoneLinks++
                if ($access -eq "edit" -or $null -eq $digest.AnyoneAccess) { $digest.AnyoneAccess = $access }
            } elseif ($scope -eq "organization") {
                $digest.OrgLinks++
                if ($access -eq "edit" -or $null -eq $digest.OrgAccess) { $digest.OrgAccess = $access }
            }
            continue
        }
        $g2 = Get-GraphProp $p "grantedToV2"
        if ($null -eq $g2) { $g2 = Get-GraphProp $p "grantedTo" }
        if ($null -eq $g2) { continue }
        $puser = Get-GraphProp $g2 "user"
        if ($null -eq $puser) { continue }
        $dname = "$(Get-GraphProp $puser 'displayName')"
        $uid = "$(Get-GraphProp $puser 'id')"
        $access = if ($roles -contains "write") { "edit" } else { "read" }
        if ($dname -eq "Everyone except external users") {
            if ($access -eq "edit" -or $null -eq $digest.EeeuAccess) { $digest.EeeuAccess = $access }
        } elseif ($dname -eq "Everyone") {
            if ($access -eq "edit" -or $null -eq $digest.EveryoneAccess) { $digest.EveryoneAccess = $access }
        }
        if (($roles -contains "owner") -and $uid -ne "") {
            $digest.Owners.Add(@{ Id = $uid; DisplayName = $dname })
        }
        if ($uid -ne "" -and $guestIdSet.Contains($uid)) {
            [void]$digest.GuestIds.Add($uid)
        }
    }
    return $digest
}

function Merge-SharingDigest {
    param($Into, $From)
    $Into.AnyoneLinks += $From.AnyoneLinks
    if ($From.AnyoneAccess -eq "edit" -or $null -eq $Into.AnyoneAccess) { $Into.AnyoneAccess = $From.AnyoneAccess }
    $Into.OrgLinks += $From.OrgLinks
    if ($From.OrgAccess -eq "edit" -or $null -eq $Into.OrgAccess) { $Into.OrgAccess = $From.OrgAccess }
    if ($From.EveryoneAccess -eq "edit" -or $null -eq $Into.EveryoneAccess) { $Into.EveryoneAccess = $From.EveryoneAccess }
    if ($From.EeeuAccess -eq "edit" -or $null -eq $Into.EeeuAccess) { $Into.EeeuAccess = $From.EeeuAccess }
    foreach ($o in $From.Owners) { $Into.Owners.Add($o) }
    foreach ($g in $From.GuestIds) { [void]$Into.GuestIds.Add($g) }
    return $Into
}

function New-SharingItem {
    param([string]$Id, [string]$Kind, [string]$DisplayName, $WebUrl,
          $Digest, $OwnerName, $OwnerEnabled)
    return [ordered]@{
        id                                 = $Id
        kind                               = $Kind
        displayName                        = $DisplayName
        webUrl                             = $WebUrl
        ownerDisplayName                   = $OwnerName
        ownerAccountEnabled                = $OwnerEnabled
        anyoneLinks                        = $Digest.AnyoneLinks
        anyoneLinkAccess                   = $Digest.AnyoneAccess
        organizationLinks                  = $Digest.OrgLinks
        organizationLinkAccess             = $Digest.OrgAccess
        everyoneAccess                     = $Digest.EveryoneAccess
        everyoneExceptExternalUsersAccess  = $Digest.EeeuAccess
        guestCount                         = $Digest.GuestIds.Count
        # Graph does not expose whether guests may re-share; null
        # keeps that check silent instead of guessed.
        guestReshareAllowed                = $null
    }
}

$sharingOut = New-Object System.Collections.Generic.List[object]
$sitesReadable = $true
$graphSites = @()
try {
    $graphSites = @(Get-MgSite -All -ErrorAction Stop -Property @("Id","DisplayName","WebUrl"))
} catch {
    $sitesReadable = $false
    Write-Host "  Note: SharePoint sites could not be read"
    Write-Host "  ($($_.Exception.Message)). The sharing inventory will"
    Write-Host "  be empty and the Copilot audit will report itself"
    Write-Host "  as not covered rather than passed."
    $DefaultedAnswers.Add("sharingInventory (site permission lists could not be read; Copilot oversharing audit not covered)")
}
foreach ($site in $graphSites) {
    $digest = Read-SharingDigest @()
    try {
        $sitePerms = Get-GraphCollection "https://graph.microsoft.com/v1.0/sites/$($site.Id)/permissions"
        $digest = Merge-SharingDigest $digest (Read-SharingDigest @($sitePerms))
    } catch {}
    try {
        $drivePerms = Get-GraphCollection "https://graph.microsoft.com/v1.0/sites/$($site.Id)/drive/root/permissions"
        $digest = Merge-SharingDigest $digest (Read-SharingDigest @($drivePerms))
    } catch {}
    $ownerName = $null
    $ownerEnabled = $null
    if ($digest.Owners.Count -gt 0) {
        $ownerName = $digest.Owners[0].DisplayName
        if ($userEnabledById.ContainsKey($digest.Owners[0].Id)) {
            $ownerEnabled = $userEnabledById[$digest.Owners[0].Id]
        }
    } else {
        # Group-connected sites keep their owners on the group, not
        # in the site permission lists; the drive owner points at it.
        try {
            $drive = Invoke-MgGraphRequest -Method GET -ErrorAction Stop `
                -Uri "https://graph.microsoft.com/v1.0/sites/$($site.Id)/drive"
            $driveOwner = Get-GraphProp (Get-GraphProp $drive "owner") "user"
            $ownerGroup = Get-GraphProp (Get-GraphProp $drive "owner") "group"
            if ($null -ne $driveOwner) {
                $ownerName = "$(Get-GraphProp $driveOwner 'displayName')"
                $oid = "$(Get-GraphProp $driveOwner 'id')"
                if ($userEnabledById.ContainsKey($oid)) { $ownerEnabled = $userEnabledById[$oid] }
            } elseif ($null -ne $ownerGroup) {
                $gid = "$(Get-GraphProp $ownerGroup 'id')"
                $groupOwners = Get-GraphCollection "https://graph.microsoft.com/v1.0/groups/$gid/owners"
                if ($groupOwners.Count -gt 0) {
                    $ownerName = "$(Get-GraphProp $groupOwners[0] 'displayName')"
                    $oid = "$(Get-GraphProp $groupOwners[0] 'id')"
                    if ($userEnabledById.ContainsKey($oid)) { $ownerEnabled = $userEnabledById[$oid] }
                }
            }
        } catch {}
    }
    $sharingOut.Add((New-SharingItem -Id $site.Id -Kind "sharepoint-site" `
        -DisplayName "$($site.DisplayName)" -WebUrl $site.WebUrl `
        -Digest $digest -OwnerName $ownerName -OwnerEnabled $ownerEnabled))
}
# OneDrive drives whose owner account is disabled: the content and
# its sharing outlive the account, unreviewed.
foreach ($u in $graphUsers) {
    if ([bool]$u.AccountEnabled) { continue }
    if ("$($u.UserType)" -eq "Guest") { continue }
    try {
        $rootPerms = Get-GraphCollection "https://graph.microsoft.com/v1.0/users/$($u.Id)/drive/root/permissions"
        $digest = Read-SharingDigest @($rootPerms)
        $sharingOut.Add((New-SharingItem -Id "drive-$($u.Id)" -Kind "onedrive" `
            -DisplayName "OneDrive - $($u.DisplayName)" -WebUrl $null `
            -Digest $digest -OwnerName $u.DisplayName -OwnerEnabled $false))
    } catch {
        # No OneDrive on this account, or no access to it.
        continue
    }
}
if ($sitesReadable) {
    Write-Host "  Sharing inventory: $($sharingOut.Count) sites and drives read (permission lists only)."
}

# ----------------------------------------------------------- tenant settings -
$caPolicies = @()
$caReadable = $true
try {
    $caPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop `
        -Property @("Id","DisplayName","State","Conditions","GrantControls"))
} catch { $caReadable = $false }
$enabledCaCount = @($caPolicies | Where-Object { "$($_.State)" -eq "enabled" }).Count

$secDefaultsOn = $false
try {
    $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop `
        -Property @("IsEnabled")
    $secDefaultsOn = [bool]$sd.IsEnabled
} catch {}

# Legacy authentication is off tenant-wide when security defaults are
# on, or when an enabled Conditional Access policy blocks the legacy
# client app types. Anything unreadable errs toward "still enabled",
# which is the side that produces a finding to review.
$legacyEnabled = $true
if (-not $caReadable) {
    $DefaultedAnswers.Add("legacyAuthenticationEnabled (policies unreadable; assumed still enabled)")
}
if ($secDefaultsOn) {
    $legacyEnabled = $false
} else {
    foreach ($p in $caPolicies) {
        if ("$($p.State)" -ne "enabled") { continue }
        $cats = @()
        $blocks = $false
        if ($null -ne $p.Conditions) { $cats = @($p.Conditions.ClientAppTypes) }
        if ($null -ne $p.GrantControls) {
            $blocks = @($p.GrantControls.BuiltInControls) -contains "block"
        }
        if ($blocks -and ($cats -contains "exchangeActiveSync") -and ($cats -contains "other")) {
            $legacyEnabled = $false
        }
    }
}
Write-Host "  Conditional Access policies enabled: $enabledCaCount."

# ------------------------------------------------------- owner-stated facts -
Write-Host ""
Write-Host "Step 3 of 4 - a few questions only you can answer. These are"
Write-Host "about your devices and documents, which no tenant export can"
Write-Host "see. Press Enter for 'don't know': the scan will show a gap"
Write-Host "to review for that item instead of a pass, and this script"
Write-Host "lists every default at the end."
Write-Host ""

Write-Host "External file sharing (OneDrive / SharePoint). If you want to"
Write-Host "check first: SharePoint admin centre > Policies > Sharing."
Write-Host "  1 = Anyone with the link"
Write-Host "  2 = New and existing guests"
Write-Host "  3 = Existing guests only"
Write-Host "  4 = Only people in your organization"
$sharingChoice = (Read-Host "Sharing level (1-4, Enter = not sure)").Trim()
$sharingMap = @{
    "1" = "Anyone"
    "2" = "ExternalUserAndGuestSharing"
    "3" = "ExistingExternalUserSharingOnly"
    "4" = "Disabled"
}
if ($sharingMap.ContainsKey($sharingChoice)) {
    $sharingCapability = $sharingMap[$sharingChoice]
} else {
    $sharingCapability = "ExistingExternalUserSharingOnly"
    $DefaultedAnswers.Add("externalSharingCapability (recorded as 'existing guests only' - verify it in the SharePoint admin centre)")
    Write-Host "  Recorded as 'existing guests only'. Verify this one before"
    Write-Host "  trusting the sharing result in your report."
}

$edr = Ask-OptionalInt "Endpoint protection (EDR) coverage, percent of computers (0-100)"
if ($null -eq $edr) { $edr = 0; $DefaultedAnswers.Add("edrCoveragePercent (recorded as 0 = no coverage you could confirm)") }
$enc = Ask-OptionalInt "Computers with disk encryption on, percent (0-100)"
if ($null -eq $enc) { $enc = 0; $DefaultedAnswers.Add("deviceEncryptionPercent (recorded as 0 = no coverage you could confirm)") }

$backupOn = Ask-YesNo "Are backups of your Microsoft 365 data running"
if ($null -eq $backupOn) {
    $backupOn = $false
    $backupSuccessDays = $null
    $backupTestDays = $null
    $DefaultedAnswers.Add("backup state (recorded as not enabled = nothing you could confirm)")
} else {
    $backupSuccessDays = Ask-OptionalInt "Days since the last successful backup"
    $backupTestDays = Ask-OptionalInt "Days since a restore was last TESTED end to end"
    if ($backupOn -and $null -eq $backupTestDays) {
        # 9999 is this script's documented sentinel for "no test date
        # the owner could state" - the scan treats it as not recent.
        $backupTestDays = 9999
        $DefaultedAnswers.Add("backupLastTestRestoreDaysAgo (recorded as 9999 = no test date you could state)")
    }
    if ($backupOn -and $null -eq $backupSuccessDays) {
        $backupSuccessDays = 9999
        $DefaultedAnswers.Add("backupLastSuccessfulDaysAgo (recorded as 9999 = no date you could state)")
    }
}

$trainMonths = Ask-OptionalInt "Months since staff last did security awareness training"
if ($null -eq $trainMonths) { $trainMonths = 999; $DefaultedAnswers.Add("securityTrainingLastMonthsAgo (recorded as 999 = none you could date)") }
$trainPct = Ask-OptionalInt "Staff who completed that training, percent (0-100)"
if ($null -eq $trainPct) { $trainPct = 0; $DefaultedAnswers.Add("securityTrainingCompletionPercent (recorded as 0)") }

$irPlan = Ask-YesNo "Is there a written incident response plan"
if ($null -eq $irPlan) { $irPlan = $false; $DefaultedAnswers.Add("incidentResponsePlanDocumented (recorded as no document you could point to)") }
$secPolicy = Ask-YesNo "Is there a written information security policy staff can point to"
if ($null -eq $secPolicy) { $secPolicy = $false; $DefaultedAnswers.Add("writtenSecurityPolicyDocumented (recorded as no document you could point to)") }
$immutableBackup = Ask-YesNo "Is at least one backup copy kept offline or in immutable storage"
if ($null -eq $immutableBackup) { $immutableBackup = $false; $DefaultedAnswers.Add("backupOfflineOrImmutableCopy (recorded as not confirmed)") }
$pentestMonths = Ask-OptionalInt "Months since the last independent penetration test or vulnerability assessment (blank = none you can date)"
if ($null -eq $pentestMonths) { $DefaultedAnswers.Add("penetrationTestLastMonthsAgo (left unrecorded = no test date you could state; the scan reports evidence missing, not a pass)") }
$autoUpd = Ask-YesNo "Do computers apply updates automatically"
if ($null -eq $autoUpd) { $autoUpd = $false; $DefaultedAnswers.Add("automaticUpdatesEnabled (recorded as not confirmed)") }

# --------------------------------------------------------------- snapshot ---
$snapshot = [ordered]@{
    _meta = [ordered]@{
        fictional      = $false
        firm_name      = $firmName
        firm_size_seats = $enabledMembers.Count
        label          = "Exported from a live tenant by tenantcheck-export.ps1, run by the firm's own admin. Findings cover only what the export contains."
        snapshot_date  = (Get-Date -Format "yyyy-MM-dd")
        source_shape   = "Built by tools/tenantcheck-export.ps1 from Microsoft Graph (users, authentication method registrations, directory role assignments, inbox rules, OAuth2 permission grants, service principals, Conditional Access policies, organization, site and library permission lists) plus owner-stated answers entered during the script run."
    }
    users = @($usersOut)
    exportCoverage = [ordered]@{
        mailboxesChecked = $mailboxesChecked
        mailboxesSkipped = $mailboxesSkipped
    }
    inboxRules = @($rulesOut)
    oauthGrants = @($grantsOut)
    sharingInventory = @($sharingOut)
    tenantSettings = [ordered]@{
        externalSharingCapability = $sharingCapability
        legacyAuthProtocols       = @("POP3", "IMAP4", "Authenticated SMTP")
        legacyAuthenticationEnabled = $legacyEnabled
        # Microsoft Entra platform values for cloud accounts; Graph
        # does not expose tenant-configurable values for these.
        passwordPolicy = [ordered]@{
            complexityRequired = $true
            lockoutThreshold   = 10
            minimumLength      = 8
        }
    }
    securityControls = [ordered]@{
        automaticUpdatesEnabled          = [bool]$autoUpd
        backupEnabled                    = [bool]$backupOn
        backupLastSuccessfulDaysAgo      = $backupSuccessDays
        backupLastTestRestoreDaysAgo     = $backupTestDays
        backupOfflineOrImmutableCopy     = [bool]$immutableBackup
        conditionalAccessPolicyCount     = $enabledCaCount
        deviceEncryptionPercent          = $enc
        edrCoveragePercent               = $edr
        incidentResponsePlanDocumented   = [bool]$irPlan
        penetrationTestLastMonthsAgo     = $pentestMonths
        writtenSecurityPolicyDocumented  = [bool]$secPolicy
        securityTrainingCompletionPercent = $trainPct
        securityTrainingLastMonthsAgo    = $trainMonths
    }
}

Write-Host ""
Write-Host "Step 4 of 4 - writing $OutFile ..."
$json = $snapshot | ConvertTo-Json -Depth 12
$outPath = $OutFile
if (-not [System.IO.Path]::IsPathRooted($outPath)) {
    $outPath = Join-Path (Get-Location) $OutFile
}
# UTF-8 without BOM, so the file uploads exactly as written.
[System.IO.File]::WriteAllText($outPath, $json, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "Done. Snapshot written to: $outPath"
Write-Host "  $($usersOut.Count) users, $($rulesOut.Count) inbox rules, $($grantsOut.Count) app grants, $($sharingOut.Count) sharing inventory items."
Write-Host "  Mailboxes checked for inbox rules: $mailboxesChecked; skipped (could not be read): $mailboxesSkipped."
if ($DefaultedAnswers.Count -gt 0) {
    Write-Host ""
    Write-Host "Answers recorded as 'no evidence' because they were not"
    Write-Host "stated (the report shows a gap to review for each, not a pass):"
    foreach ($d in $DefaultedAnswers) { Write-Host "  - $d" }
}
Write-Host ""
Write-Host "Next step: upload the file on the TenantCheck 365 scan page."
Write-Host "Nothing was sent anywhere by this script."

Disconnect-MgGraph | Out-Null
