# TenantCheck 365 — Live Microsoft Graph Connection: Owner Setup

The code side is built and tested (`graph_connect.py`, the `/connect`
page, `/connect/callback`, and live scans through the existing
engine). Nothing here requires a developer. The steps below are the
ones **only you, the product owner, can do**, because they happen
inside your own Microsoft and Render accounts. Total time: roughly
**30 minutes**, one sitting.

> **The one rule that matters:** the client secret (Step 4) is a
> password for the whole product. It goes from Microsoft's screen
> **directly into Render's environment variables, by your hand**.
> Never send it by chat, email, text, or a screenshot — not to Muse,
> not to anyone. If a secret ever travels by an insecure channel,
> delete it in Entra ID and create a new one; that takes two minutes.
> The client ID and the redirect URI are not secret — those you can
> share freely.

---

## Step 1 — Sign in to the Azure portal — ~5 minutes

1. Go to <https://portal.azure.com> and sign in with the Microsoft
   account that will own TenantCheck 365 (the same account that owns
   the Render service and the Stripe account is a good choice).
2. If the account has no Microsoft Entra tenant yet, Azure will offer
   to create one ("Microsoft Entra ID" → create a free tenant).
   An app registration itself costs nothing and needs no paid Azure
   subscription.

## Step 2 — Register the app — ~5 minutes

1. In the portal, open **Microsoft Entra ID → App registrations →
   New registration**.
2. Name: `TenantCheck 365`.
3. Supported account types: **"Accounts in any organizational
   directory (Any Microsoft Entra ID tenant — Multitenant)"**.
   This matters: it is what lets a *customer's* admin consent to the
   app in *their* tenant. "Single tenant" would lock it to your own
   firm only.
4. Redirect URI: platform **Web**, value exactly:

   `https://tenantcheck365.ca/connect/callback`

   (Character-for-character. A trailing slash or a different domain
   makes Microsoft refuse the consent redirect.)
5. Click **Register**. On the Overview page, copy the
   **Application (client) ID** — you will need it in Step 5. It is
   not a secret.

## Step 3 — Add the API permissions — ~10 minutes

Still in the app registration:

1. Open **API permissions → Add a permission → Microsoft Graph →
   Application permissions**.
2. Add each of these (all read-only; the app can never change
   anything in a customer tenant):
   - `User.Read.All`
   - `Directory.Read.All`
   - `Reports.Read.All`
   - `RoleManagement.Read.Directory`
   - `AuditLog.Read.All`
   - `Policy.Read.All`
   - `Mail.Read` — required by Microsoft for the inbox *message
     rules* endpoint. TenantCheck calls that endpoint for rule
     settings (forwarding targets) and never reads message contents;
     the permission is broader than the use, which is Microsoft's
     design, and the consent screen shows it plainly to the
     customer's admin.
   - `Sites.Read.All` — for the SharePoint sharing-settings read.
3. Click **"Grant admin consent for <your tenant>"** and confirm.
   This consents only for *your own* tenant (so you can test); every
   customer still consents separately, in their own tenant, with
   their own admin. Nothing here grants access to any customer.

## Step 4 — Create the client secret — ~3 minutes

1. Open **Certificates & secrets → Client secrets → New client
   secret**.
2. Description: `tenantcheck-render`. Expiry: **24 months** (the
   longest offered). Put a calendar reminder 30 days before it
   expires — when it lapses, live scans stop until a new secret is
   set (Steps 4–5 repeated, ~8 minutes).
3. Click **Add**, then **immediately copy the secret's `Value`**
   (not the "Secret ID"). The value is shown once and never again.
   Paste it straight into Render in Step 5 — do not park it in a
   note, a file, or a message.

## Step 5 — Set the environment variables on Render — ~5 minutes

1. Open <https://dashboard.render.com>, select the **tenantcheck365**
   web service → **Environment**.
2. Add these three variables:

   | Name | Value |
   |---|---|
   | `TENANTCHECK_MS_CLIENT_ID` | the Application (client) ID from Step 2 |
   | `TENANTCHECK_MS_REDIRECT_URI` | `https://tenantcheck365.ca/connect/callback` |
   | `TENANTCHECK_MS_CLIENT_SECRET` | the secret **Value** from Step 4 |

3. **Save Changes.** Render redeploys the service automatically
   (~2 minutes).

## Step 6 — Verify — ~2 minutes

1. Visit <https://tenantcheck365.ca/live-connection>. The status
   block should switch from "setup is pending" to "setup is
   complete".
2. Visit <https://tenantcheck365.ca/connect>. You should see the
   "Connect a tenant with Microsoft admin consent" button.
3. First real test: have a friendly firm's Global Administrator (or
   your own test tenant's admin) click it, sign in, and consent.
   The tenant then appears under "Connected tenants", and its live
   scan can be run from the same page.

---

## What customers experience after this

Their admin consents once, on Microsoft's own screen, seeing the
exact permission list. TenantCheck then reads the tenant with an
app-only token (no user passwords exist anywhere in this design),
runs the identical checks as the export path, and the admin can
revoke consent in Entra ID → Enterprise applications at any time,
which ends all access immediately.

One honest limitation to know about: a few InsureReady inputs are
facts only the firm itself can state (backup restore tests, EDR and
encryption coverage, training, a written incident plan, password
policy). Graph cannot supply them, so before a live scan runs, those
values must be recorded on the tenant's connection record — the scan
refuses to run on guesses and names what is missing instead.
