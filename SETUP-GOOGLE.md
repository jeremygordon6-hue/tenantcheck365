# TenantCheck 365 — Live Google Workspace Connection: Owner Setup

The code side is built and tested (`google_connect.py`, the
`/google/connect` page, `/google/live-connection`, and live scans
through the existing Google engine). Nothing here requires a
developer. The steps below are the ones **only you, the product
owner, can do**, because they happen inside your own Google Cloud
and Render accounts. Total time: roughly **30 minutes**, one
sitting.

Google's model is different from Microsoft's, so read this first:
there is no consent screen. You create a **service account** in
your own Google Cloud project. That service account has access to
*nothing* until a **customer's own Workspace super admin**
authorizes its client ID in *their* Admin console (domain-wide
delegation, Step 6). TenantCheck can never authorize itself into
anyone's domain.

> **The one rule that matters:** the service account key (Step 4)
> is a password for every customer domain that ever authorizes
> this service account. It goes from Google's screen **directly
> into Render's environment variables, by your hand**. Never send
> it by chat, email, text, or a screenshot — not to Muse, not to
> anyone. Do not park the downloaded key file in Drive, in a repo,
> or on a shared computer; after Step 5, delete the local copy or
> keep it only in your password manager. If a key ever travels by
> an insecure channel, delete that key on the service account and
> create a new one; that takes two minutes. The service account
> email and its client ID are not secret — those you can share
> freely, and customers need the client ID to authorize you.

---

## Step 1 — Create the Google Cloud project — ~5 minutes

1. Go to <https://console.cloud.google.com> and sign in with the
   Google account that will own TenantCheck 365 (the same account
   family that owns the Render service is a good choice).
2. Create a project (name it something plain, e.g.
   `tenantcheck-365`). An app project itself costs nothing and
   needs no billing account for this use.
3. Open **APIs & Services → Library**, search for **Admin SDK
   API**, and **Enable** it. That one API (`admin.googleapis.com`)
   serves every Directory read the scan uses.

## Step 2 — Create the service account — ~5 minutes

1. Open **IAM & Admin → Service accounts → Create service
   account**. Name: `tenantcheck-reader`. No Google Cloud roles
   are needed — domain-wide delegation is granted by each
   customer's Workspace admin, not by Cloud IAM, so grant it
   nothing here.
2. On the service account's **Details** page, copy two values for
   Step 5:
   - its **email** (looks like
     `tenantcheck-reader@your-project.iam.gserviceaccount.com`), and
   - its **Unique ID** — a long number. This is the **client ID**
     each customer pastes into their Admin console to authorize
     you. It is not a secret.

## Step 3 — The scopes customers will authorize — know them cold

There is nothing to click in this step; this is the list, so you
can answer for it. When a customer authorizes the client ID, they
paste exactly these scopes (the connect page shows them the same
list):

- `https://www.googleapis.com/auth/admin.directory.user.readonly`
  — read user accounts (2-Step Verification state, suspended,
  super-admin flag, last login).
- `https://www.googleapis.com/auth/admin.directory.group.readonly`
  — read groups.
- `https://www.googleapis.com/auth/admin.directory.group.member.readonly`
  — read group membership (to count external members).
- `https://www.googleapis.com/auth/admin.directory.customer.readonly`
  — read whose domain this is.
- `https://www.googleapis.com/auth/admin.directory.user.security`
  — read the third-party apps each user has authorized
  (the tokens list). **One honest wrinkle to be able to explain:**
  Google offers no read-only version of this scope — it can
  technically also revoke a user's tokens and sign them out.
  TenantCheck only ever calls the read (`tokens.list`). It is in
  the list because there is no narrower way to inventory
  third-party apps, and the connect page tells customers exactly
  that before they authorize.

Deliberately **not** requested:
`admin.reports.audit.readonly` — the Directory user list already
returns last-login times, so an audit scope would widen access
for nothing.

## Step 4 — Create the key — ~3 minutes

1. Still on the service account: **Keys → Add key → Create new
   key → JSON → Create**. A `.json` file downloads **once**. It
   contains the private key. Treat the whole file as the secret.
2. You do not upload this file anywhere in TenantCheck. In Step
   5 you paste **either** the file's entire contents **or** just
   its `private_key` value into one Render variable — the app
   reads both shapes.
3. Then delete the downloaded file from the computer (or move it
   into your password manager as a secure note). If you lose the
   key later, nothing breaks permanently: delete the key on the
   service account and create a new one (~5 minutes, Steps 4–5).

> **Activation note — the RSA signer.** The app signs its token
> requests with RS256. The Python standard library cannot do RSA
> signing, so the live token exchange needs the `cryptography`
> package importable by the service. On Render that means the
> service's **Build Command** must install it (e.g.
> `pip install cryptography`) instead of the current no-op build.
> Until that is set, `/google/live-connection` can show "setup is
> complete" (the variables are present) but a registration
> validation will plainly report that signing is unavailable and
> record nothing — it will never fake a connection.

## Step 5 — Set the environment variables on Render — ~5 minutes

1. Open <https://dashboard.render.com>, select the **tenantcheck365**
   web service → **Environment**.
2. Add these three variables:

   | Name | Value |
   |---|---|
   | `TENANTCHECK_GOOGLE_SA_EMAIL` | the service account email from Step 2 |
   | `TENANTCHECK_GOOGLE_SA_CLIENT_ID` | the numeric Unique ID from Step 2 |
   | `TENANTCHECK_GOOGLE_SA_KEY` | the key from Step 4 (whole JSON, or just the `private_key` value) |

3. **Save Changes.** Render redeploys the service automatically
   (~2 minutes).

## Step 6 — Verify — ~2 minutes

1. Visit <https://tenantcheck365.ca/google/live-connection>. The
   status block should switch from "setup is pending" to "setup
   is complete".
2. Visit <https://tenantcheck365.ca/google/connect>. You should
   see the client ID and the scope list a customer admin needs,
   and the registration form.
3. First real test: a friendly firm's Workspace super admin (or
   your own test domain's admin) does the customer steps below;
   their domain then validates and appears under "Connected
   Google domains", and its live scan runs from the same page.

---

## What customers do to connect (their side, ~5 minutes)

1. In their **Admin console**: **Security → Access and data
   control → API controls → Domain-wide delegation → Add new**.
2. Paste **our client ID** (shown on `/google/connect`) and the
   **exact scope list** from Step 3, then **Authorize**.
3. On `/google/connect`, register their **domain** and the
   **admin email** TenantCheck should impersonate for reads (a
   real admin in their domain; a dedicated admin account used
   only for reporting is a good choice). TenantCheck immediately
   makes one read-only call to prove the delegation works; only
   a domain that answers is recorded — a failed validation
   records nothing.
4. **Revoking is theirs alone:** deleting that one delegation
   entry in their Admin console ends all access immediately,
   without asking us. Nothing in TenantCheck can restore it.

## What customers experience after this

TenantCheck reads the domain with an app-only token obtained by
impersonating the admin email they named — no user passwords
exist anywhere in this design — and runs the identical Google
checks as the export path.

Honest limitations to know about, all stated on the site too:

- A few scan inputs are facts only the firm itself can state
  (backup restore tests, EDR and encryption coverage, training,
  a written incident plan, and the domain's Drive sharing level,
  less-secure-app setting and password policy — Admin console
  settings the Directory API does not expose). They are recorded
  on the connection as owner-stated facts; whatever is not
  stated is reported as not covered or evidence missing, never
  guessed.
- Per-user mail forwarding is **not** read on the live path (it
  lives in the Gmail API, which is deliberately outside the
  authorized scopes), and whether a group *allows* external
  members is a Groups Settings value the Directory API does not
  expose (membership itself is read). Two insurance answers can
  therefore differ between a live scan and an export scan; the
  scan says so.
