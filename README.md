# BallmerBuster

Automated **Azure / Entra ID whitebox pentest** workflow. It runs a battery of
read-only checks against the subscriptions you can reach, stores everything in a
self-contained **engagement directory**, and serves a local web **report** with
a **Utils** tab for follow-on tooling (currently a browser-driven
[TREVORspray](https://github.com/blacklanternsecurity/TREVORspray) O365/Entra
password-spraying panel).

> Authorized testing only. BallmerBuster reads cloud resources with your
> credentials, and the Utils tab can send live authentication attempts at a
> tenant. Only point it at environments you have written permission to test.

---

## Quick start

```bash
# build
go build -o ballmerbuster ./cmd/ballmerbuster

# authenticate to Azure (either works)
az login
# ...or a service principal:
export AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=...

# run a scan (creates ./engagements/<timestamp>/)
./ballmerbuster scan --all-subs

# open the report and browse findings + the Utils tab
./ballmerbuster report ./engagements/<timestamp>
# → report listening on http://127.0.0.1:7979
```

### Commands

| Command | Purpose |
|---|---|
| `ballmerbuster scan [flags]` | Run the checks against one/many subscriptions into an engagement dir. |
| `ballmerbuster report <dir> [--addr host:port]` | Serve the local web report (Report + Utils tabs). Default `127.0.0.1:7979`. |
| `ballmerbuster resume <dir>` | Resume an interrupted scan. |
| `ballmerbuster modules` | List registered modules with kind, section, and severity rating. |

Useful `scan` flags: `--subscription`, `--subscriptions a,b`, `--all-subs`,
`--management-group`, `--out`, `--engagement <dir>` (append), `--modules a,b`,
`--no-<module>`, `--no-tui`. See `ballmerbuster scan --help` for the full list.

---

## The report web UI

`ballmerbuster report <dir>` serves two top-level tabs:

- **Report** — all findings, filterable by section / module / check, with
  severity counts, false-positive marking, and raw-output links.
- **Utils** — operator tooling that runs from the report server. Today that is
  the **TREVORspray** panel described below.

> **No collected data yet?** The report still works. If the engagement dir has
> no `engagement.db` (or doesn't exist), the server creates an empty one on
> startup — the Report tab is simply empty, and the **Utils → TREVORspray** tab
> works fully standalone. So you can use it purely as a spraying console:
>
> ```bash
> ./ballmerbuster report ./my-op      # fresh/empty dir is fine
> ```

---

## Utils → TREVORspray (O365 / Entra password spraying)

A browser-driven front end for TREVORspray. It installs the tool into a
self-contained venv under the engagement, builds a target userlist (optionally
from DeHashed), and runs **recon / spray / single test-user** attempts against
Microsoft 365 / Entra — streaming live, colorized output into an in-browser
terminal. Everything (venv, tool state, userlists, per-run logs) is scoped to
`<engagement>/trevorspray/`.

**Lockout guardrail:** a spray is capped to a configurable number of passwords
per user (**default 2**). Since TREVORspray tries one password per user per
pass, that ceiling *is* the per-user attempt limit — extra passwords are dropped
before the run with a warning.

### Prerequisites

- `python3` (3.9+) on `PATH` — the panel builds its own venv; nothing else is
  needed globally.
- Egress to `github.com` (install), `api.dehashed.com` (userlist), and
  `login.microsoftonline.com` (spraying).
- Keep the report bound to localhost (the default) unless you intend others to
  reach the spraying console.

### 1 · Install

Click **Install / update TREVORspray**. It creates a venv at
`<engagement>/trevorspray/venv` and `pip install`s `trevorproxy` + `TREVORspray`
from git, streaming pip output into the terminal and flipping the status pill to
**✓ installed**. Safe to re-run to upgrade. Log: `/raw/trevorspray/install.log`.
The **Run** button stays disabled until this succeeds.

### 2 · Build a userlist from DeHashed *(optional)*

| Field | Meaning |
|---|---|
| **API endpoint** | Blank → v2 default `https://api.dehashed.com/v2/search`. Override for another API/version. |
| **API key** | Your DeHashed key (**show** toggle reveals it). |
| **Email** | Blank → **v2** (`Dehashed-Api-Key` header). Set it → **v1** (GET + HTTP basic auth `email:key`). |
| **Domain(s) / tenant** | e.g. `contoso.com` → queries `domain:contoso.com`. Paste a **line-separated list** to sweep several tenants in one shot. |
| **Max results** | Records to fetch **per domain** (default 100). The server **paginates** the DeHashed API to gather up to this many; DeHashed serves at most 10,000 per query. If a tenant has more matches than you fetched, the result banner warns how many more are available so you can raise this. |

**Fetch from DeHashed** dedupes emails (preferred as O365 UPNs) and usernames,
saves them to `<engagement>/trevorspray/userlists/<domain>-dehashed.txt`, and
loads them into the **Users** box. With several domains you also get a
`combined-dehashed.txt` (all tenants merged) plus a per-domain breakdown chip
row. Previously-saved lists appear as **Saved userlists** chips — click one to
reload it. You can also skip this and paste emails directly.

**Exportable credential table.** The full DeHashed records are rendered as a
sortable-width table below the button — `domain, email, username, password,
hashed_password, name, database_name, ip_address, phone` (empty columns are
hidden) — so you can eyeball the creds and reuse them elsewhere. The rows are
written to `<engagement>/trevorspray/userlists/<name>-dehashed.csv` (linked as
**Saved CSV**), and **Export CSV** downloads exactly what's shown straight from
the browser. Handy for credential-stuffing the same passwords against other
services on the engagement.

### 3 · Recon / Spray / Test

Pick a **mode**:

- **Recon** — `trevorspray --recon <domain>`: tenant ID/name, other tenant
  domains, auth URLs, autodiscover, federation config, MX. Paste **one domain
  per line** to recon several tenants in sequence (each is a separate labelled
  run in the same terminal). With the Users box populated it also validates
  which accounts exist (set **User-enum** to `onedrive` / `seamless_sso` /
  `teams_photo`). No passwords sent. **Start here** to confirm the tenant and
  prune your userlist to real accounts.
- **Password spray** — `-u users -p passwords` across all users, capped to
  max-attempts passwords.
- **Test single user** — uses only the first user and forces exit-on-first-
  success; for validating one credential / checking MFA on one account.
- **Combo (user:pass)** — paste your own `user:password` pairs (one per line);
  each is tried as an exact pair via TREVORspray's `-up`, with **no**
  user×password cross-product. Pairs are still capped to **max-attempts per
  username** (extras dropped with a warning) to protect against lockouts. Use
  this when you already have specific credentials to validate (e.g. reused
  passwords from the DeHashed table) rather than spraying a shared password.

Key fields:

| Field | Notes |
|---|---|
| **Module** | Auth endpoint. `msol` (default) = O365/Azure AD and reports MFA. Also `owa, adfs, okta, auth0, anyconnect, jumpcloud, officehome`. |
| **Tenant / domain** | Required for recon; shown in the spray confirmation. |
| **URL override** | Optional explicit endpoint, e.g. `https://login.microsoftonline.com/<tenant>/oauth2/token`. |
| **Users / Passwords** | One per line. Live counters show `N users` and `M passwords → K/user`. |
| **Max attempts/user** | Lockout guardrail (default 2). Extra passwords dropped with a warning. |
| **Delay / Lockout delay / Jitter** | Seconds between requests / extra sleep on a lockout / random added delay. Raise to spray slowly. |
| **Threads** | Concurrency (default 1). Higher = faster = more lockout risk. |
| **Exit on first success** | Off by default so a spray collects *all* valid creds. |
| **Ignore lockouts** | Don't auto-halt when lockouts are detected (use with care). |
| **Force** | Retry user/password pairs already attempted in this engagement's state. |
| **Verbose** | Debug-level output. |

**Run** streams live colorized output. Spray/test first show a confirmation with
the attempt math (`3 users × 2 passwords = 6 attempts against contoso.com`) and
an authorization reminder. **Stop** aborts the whole process group. On
completion the terminal bar links the **output dir**, **run log**, and **tool
log**.

**Reading msol results:** each account is flagged valid / invalid / locked /
**MFA**. A valid credential that reports MFA is still a win — the *MFA-bypass
lever* is the **Module** selector, since different modules hit different auth
endpoints and some legacy paths don't enforce MFA. Try the same credential
across modules to find one that authenticates without MFA.

### Where things land

Under `<engagement>/trevorspray/` (browse via `/raw/trevorspray/…`):

```
venv/                          # the isolated install
install.log                    # pip output
home/.trevorspray/             # per-engagement TREVORspray state + cumulative trevorspray.log
userlists/<domain>-dehashed.txt    # per-domain userlist
userlists/combined-dehashed.txt    # all domains merged (multi-domain fetch)
userlists/<name>-dehashed.csv      # full exportable credential table
runs/<mode>-<timestamp>/
    users.txt  passwords.txt  trevorspray.log
```

TREVORspray's `~/.trevorspray` state is isolated per engagement via `HOME`, so
runs never collide with your real home dir, and the cumulative *tool log* is
more verbose (DEBUG) than the console.

### Recommended flow & safety

1. **Recon** the tenant → confirm it's cloud/federated, grab auth URLs.
2. **Recon + Users** (with a user-enum method) → keep only accounts that exist.
3. **Test** one account with one password → sanity-check the module/endpoint.
4. **Spray** with **max attempts 1–2**, a **delay** (and/or low **threads**),
   spread over time to stay under lockout thresholds. Watch for lockout
   warnings.

Two operational caveats: closing the browser tab **kills a running spray** (runs
are request-scoped), and this is an **active attack tool** — only use it against
tenants you're authorized to test. Non-secret run settings are remembered in the
browser's `localStorage`; the DeHashed API key, email, and the user/password
lists are never stored.
