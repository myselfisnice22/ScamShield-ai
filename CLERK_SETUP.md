# Clerk sign-in for ScamShield AI

Sign-in is **off until you add Clerk keys**. Without keys, the website, API and phone
app work exactly as before.

> **Before you start:** a parent or guardian should create the Clerk account and own the
> keys. Signing users in means ScamShield now handles names and email addresses, so the
> privacy policy (`mobile/PRIVACY.md`) must say so.

This setup follows Clerk's official guides:
- Phone app: the [JavaScript quickstart](https://clerk.com/docs/js-frontend/getting-started/quickstart) "script tag" option.
  It loads `@clerk/ui@1` (the sign-in box), then `@clerk/clerk-js@6`, and calls
  `Clerk.load({ ui: { ClerkUI: window.__internal_ClerkUICtor } })`.
- Backend API: [manual JWT verification](https://clerk.com/docs/guides/sessions/manual-jwt-verification).
  It checks the RS256 signature with your JWKS, `exp`/`nbf`, `azp` against your allowed apps,
  and rejects `sts: "pending"` sessions.
- Clerk's setup tool (`npx clerk@latest init`) does not support Python/Streamlit or a
  plain-JavaScript Capacitor app, and Clerk says not to run `init` in a project that
  already uses Clerk. So the pieces were added by hand instead.

## The three parts

| Part | How sign-in works | Where the settings go |
|---|---|---|
| **Streamlit website** | Streamlit's built-in `st.login`, with Clerk as the login provider (OpenID Connect) | `.streamlit/secrets.toml`, or Streamlit Cloud → app **Settings → Secrets** |
| **Backend API** | Python checks the Clerk session token on every scan (`backend/clerk_auth.py`) | Environment variables on the server |
| **Phone app** | Clerk's own sign-in box; every scan sends the user's token to the API | `mobile/www/config.js` → `clerkPublishableKey` |

## 1. Create the Clerk application

1. Sign up at **clerk.com** (parent's account) and create an application, e.g. "ScamShield AI".
2. Choose sign-in methods, e.g. email and Google.
3. Under **API Keys**, note the **Publishable key** (`pk_test_...`). The **Secret key**
   (`sk_test_...`) must **never** go in the app or on GitHub.
4. Note your **Frontend API URL**, e.g. `https://your-app.clerk.accounts.dev`.

## 2. Streamlit website

1. Clerk dashboard → **OAuth applications** → **Add**.
   - Redirect URI (testing on your laptop): `http://localhost:8501/oauth2callback`
   - Redirect URI (Streamlit Cloud): `https://YOUR-APP.streamlit.app/oauth2callback`
   - Scopes: `openid profile email`
2. Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and fill in the
   Client ID, Client Secret and Discovery URL. That file is in `.gitignore`, so it is never uploaded.
3. Make the cookie secret with:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
4. Install the requirements and run the website:
   ```bash
   python -m pip install -r requirements.txt
   ```
   ```bash
   python -m streamlit run mobile_app.py
   ```
5. **Streamlit Cloud:** paste the same text into the app's **Settings → Secrets**, with the
   cloud redirect URI.

## 3. Backend API

Set these environment variables where the API runs. On your laptop (PowerShell):

```bash
$env:CLERK_ISSUER="https://your-app.clerk.accounts.dev"
```
```bash
python -m uvicorn backend.api:app --port 8000
```

| Variable | Meaning |
|---|---|
| `CLERK_ISSUER` | Your Frontend API URL. **Setting it turns sign-in checking on.** |
| `CLERK_JWKS_URL` | Optional. Default: `CLERK_ISSUER/.well-known/jwks.json` |
| `CLERK_AUTHORIZED_PARTIES` | Optional. Apps allowed to call the API. Default: `https://localhost,capacitor://localhost` |

`http://localhost:8000/health` then shows `"sign_in_required": true`.

## 4. Phone app

1. Put the **publishable** key in `mobile/www/config.js`: `clerkPublishableKey: "pk_test_..."`.
2. Clerk dashboard → **Domains / Allowed origins**: add `https://localhost` (Android) and
   `capacitor://localhost` (iPhone).
3. Run `npm.cmd run sync` in `mobile/`, then run the app from Android Studio.

**Known limitation:** this uses Clerk's web sign-in inside the app. It's designed for
**development (`pk_test_`) instances**. Before publishing with a production (`pk_live_`)
instance, check Clerk's current documentation for apps running in a native WebView
(Capacitor). Production instances are tied to your own domain, and you'll need to add
that domain to the Content-Security-Policy in `mobile/www/index.html`.

## Testing

```bash
python -m unittest backend.test_clerk_auth -v
```
```bash
python -m unittest test_streamlit_auth -v
```

These tests use their own fake keys and need no Clerk account.

## Sign-in on Streamlit Community Cloud (e.g. junosai.streamlit.app)

`secrets.toml` is never uploaded to GitHub, so the hosted app needs its own copy:

1. Clerk → **OAuth applications** → your app → **Redirect URIs**: add
   `https://YOUR-APP.streamlit.app/oauth2callback` (keep the localhost one).
2. share.streamlit.io → your app → **⋮ → Settings → Secrets**: paste your
   `secrets.toml`, but with
   `redirect_uri = "https://YOUR-APP.streamlit.app/oauth2callback"`. Save.
3. `requirements.txt` must list **Authlib** and **httpx**. Without httpx the
   SIGN IN button gives "Internal server error" on the hosted app.

Without step 2 the hosted app opens with no sign-in at all.

## Settings tab: sign out and delete account

Signed-in users get a **⚙️ Settings** tab with **Sign out** and **Delete account**.

Deleting an account removes the user from Clerk (Clerk's Backend API) and
clears their scan history in the session. It needs Clerk's **Secret key**,
which is different from the OAuth Client Secret:

1. Clerk dashboard → **Configure → API keys** → copy the **Secret key** (`sk_test_…` / `sk_live_…`).
2. Add to `.streamlit/secrets.toml`:

   ```toml
   [clerk_admin]
   secret_key = "sk_test_..."
   ```

3. Restart ScamShield. `python check_clerk_setup.py` (step 5b) confirms Clerk accepts it.

Without it, the Settings tab still has Sign out and explains how to switch
deletion on. The Secret key has full control of your Clerk app: never commit
it or share it.

## Troubleshooting: "I sign in on Clerk but come back logged out"

Sign-in happens in three steps, and Streamlit silently discards the result if
step 2 or 3 fails:

1. ScamShield → Clerk (you see Clerk's page)
2. Clerk → `/oauth2callback`: Streamlit matches the result to a "sign-in in
   progress" cookie
3. Streamlit checks Clerk's ID token, then saves a signed cookie for 30 days

| Cause | What ScamShield now does |
|---|---|
| `client_kwargs` has no `prompt`. Streamlit 1.66+ then asks Clerk for `prompt=select_account`, which Clerk rejects **after** you type your password (terminal: `Used unknown value '[select_account]' for prompt parameter`). | Blocks sign-in and shows the fix: `client_kwargs = { scope = "openid profile email", prompt = "" }`. `check_clerk_setup.py` checks it too. |
| Opened at `127.0.0.1:8501` or the "Network URL" instead of `localhost:8501`. Browsers keep cookies separately per address, so step 2 can't find the cookie. **The most common cause.** | Shows a warning and a button to the right address instead of a sign-in that would fail |
| Sign-in interrupted (Back button, created an account in the middle) | Shows "The sign-in was interrupted…". Sign in again. |
| Computer clock wrong, so Clerk's token looks expired | Shows the reason and how to sync the Windows clock |
| Clerk OAuth app missing the `openid` scope | Shows which scopes to add |
| Wrong Client ID/Secret, or the network is blocked | Shows the reason and suggests running `python check_clerk_setup.py` |

Detailed reasons are shown only when running on your own computer. Hosted apps
show a general message.

**Session length:** Clerk's free plan ends sessions after 7 days, but
Streamlit's cookie lasts 30. ScamShield asks you to sign in again after 7 days.

**Tests:**

```bash
python -m unittest test_streamlit_auth test_clerk_login_flow -v
```

`test_clerk_login_flow` starts the real app and a fake Clerk (`clerk_mock_server.py`)
and checks login, refresh, logout, expired tokens, replayed callbacks and the
127.0.0.1 problem. It uses a temporary secrets file, never your real one.
