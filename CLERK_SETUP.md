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
