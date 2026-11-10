"""ScamShield AI - Clerk sign-in checker.

Finds out WHY Streamlit sign-in with Clerk isn't working, step by step,
the same way Streamlit does it, and prints the fix.

Run from the ScamShield folder:
    python check_clerk_setup.py

It reads .streamlit/secrets.toml but NEVER prints your secrets.
"""

import base64
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

SECRETS = Path(__file__).resolve().parent / ".streamlit" / "secrets.toml"
EXPECTED_REDIRECT = "http://localhost:8501/oauth2callback"

problems = 0


def ok(text):
    print(f"  [OK]   {text}")


def bad(text, fix):
    global problems
    problems += 1
    print(f"  [FAIL] {text}")
    print(f"         FIX: {fix}")


def step(title):
    print(f"\n{title}")


def main():
    print("SCAMSHIELD - CLERK SIGN-IN CHECK (your secrets are never printed)")

    # ------------------------------------------------------------------
    step("1. secrets.toml")
    try:
        import tomllib
    except ModuleNotFoundError:
        print("  Python 3.11 or newer is needed for this checker.")
        return 1
    if not SECRETS.is_file():
        bad(f"{SECRETS} was not found.",
            "Copy .streamlit/secrets.toml.example to .streamlit/secrets.toml and fill it in.")
        return 1
    try:
        config = tomllib.loads(SECRETS.read_text(encoding="utf-8"))
    except Exception as error:
        bad(f"secrets.toml has a typing mistake: {error}",
            "Check every value is inside \"quotes\" and the headings are [auth] and [auth.clerk].")
        return 1
    auth = config.get("auth", {})
    clerk = auth.get("clerk", {})
    if not clerk:
        bad("No [auth.clerk] section.", "Add the [auth.clerk] heading exactly like the example file.")
        return 1

    values = {
        "redirect_uri": auth.get("redirect_uri", ""),
        "cookie_secret": auth.get("cookie_secret", ""),
        "client_id": clerk.get("client_id", ""),
        "client_secret": clerk.get("client_secret", ""),
        "server_metadata_url": clerk.get("server_metadata_url", ""),
    }
    for name, value in values.items():
        if not value:
            bad(f"{name} is empty or missing.", f"Fill in {name} in secrets.toml.")
        elif "PASTE" in value or "REPLACE" in value or "YOUR-" in value:
            bad(f"{name} still contains the placeholder text.", f"Replace it with your real {name}.")
        elif value != value.strip():
            bad(f"{name} has extra spaces at the start or end.", "Remove the spaces inside the quotes.")
        else:
            ok(f"{name} is filled in")
    if values["redirect_uri"] and values["redirect_uri"] != EXPECTED_REDIRECT:
        bad(f"redirect_uri is '{values['redirect_uri']}'.", f"Use exactly {EXPECTED_REDIRECT}")
    if problems:
        return 1

    kwargs = clerk.get("client_kwargs") or {}
    prompt = kwargs.get("prompt") if isinstance(kwargs, dict) else None
    if prompt is None or str(prompt).strip() not in ("", "login", "consent", "none"):
        bad("client_kwargs has no Clerk-compatible prompt setting. Streamlit would ask Clerk for "
            "prompt=select_account, which Clerk rejects after you sign in (you land back on the "
            "sign-in page).",
            'Under [auth.clerk] use: client_kwargs = { scope = "openid profile email", prompt = "" }')
    else:
        ok("client_kwargs prompt setting works with Clerk")

    # ------------------------------------------------------------------
    step("2. Security libraries (Windows can block these)")
    try:
        import authlib  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: F401
        import httpx
        ok("Authlib, cryptography and httpx load correctly")
    except ModuleNotFoundError as error:
        bad(f"Missing library: {error.name}", "Run: python -m pip install -r requirements.txt")
        return 1
    except Exception as error:
        bad(f"A library is installed but could not load: {error}",
            "If it mentions 'Application Control policy', Windows Smart App Control is blocking it. "
            "Ask a parent to check Windows Security > App & browser control.")
        return 1

    # ------------------------------------------------------------------
    step("3. Can Python find Clerk on the internet?")
    host = urlsplit(values["server_metadata_url"]).hostname or ""
    try:
        address = socket.gethostbyname(host)
        ok(f"{host} found ({address})")
    except OSError as error:
        bad(f"Python cannot look up {host} ({error}).",
            "Your browser may use 'Secure DNS' while Python can't. Check for a VPN, parental-control "
            "or network filter blocking clerk.accounts.dev, or try another Wi-Fi network.")
        return 1

    # ------------------------------------------------------------------
    step("4. Clerk's settings (Discovery URL)")
    try:
        response = httpx.get(values["server_metadata_url"], timeout=15, follow_redirects=True)
        metadata = response.json()
        token_endpoint = metadata["token_endpoint"]
        metadata["authorization_endpoint"]
        ok("Discovery URL works")
    except Exception as error:
        bad(f"Couldn't read the Discovery URL ({type(error).__name__}).",
            "Copy the Discovery URL again from Clerk > OAuth applications. It must end with "
            "/.well-known/openid-configuration")
        return 1

    # ------------------------------------------------------------------
    step("5. Client ID and Client Secret")
    # We send a deliberately FAKE sign-in code. Clerk then answers:
    #   "invalid_client" -> your ID/secret are wrong
    #   "invalid_grant"  -> your ID/secret are RIGHT (only our fake code is wrong)
    basic = base64.b64encode(f"{values['client_id']}:{values['client_secret']}".encode()).decode()
    try:
        response = httpx.post(
            token_endpoint,
            data={"grant_type": "authorization_code", "code": "scamshield-check-not-a-real-code",
                  "redirect_uri": values["redirect_uri"]},
            headers={"Authorization": "Basic " + basic, "Accept": "application/json"},
            timeout=15,
        )
        try:
            error_code = response.json().get("error", "")
        except Exception:
            error_code = ""
    except Exception as error:
        bad(f"Couldn't reach Clerk's token address ({type(error).__name__}).",
            "Same as step 3: check VPN / network filters.")
        return 1
    if error_code == "invalid_client" or response.status_code == 401:
        bad("Clerk says the Client ID or Client Secret is wrong.",
            "In Clerk > OAuth applications > Scamshield Website, copy the Client ID again and create a "
            "NEW Client Secret. Paste both into secrets.toml, save, and restart Streamlit.")
    elif error_code in ("invalid_grant", "invalid_request"):
        ok("Client ID and Client Secret are accepted by Clerk")
    else:
        print(f"  [?]    Unexpected answer from Clerk (HTTP {response.status_code}, '{error_code}').")

    # ------------------------------------------------------------------
    step("5b. Delete-account Secret key (optional)")
    secret_key = str((config.get("clerk_admin") or {}).get("secret_key", "")).strip()
    if not secret_key:
        print("  [--]   Not set up: users can sign out but not delete their account.")
        print("         To enable: add [clerk_admin] secret_key = \"sk_...\" (see secrets.toml.example).")
    elif not secret_key.startswith("sk_") or "REPLACE" in secret_key:
        bad("[clerk_admin] secret_key doesn't look like a Clerk Secret key.",
            "Copy it from Clerk > Configure > API keys > Secret keys. It starts with sk_.")
    else:
        try:
            check = httpx.get("https://api.clerk.com/v1/users/count",
                              headers={"Authorization": "Bearer " + secret_key}, timeout=15)
            if check.status_code == 200:
                ok("Secret key accepted by Clerk (Delete account will work)")
            elif check.status_code in (401, 403):
                bad("Clerk rejected the Secret key.",
                    "Copy it again from Clerk > Configure > API keys, for the SAME Clerk app.")
            else:
                print(f"  [?]    Unexpected answer from Clerk's API (HTTP {check.status_code}).")
        except Exception as error:
            bad(f"Couldn't reach api.clerk.com ({type(error).__name__}).", "Check VPN / network filters.")

    # ------------------------------------------------------------------
    step("6.Things to check in the Clerk dashboard (can't be tested from here)")
    print(f"  - Redirect URI in the OAuth application is exactly: {EXPECTED_REDIRECT}")
    print("  - Open the app at http://localhost:8501 (NOT 127.0.0.1)")
    print("  - If you just created your account, click SIGN IN once more")
    print("  - On Clerk's consent screen, click Allow")

    print("\nRESULT:", "everything testable looks right." if not problems
          else f"{problems} problem(s) found - fix them, then restart Streamlit.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
