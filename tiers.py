"""ScamShield AI - plans (Free / Plus / Pro) and monthly check limits.

Shared by the Streamlit website (mobile_app.py) and the backend API
(backend/api.py), so both enforce exactly the same rules.

WHERE A USER'S PLAN COMES FROM
------------------------------
ScamShield has NO payment system. A user's plan is read from their Clerk
account's PUBLIC METADATA, e.g. {"plan": "pro"}. Only the account owner can set
it (Clerk dashboard -> Users -> user -> Metadata, or Clerk's backend API); users
cannot change their own public metadata, so they cannot upgrade themselves.
Nothing here takes payments or says that a subscription has been paid for.
Anyone without a valid plan is on Free.

  * Backend API: add the plan to Clerk's session token (Clerk dashboard ->
    Sessions -> Customize session token):  {"plan": "{{user.public_metadata.plan}}"}
  * Website: add the "public_metadata" scope to the Clerk OAuth application,
    so the plan arrives with the sign-in details.

LOCAL TESTING: when Clerk sign-in is NOT configured there are no accounts, so
SCAMSHIELD_LOCAL_TEST_PLAN=plus|pro sets the plan for everyone. It is ignored
whenever sign-in is on.

HOW MONTHLY LIMITS WORK
-----------------------
UsageStore keeps ONE number per account per calendar month (UTC) in a small
SQLite file: (user id, "2026-11") -> checks used. A new month uses a new
key, so the usage resets automatically on the 1st (UTC). Only the
Clerk user id (e.g. "user_2abc...") and the count are stored, never messages,
names or emails.

  1. reserve() adds 1 in a single database statement, but only while the
     count is below the limit, so two requests at the same time can't both
     take the last check.
  2. If the check then fails (unreadable file, OCR error...), release()
     gives the check back. Users are only charged for checks that complete.

Free has NO monthly limit (unchanged from before); only the existing
per-minute rate limit applies. Free usage is not recorded.

Settings (environment variables, all optional):
  SCAMSHIELD_PLUS_MONTHLY_CHECKS   default 100
  SCAMSHIELD_PRO_MONTHLY_CHECKS    default 300
  SCAMSHIELD_USAGE_DB              default .scamshield_data/usage.sqlite3
"""

import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_USAGE_DB = ROOT / ".scamshield_data" / "usage.sqlite3"
LOCAL_TEST_PLAN_VARIABLE = "SCAMSHIELD_LOCAL_TEST_PLAN"
LOCAL_USER = "local-test-user"


@dataclass(frozen=True)
class Plan:
    key: str
    name: str
    price: str
    default_monthly_checks: int | None  # None = no monthly limit
    limit_variable: str | None
    documents: bool  # PDF / document scanning
    reports: bool    # downloadable reports


PLANS = {
    "free": Plan("free", "Free", "R0/month", None, None, documents=False, reports=False),
    "plus": Plan("plus", "Plus", "R70/month", 100, "SCAMSHIELD_PLUS_MONTHLY_CHECKS",
                 documents=False, reports=False),
    "pro": Plan("pro", "Pro", "R90/month", 300, "SCAMSHIELD_PRO_MONTHLY_CHECKS",
                documents=True, reports=True),
}

UPGRADE_MESSAGE = (
    "PDF and document scanning and downloadable reports are part of ScamShield Pro "
    "(R90/month). Online upgrades aren't available in the app yet. Ask the "
    "ScamShield account owner to move your account to Pro."
)


class CheckLimitReached(Exception):
    pass


def normalise_plan(value):
    """Return "free", "plus" or "pro". Anything unknown or missing is "free"."""
    value = str(value or "").strip().lower()
    return value if value in PLANS else "free"


def plan_from_claims(claims):
    """Read the plan from Clerk claims: "plan", or "public_metadata": {"plan": ...}."""
    if not claims:
        return "free"
    try:
        direct = claims.get("plan")
        metadata = claims.get("public_metadata") or {}
        nested = metadata.get("plan") if hasattr(metadata, "get") else None
    except AttributeError:
        return "free"
    return normalise_plan(direct or nested)


def local_test_plan(environ=None):
    """The plan to use when sign-in is OFF (local testing only)."""
    env = os.environ if environ is None else environ
    return normalise_plan(env.get(LOCAL_TEST_PLAN_VARIABLE))


def monthly_limit(plan, environ=None):
    """Checks allowed per month, or None for no monthly limit."""
    plan = PLANS[normalise_plan(plan)]
    if plan.default_monthly_checks is None:
        return None
    env = os.environ if environ is None else environ
    try:
        value = int(env.get(plan.limit_variable, plan.default_monthly_checks))
    except (TypeError, ValueError):
        value = plan.default_monthly_checks
    return max(0, value)


def month_key(now=None):
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y-%m")


def next_reset(now=None):
    """First day of next month (UTC), as YYYY-MM-DD."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    year, month = (now.year + 1, 1) if now.month == 12 else (now.year, now.month + 1)
    return f"{year:04d}-{month:02d}-01"


class UsageStore:
    """Monthly check counts per account, in SQLite."""

    def __init__(self, path=None):
        self.path = str(path or os.environ.get("SCAMSHIELD_USAGE_DB") or DEFAULT_USAGE_DB)
        self._lock = threading.Lock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        with self._lock, self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS monthly_usage ("
                " user_id TEXT NOT NULL, month TEXT NOT NULL, checks INTEGER NOT NULL DEFAULT 0,"
                " PRIMARY KEY (user_id, month))")

    def used(self, user_id, now=None):
        with self._lock:
            row = self._db.execute(
                "SELECT checks FROM monthly_usage WHERE user_id = ? AND month = ?",
                (user_id, month_key(now))).fetchone()
        return row[0] if row else 0

    def reserve(self, user_id, limit, now=None):
        """Use one check. Returns checks used so far. Raises CheckLimitReached."""
        if limit is None:
            return None
        month = month_key(now)
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR IGNORE INTO monthly_usage (user_id, month, checks) VALUES (?, ?, 0)",
                (user_id, month))
            updated = self._db.execute(
                "UPDATE monthly_usage SET checks = checks + 1"
                " WHERE user_id = ? AND month = ? AND checks < ?",
                (user_id, month, limit)).rowcount
            row = self._db.execute(
                "SELECT checks FROM monthly_usage WHERE user_id = ? AND month = ?",
                (user_id, month)).fetchone()
        if not updated:
            raise CheckLimitReached(limit_message(limit, now))
        return row[0]

    def release(self, user_id, now=None):
        """Give back a reserved check (the check didn't complete)."""
        with self._lock, self._db:
            self._db.execute(
                "UPDATE monthly_usage SET checks = checks - 1"
                " WHERE user_id = ? AND month = ? AND checks > 0",
                (user_id, month_key(now)))


def limit_message(limit, now=None):
    return (f"You've used all {limit} checks in your plan this month. "
            f"Your checks reset on {next_reset(now)}.")


_store = None
_store_lock = threading.Lock()


def usage_store():
    """The shared UsageStore (re-opened if SCAMSHIELD_USAGE_DB changes)."""
    global _store
    wanted = str(os.environ.get("SCAMSHIELD_USAGE_DB") or DEFAULT_USAGE_DB)
    with _store_lock:
        if _store is None or _store.path != wanted:
            _store = UsageStore(wanted)
        return _store


def account_summary(user_id, plan, store=None, now=None):
    """Plan, limit and usage, for showing in the app."""
    plan = normalise_plan(plan)
    info = PLANS[plan]
    limit = monthly_limit(plan)
    used = (store or usage_store()).used(user_id, now) if (limit is not None and user_id) else None
    return {
        "plan": plan,
        "plan_name": info.name,
        "price": info.price,
        "monthly_limit": limit,
        "checks_used": used,
        "checks_left": None if limit is None or used is None else max(0, limit - used),
        "resets_on": next_reset(now) if limit is not None else None,
        "documents": info.documents,
        "reports": info.reports,
        "upgrade_message": None if info.documents else UPGRADE_MESSAGE,
    }
