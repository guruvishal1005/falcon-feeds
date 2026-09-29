#!/usr/bin/env python
"""Scrape source URLs from FalconFeeds threat-feed posts into a CSV.

Alert emails over IMAP are the normal input: each Message-ID is the exact
key to its Elasticsearch document. A text file of post URLs still works for
one-off runs. A saved browser profile keeps the dashboard session alive.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import random
import re
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence
from urllib.parse import quote, urlparse

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Locator, Page
from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright

log = logging.getLogger("ff-scrape")

DASHBOARD_HOST = "dash.falconfeeds.io"
DASHBOARD = f"https://{DASHBOARD_HOST}"
LOGIN_URL = DASHBOARD + "/auth"
POST_URL_TEMPLATE = DASHBOARD + "/threat-feed/posts/{post_id}"
POST_ID_RE = re.compile(r"POST-[0-9A-Za-z]{8,}")
LOGIN_PATH_RE = re.compile(r"/(login|signin|sign-in|auth|register)\b")

# The dashboard SPA talks to this backend with a bearer token from localStorage.
API_BASE = "https://integrite.tech/falcon/"
API_CLIENT_ID = "falcon"
API_POST_RE = re.compile(r"/falcon/post/(POST-[0-9A-Za-z]+)")

# Screenshots are served from the API, not a public CDN. The page fetches this
# and turns it into a blob: URL, which is why the DOM has no usable image src.
IMAGE_URL_TEMPLATE = API_BASE + "filestore/download/image?fileName={name}"

# Info card renders the source link as the <h5> right after the "URL" <h4>.
SOURCE_URL_XPATH = "xpath=//h4[normalize-space(.)='URL']/following-sibling::h5[1]"
POST_DETAILS_SELECTOR = "app-post-details"

# That <h5> also contains a "Copy Link" <p>; only its direct text nodes are the URL.
DIRECT_TEXT_JS = """
el => Array.from(el.childNodes)
    .filter(n => n.nodeType === Node.TEXT_NODE)
    .map(n => n.textContent)
    .join(' ')
"""

READ_SESSION_JS = """
() => ({
  token: localStorage.getItem('token') || '',
  sessionId: localStorage.getItem('sessionID') || '',
  team: localStorage.getItem('teamDetails') || localStorage.getItem('team') || '',
})
"""

# The /auth form ships a bare <input type="text"> with no name or id, so the
# generic fallback at the end of this list is the one that usually matches.
EMAIL_SELECTORS = (
    "input[formcontrolname='email']",
    "input[type='email']",
    "input[name='email']",
    "input[autocomplete='username']",
    "input[placeholder*='mail' i]",
    "input[type='text']",
)
PASSWORD_SELECTORS = (
    "input[formcontrolname='password']",
    "input[type='password']",
    "input[name='password']",
    "input[autocomplete='current-password']",
)
# Text first: the Google buttons on the same form are also type="submit".
SUBMIT_SELECTORS = (
    "button:has-text('Sign in')",
    "button:has-text('Log in')",
    "button:has-text('Login')",
    "button[type='submit']",
)
TURNSTILE_INPUT = "input[name='cf-turnstile-response']"

CSV_FIELDS = ("input_url", "source_url", "screenshot_url", "post_id", "es_id")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_LOGIN_REQUIRED = 2
EXIT_INTERRUPTED = 130


def in_container() -> bool:
    """True inside Docker, where bundled Chromium and --no-sandbox are required."""
    return Path("/.dockerenv").exists() or os.environ.get("FF_IN_DOCKER") == "1"


class SessionExpired(RuntimeError):
    """Raised when the saved browser session is no longer authenticated."""


class LoginRequired(RuntimeError):
    """Raised when only a human can restore the session."""


@dataclass
class Target:
    """One post to scrape, plus where it came from.

    `es_id` is the Elasticsearch document id derived from the alert email's
    Message-ID. It is empty when the input was a plain text file.
    """

    url: str
    es_id: str = ""
    message_id: str = ""


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    The .env file is loaded first, because many defaults below read the
    environment and argparse evaluates those while the parser is built.
    """
    preview = argparse.ArgumentParser(add_help=False)
    preview.add_argument("--env-file", default=Path(".env"), type=Path)
    known, _ = preview.parse_known_args()
    load_env_file(resolve_env_file(known.env_file))

    parser = argparse.ArgumentParser(
        description=(
            "Open FalconFeeds post pages with a saved browser session and export "
            "each post's source URL to CSV"
        ),
    )
    parser.add_argument(
        "--source",
        choices=("file", "mail"),
        default="mail",
        help="Where post links come from (default: mail)",
    )
    parser.add_argument(
        "-i", "--input",
        default="urls.txt",
        type=Path,
        help="Text file with one post URL (or POST id) per line (default: urls.txt)",
    )
    parser.add_argument(
        "-o", "--output",
        default="source_urls.csv",
        type=Path,
        help="Output CSV path (default: source_urls.csv)",
    )
    parser.add_argument(
        "--profile",
        default=Path.home() / ".cache" / "falconfeeds-scraper" / "profile",
        type=Path,
        help="Browser profile directory holding the logged-in session",
    )
    parser.add_argument(
        "--env-file",
        default=Path(".env"),
        type=Path,
        help="File with FALCONFEEDS_EMAIL / FALCONFEEDS_PASSWORD (default: .env)",
    )
    parser.add_argument(
        "--login",
        action="store_true",
        help="Establish the session, then exit without scraping",
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Never prompt for a manual login; exit 2 instead (for daemons)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Run without a visible window",
    )
    parser.add_argument(
        "--channel",
        default="" if in_container() else "chrome",
        help="Browser channel: chrome, msedge, or '' for bundled Chromium",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Append to an existing CSV and skip URLs already present in it",
    )
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="Work through every past alert email, oldest first, resuming where "
             "the last run stopped. Implies --source mail and --resume",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=2.0,
        help="Base seconds to wait between posts (default: 2.0; --safe raises this)",
    )
    parser.add_argument(
        "--jitter",
        type=float,
        default=0.0,
        help="Extra random seconds added to --delay so the cadence is not a metronome",
    )
    parser.add_argument(
        "--cooldown-every",
        type=int,
        default=0,
        help="Take a longer pause after this many posts (0 = never)",
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        default=0.0,
        help="Seconds for the longer pause (default: 0)",
    )
    parser.add_argument(
        "--max-per-run",
        type=int,
        default=0,
        help="Stop after this many posts (default: 0, no cap; backfill is one long run)",
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Production pacing: ~8s between posts, jitter, a rest every 20 posts, "
             "and backoff after failures. Implied by --backfill",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=45,
        help="Give up on a page after this many seconds (default: 45). "
             "Do not raise this to 'be safer'; a stuck page should fail and move on",
    )
    parser.add_argument(
        "--login-timeout",
        type=int,
        default=600,
        help="Seconds to wait for a manual login (default: 600)",
    )
    watch = parser.add_argument_group("watch mode")
    watch.add_argument(
        "--watch",
        action="store_true",
        help="Stay running, keep the session warm and scrape new posts as they appear",
    )
    watch.add_argument(
        "--poll-seconds",
        type=int,
        default=60,
        help="Seconds between polls for new work (default: 60)",
    )
    watch.add_argument(
        "--keepalive-minutes",
        type=int,
        default=15,
        help="Reload the dashboard after this long idle to refresh the session",
    )
    watch.add_argument(
        "--max-failures",
        type=int,
        default=5,
        help="Consecutive poll failures before giving up (default: 5)",
    )
    watch.add_argument(
        "--state-file",
        default=Path(".falconfeeds.state.json"),
        type=Path,
        help="Where the mail UID checkpoint is stored",
    )
    mail = parser.add_argument_group("mail source (--source mail)")
    mail.add_argument("--mail-host", default=os.environ.get("IMAP_HOST", "imap.gmail.com"))
    mail.add_argument("--mail-port", type=int,
                      default=int(os.environ.get("IMAP_PORT", "993")))
    mail.add_argument("--mail-user", default=os.environ.get("IMAP_USER", ""))
    mail.add_argument("--mail-password", default=os.environ.get("IMAP_PASSWORD", ""))
    mail.add_argument("--mail-folder", default=os.environ.get("IMAP_FOLDER", "INBOX"),
                      help="Mailbox to read; Gmail's archive is '[Gmail]/All Mail'")
    mail.add_argument("--mail-from", default=os.environ.get("IMAP_FROM", "falconfeeds"),
                      help="Substring the sender must contain (default: falconfeeds)")
    mail.add_argument("--mail-subject", default="ALERT",
                      help="Substring the subject must contain (default: ALERT). "
                           "Pass an empty string to include promotional mail")
    mail.add_argument("--mail-since", default="",
                      help="Only mail on or after this date (YYYY-MM-DD)")
    mail.add_argument("--mail-before", default="",
                      help="Only mail before this date (YYYY-MM-DD)")
    mail.add_argument("--mail-limit", type=int, default=0,
                      help="Stop after this many emails (0 = no limit)")
    mail.add_argument("--mail-no-follow", action="store_true",
                      help="Do not resolve click-tracking links to find the post URL")
    mail.add_argument("--mail-inspect", type=int, metavar="N", default=0,
                      help="Print what N alert emails contain, then exit")
    mail.add_argument("--verify-mapping", type=int, metavar="N", nargs="?",
                      const=40, default=0,
                      help="Check that this mailbox is the one feeding the "
                           "Elasticsearch index, then exit. Run this before "
                           "enabling --es-write on a new environment")
    mail.add_argument("--settled-hours", type=int, default=24,
                      help="Ignore mail newer than this when verifying, to "
                           "allow for ingestion lag (default: 24)")
    blob = parser.add_argument_group("screenshot re-hosting")
    blob.add_argument(
        "--blob-sas-url",
        default=os.environ.get("AZURE_BLOB_SAS_URL", ""),
        help="Azure container SAS URL. When set, screenshots are downloaded "
             "and re-uploaded there, and the CSV holds the blob URL. Keep this "
             "in .env, not on the command line",
    )
    blob.add_argument(
        "--no-upload-images",
        action="store_true",
        help="Keep the FalconFeeds image URLs instead of re-hosting them",
    )
    es = parser.add_argument_group("elasticsearch")
    es.add_argument("--es-url", default=os.environ.get("ES_URL", ""),
                    help="Elasticsearch URL; enables the skip check and the writer")
    es.add_argument("--es-index", default=os.environ.get("ES_INDEX", "df_breaches"),
                    help="Index holding the alerts (default: df_breaches)")
    es.add_argument("--es-user", default=os.environ.get("ES_USER", ""))
    es.add_argument("--es-password", default=os.environ.get("ES_PASSWORD", ""))
    es.add_argument("--es-ca-cert", default=os.environ.get("ES_CA_CERT", ""),
                    help="CA bundle for a self-signed cluster certificate")
    es.add_argument("--es-insecure", action="store_true",
                    default=os.environ.get("ES_INSECURE", "") == "1",
                    help="Skip TLS verification (the cluster uses a self-signed CA)")
    es.add_argument("--es-write", action="store_true",
                    help="Actually write source_url back. Off by default: without "
                         "it the writer only logs what it would do")
    es.add_argument("--no-es-skip", action="store_true",
                    help="Do not skip alerts that already have a source_url")
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def resolve_env_file(path: Path) -> Path:
    """Prefer the given path; if it is a relative miss, try next to this script."""
    if path.is_file():
        return path
    if not path.is_absolute():
        nearby = Path(__file__).resolve().parent / path
        if nearby.is_file():
            return nearby
    return path


def load_env_file(path: Path) -> None:
    """Load KEY=VALUE pairs from a file without overriding real env vars.

    Empty values already in the environment are replaced: an exported
    `IMAP_USER=` in the shell would otherwise hide the .env entry.
    """
    if not path.is_file():
        return
    mode = path.stat().st_mode & 0o077
    if mode:
        log.warning("%s is readable by others; chmod 600 it", path)
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.lstrip("\ufeff").strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        if not key:
            continue
        if key not in os.environ or os.environ[key] == "":
            os.environ[key] = value


def apply_safe_pace(args: argparse.Namespace) -> None:
    """Apply conservative pacing unless the user overrode the values.

    22k posts at a flat 2s delay looks like a bot and will get a trial
    (or a paid seat) rate-limited. Safe mode is human-shaped: several seconds
    between pages, a little randomness, a longer rest every so often, and a
    growing pause after failures. Page timeout stays at 45s so a hung load
    does not sit there for minutes.
    """
    if not (args.safe or args.backfill):
        return
    delay_set = any(a == "--delay" or a.startswith("--delay=") for a in sys.argv)
    if not delay_set:
        args.delay = max(args.delay, 8.0)
    if args.jitter <= 0:
        args.jitter = 3.0
    if args.cooldown_every <= 0:
        args.cooldown_every = 20
    if args.cooldown <= 0:
        args.cooldown = 60.0
    log.info(
        "Safe pace: %.1f–%.1fs between posts, %.0fs rest every %d, "
        "page timeout %ds, cap %s this run",
        args.delay, args.delay + args.jitter, args.cooldown,
        args.cooldown_every, args.timeout,
        args.max_per_run if args.max_per_run else "none (one long run)",
    )


def pause_between_posts(args: argparse.Namespace, index: int, total: int,
                        streak_failed: int) -> None:
    """Sleep like a person between posts. Does not run after the last one."""
    if index >= total:
        return
    if streak_failed:
        wait = min(300.0, 15.0 * (2 ** (streak_failed - 1)))
        log.warning("Backing off %.0fs after %d consecutive failure(s)",
                    wait, streak_failed)
        time.sleep(wait)
        return
    wait = args.delay + random.uniform(0.0, max(0.0, args.jitter))
    if args.cooldown_every and index % args.cooldown_every == 0:
        extra = args.cooldown + random.uniform(0.0, args.cooldown * 0.3)
        log.info("Cooldown %.0fs after %d posts", extra, index)
        wait += extra
    time.sleep(wait)


def apply_env_credentials(args: argparse.Namespace) -> None:
    """Fill mail/ES flags from the environment when argparse left them empty."""
    if not args.mail_user:
        args.mail_user = os.environ.get("IMAP_USER", "")
    if not args.mail_password:
        args.mail_password = os.environ.get("IMAP_PASSWORD", "")
    # Gmail shows App Passwords as four groups; IMAP wants the 16 characters.
    args.mail_password = args.mail_password.replace(" ", "")
    if not args.es_url:
        args.es_url = os.environ.get("ES_URL", "")
    if not args.es_user:
        args.es_user = os.environ.get("ES_USER", "")
    if not args.es_password:
        args.es_password = os.environ.get("ES_PASSWORD", "")
    if not args.blob_sas_url:
        args.blob_sas_url = os.environ.get("AZURE_BLOB_SAS_URL", "")


def read_targets(path: Path) -> list[Target]:
    """Read post URLs from a text file, skipping blanks and '#' comments."""
    if not path.is_file():
        log.error("Input file not found: %s", path)
        return []
    urls = normalise_urls(path.read_text(encoding="utf-8").splitlines())
    return [Target(url=url) for url in urls]


def normalise_urls(lines: Sequence[str]) -> list[str]:
    """Turn raw lines into de-duplicated dashboard post URLs."""
    targets: list[str] = []
    seen: set[str] = set()
    for raw in lines:
        line = (raw or "").strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("http"):
            match = POST_ID_RE.search(line)
            if not match:
                log.warning("Skipping unrecognised line: %s", line)
                continue
            line = POST_URL_TEMPLATE.format(post_id=match.group(0))
        if line not in seen:
            seen.add(line)
            targets.append(line)
    return targets


def read_done_urls(path: Path) -> set[str]:
    """Return the input URLs already recorded in an existing output CSV."""
    if not path.is_file():
        return set()
    with path.open(newline="", encoding="utf-8") as handle:
        return {
            row["input_url"]
            for row in csv.DictReader(handle)
            if row.get("input_url")
        }


def check_csv_header(path: Path) -> None:
    """Refuse to append to a CSV written by an older column layout."""
    if not path.is_file() or path.stat().st_size == 0:
        return
    with path.open(newline="", encoding="utf-8") as handle:
        header = next(csv.reader(handle), [])
    missing = [name for name in CSV_FIELDS if name not in header]
    if missing:
        raise RuntimeError(
            f"{path} has columns {header} and is missing {missing}. "
            f"Rename or delete it so a new one can be written."
        )


def load_state(path: Path) -> dict[str, Any]:
    """Read the watch-mode checkpoint, tolerating a missing or corrupt file."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    """Persist the watch-mode checkpoint."""
    try:
        path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except OSError as exc:
        log.warning("Could not write state file %s: %s", path, exc)


@contextmanager
def profile_lock(profile: Path) -> Iterator[None]:
    """Stop two scrapers from sharing one Chrome profile directory."""
    lock = profile.parent / f"{profile.name}.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            handle = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            try:
                pid = int(lock.read_text(encoding="utf-8").strip() or 0)
            except (OSError, ValueError):
                pid = 0
            if pid:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    log.warning("Removing stale profile lock from pid %d", pid)
                    lock.unlink(missing_ok=True)
                    continue
                except PermissionError:
                    pass
                raise RuntimeError(
                    f"profile {profile} is already in use by pid {pid}"
                )
            lock.unlink(missing_ok=True)
    try:
        os.write(handle, str(os.getpid()).encode())
        os.close(handle)
        yield
    finally:
        lock.unlink(missing_ok=True)


def session_token(page: Page) -> str:
    """Return the dashboard's stored bearer token, or '' when signed out."""
    try:
        raw = page.evaluate("() => localStorage.getItem('token') || ''")
    except PlaywrightError:
        return ""
    return str(raw or "").strip().strip('"')


def is_logged_out(page: Page) -> bool:
    """Report whether the browser lacks a usable dashboard session.

    The URL alone is not proof: the SPA happily sits on a dashboard path while
    unauthenticated. The token the app stores after login is the real signal.
    """
    host = urlparse(page.url).hostname or ""
    if host != DASHBOARD_HOST or LOGIN_PATH_RE.search(page.url):
        return True
    return not session_token(page)


def open_page(page: Page, url: str, selector: str, timeout: int, reloads: int = 2) -> bool:
    """Navigate and wait for the SPA to render, reloading if it stays empty.

    The dashboard frequently serves an inert prerendered shell on the first
    navigation; reloading is what actually boots Angular.
    """
    page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
    slice_ms = max(5_000, timeout * 1000 // (reloads + 1))
    for attempt in range(reloads + 1):
        if attempt:
            log.debug("Nothing rendered yet, reloading %s", url)
            try:
                page.reload(wait_until="domcontentloaded", timeout=timeout * 1000)
            except PlaywrightError as exc:
                log.debug("Reload failed: %s", str(exc).splitlines()[0])
                continue
        try:
            page.wait_for_selector(selector, timeout=slice_ms)
            return True
        except PlaywrightTimeout:
            continue
    return False


def authenticated_page(context: Any) -> Page | None:
    """Return whichever open tab holds a signed-in dashboard session."""
    for candidate in list(context.pages):
        try:
            host = urlparse(candidate.url).hostname or ""
        except PlaywrightError:
            continue
        if host == DASHBOARD_HOST and session_token(candidate):
            return candidate
    return None


def find_first(page: Page, selectors: Sequence[str], timeout: int) -> Locator | None:
    """Return the first selector in the list that resolves to a visible element."""
    deadline = time.monotonic() + timeout / 1000
    while time.monotonic() < deadline:
        for selector in selectors:
            locator = page.locator(selector).first
            try:
                if locator.count() and locator.is_visible():
                    return locator
            except PlaywrightError:
                continue
        page.wait_for_timeout(500)
    return None


def wait_for_turnstile(page: Page, timeout: int = 30_000) -> None:
    """Give an invisible Cloudflare Turnstile widget time to mint its token."""
    widget = page.locator(TURNSTILE_INPUT).first
    if not widget.count():
        return
    deadline = time.monotonic() + timeout / 1000
    while time.monotonic() < deadline:
        if page.evaluate(
            f"() => (document.querySelector({TURNSTILE_INPUT!r}) || {{}}).value || ''"
        ):
            log.debug("Turnstile token present")
            return
        page.wait_for_timeout(500)
    log.warning("Turnstile did not resolve in time; submitting anyway")


def login_with_password(page: Page, email: str, password: str, timeout: int) -> bool:
    """Attempt an unattended login. Returns True once the dashboard is reachable."""
    log.info("Attempting automatic login as %s", email)
    if not open_page(page, LOGIN_URL, ", ".join(EMAIL_SELECTORS), timeout=30):
        log.error(
        log.error("Login form never rendered")
        )
        return False
    email_box = find_first(page, EMAIL_SELECTORS, 10_000)
    if email_box is None:
        log.error("Login form rendered but no email field matched")
        return False
    email_box.fill(email)
    password_box = find_first(page, PASSWORD_SELECTORS, 10_000)
    if password_box is None:
        # Some flows ask for the password on a second step.
        submit = find_first(page, SUBMIT_SELECTORS, 3_000)
        if submit is not None:
            submit.click()
        password_box = find_first(page, PASSWORD_SELECTORS, 15_000)
    if password_box is None:
        log.error("No password field found on the login page")
        return False
    password_box.fill(password)
    wait_for_turnstile(page)
    submit = find_first(page, SUBMIT_SELECTORS, 5_000)
    if submit is not None:
        submit.click()
    else:
        password_box.press("Enter")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        page.wait_for_timeout(1000)
        if not is_logged_out(page):
            log.info("Automatic login succeeded")
            page.wait_for_timeout(2000)
            return True
        error = page.locator("app-alerts").first
        try:
            if error.count() and error.inner_text().strip():
                log.error("Login rejected: %s", error.inner_text().strip()[:200])
                return False
        except PlaywrightError:
            pass
    log.error("Automatic login timed out")
    return False


def wait_for_manual_login(context: Any, timeout: int) -> Page | None:
    """Block until a human logs in, in any tab of the browser window."""
    print(
        "\n  Log in to FalconFeeds in the browser window that just opened.\n"
        "  If the page looks blank, reload it once - the dashboard needs that.\n"
        "  The session is saved to the profile directory and reused next time.\n",
        file=sys.stderr,
    )
    deadline = time.monotonic() + timeout
    reported = 0.0
    while time.monotonic() < deadline:
        time.sleep(2)
        active = authenticated_page(context)
        if active is not None:
            log.info("Login detected on %s", active.url)
            time.sleep(2)
            return active
        if time.monotonic() - reported > 30:
            reported = time.monotonic()
            urls = [p.url for p in context.pages]
            log.debug("Still waiting; open tabs: %s", urls)
    log.error("Timed out waiting for login after %ds", timeout)
    return None


def ensure_session(context: Any, page: Page, args: argparse.Namespace) -> Page:
    """Guarantee an authenticated session and return the page holding it.

    Order: reuse the saved session, then log in from stored credentials, then
    ask a human. Raises LoginRequired when no path is available.
    """
    open_page(page, DASHBOARD + "/threat-feed/posts", "app-root", timeout=args.timeout)
    active = authenticated_page(context)
    if active is not None:
        log.info("Existing session is valid")
        return active
    log.warning("Session is not authenticated (at %s)", page.url)
    email = os.environ.get("FALCONFEEDS_EMAIL", "")
    password = os.environ.get("FALCONFEEDS_PASSWORD", "")
    if email and password:
        if login_with_password(page, email, password, args.login_timeout):
            active = authenticated_page(context)
            if active is not None:
                return active
            log.error("Login appeared to succeed but no session token was stored")
    else:
        log.info("No FALCONFEEDS_EMAIL/FALCONFEEDS_PASSWORD set, skipping auto-login")
    if args.no_interactive or args.headless or not sys.stdin.isatty():
        raise LoginRequired(
            "Automatic login failed and no terminal is attached for a manual one"
        )
    active = wait_for_manual_login(context, args.login_timeout)
    if active is not None:
        return active
    raise LoginRequired("Manual login did not complete")


def extract_post_id(page: Page, input_url: str) -> str:
    """Return the POST-XXXX id from the URL, falling back to the page body."""
    for candidate in (input_url, page.url):
        match = POST_ID_RE.search(candidate)
        if match:
            return match.group(0)
    match = POST_ID_RE.search(page.content())
    return match.group(0) if match else ""


def extract_source_url(page: Page) -> str:
    """Return the source URL shown in the post's Info card, or ''."""
    locator = page.locator(SOURCE_URL_XPATH).first
    try:
        locator.wait_for(state="attached", timeout=10_000)
    except PlaywrightTimeout:
        log.debug("No 'URL' field rendered on the page")
        return ""
    text = str(locator.evaluate(DIRECT_TEXT_JS) or "").strip()
    if not text:
        text = locator.inner_text().split("content_copy")[0].strip()
    # Guard against picking up the "Copy Link" label if the DOM ever changes.
    return text.split()[0] if text else ""


class PostApiCapture:
    """Keeps the post JSON the dashboard fetches while rendering a page.

    The page already asks the backend for the post, and that response carries
    both the source URL and the screenshot filenames. Reading it as it goes
    past is free, and more reliable than digging them out of the DOM.
    """

    def __init__(self, page: Page) -> None:
        self.by_post: dict[str, dict[str, Any]] = {}
        page.on("response", self._capture)

    def _capture(self, response: Any) -> None:
        match = API_POST_RE.search(response.url or "")
        if not match:
            return
        try:
            body = response.json()
        except Exception:
            return
        if isinstance(body, dict):
            data = body.get("data")
            self.by_post[match.group(1)] = data if isinstance(data, dict) else body

    def data(self, post_id: str) -> dict[str, Any]:
        """Return the captured payload for a post, or {}."""
        return self.by_post.get(post_id, {})

    def wait(self, page: Page, post_id: str, timeout_ms: int = 8000) -> dict[str, Any]:
        """Wait for a post's payload to arrive.

        The response can land after the page has rendered, and Playwright only
        dispatches the event while we are inside one of its calls, so poll
        rather than reading once.
        """
        deadline = time.monotonic() + timeout_ms / 1000
        while True:
            data = self.data(post_id)
            if data or time.monotonic() > deadline:
                return data
            page.wait_for_timeout(200)


def published_url(data: dict[str, Any]) -> str:
    """Return meta.publishedURL from a post payload, or ''."""
    meta = data.get("meta")
    value = (meta or {}).get("publishedURL") if isinstance(meta, dict) else None
    return value.strip() if isinstance(value, str) else ""


def screenshot_urls(data: dict[str, Any]) -> list[str]:
    """Turn meta.images filenames into fetchable image URLs."""
    meta = data.get("meta")
    images = (meta or {}).get("images") if isinstance(meta, dict) else None
    if not isinstance(images, list):
        return []
    return [
        IMAGE_URL_TEMPLATE.format(name=quote(name, safe=""))
        for name in images
        if isinstance(name, str) and name.strip()
    ]


def scrape_post_dom(
    page: Page, input_url: str, timeout: int, capture: PostApiCapture | None = None
) -> dict[str, str]:
    """Open a post page and pull out its source URL, screenshots and post id."""
    rendered = open_page(page, input_url, POST_DETAILS_SELECTOR, timeout)
    if is_logged_out(page):
        host = urlparse(page.url).hostname or ""
        if LOGIN_PATH_RE.search(page.url) or "falconfeeds" in host:
            raise SessionExpired("Session expired")
        raise RuntimeError(f"redirected off the dashboard to {page.url}")
    if not rendered:
        raise RuntimeError("post details never rendered")
    post_id = extract_post_id(page, input_url)
    data = capture.wait(page, post_id) if capture else {}
    from_api = published_url(data)
    from_dom = extract_source_url(page)
    if from_api and from_dom and from_api != from_dom:
        log.debug("Source URL differs: api %s, dom %s", from_api, from_dom)
    if not data:
        log.debug("No post payload captured for %s; screenshots unavailable", post_id)
    return {
        "input_url": input_url,
        "source_url": from_api or from_dom,
        "screenshot_url": " ".join(screenshot_urls(data)),
        "post_id": post_id,
    }


def api_headers(page: Page) -> dict[str, str]:
    """Build dashboard API headers from the browser session's stored token."""
    session = page.evaluate(READ_SESSION_JS)
    token = session_token(page)
    if not token:
        raise SessionExpired("No API token in the browser session")
    team = ""
    raw_team = session.get("team") or ""
    if raw_team:
        try:
            team = json.loads(raw_team).get("teamUUID", "")
        except ValueError:
            team = ""
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "ts-x-client-id": API_CLIENT_ID,
        "ts-falcon-x-session-id": session.get("sessionId", ""),
        "x-ts-team-uuid": team,
        "Origin": DASHBOARD,
        "Referer": DASHBOARD + "/",
    }


def launch_context(player: Any, args: argparse.Namespace) -> Any:
    """Launch a persistent browser context, falling back to bundled Chromium."""
    options: dict[str, Any] = {
        "user_data_dir": str(args.profile),
        "headless": args.headless,
        "viewport": {"width": 1440, "height": 900},
        "args": ["--disable-blink-features=AutomationControlled"],
    }
    if in_container():
        options["args"] += ["--no-sandbox", "--disable-dev-shm-usage"]
    if args.channel:
        try:
            return player.chromium.launch_persistent_context(
                channel=args.channel, **options
            )
        except PlaywrightError as exc:
            log.warning(
                "Channel '%s' unavailable (%s), using bundled Chromium",
                args.channel,
                str(exc).splitlines()[0],
            )
    return player.chromium.launch_persistent_context(**options)


def mail_connect(args: argparse.Namespace, quiet: bool = False) -> Any:
    """Open the mailbox named by the CLI flags and environment."""
    import falconfeeds_mail as mail

    apply_env_credentials(args)
    missing = [
        name for name, value in (
            ("IMAP_USER", args.mail_user),
            ("IMAP_PASSWORD", args.mail_password),
        ) if not value
    ]
    if missing:
        env_path = resolve_env_file(Path(args.env_file))
        where = env_path.resolve() if env_path.is_file() else f"{env_path} (not found)"
        raise RuntimeError(
            f"Missing {', '.join(missing)}. Put them in {where}. "
            "Gmail needs an App Password, not your normal password."
        )
    conn = mail.connect(args.mail_host, args.mail_port, args.mail_user,
                        args.mail_password, quiet=quiet)
    total = mail.select_folder(conn, args.mail_folder)
    if quiet:
        log.debug("Reopened %s read-only (%d messages)", args.mail_folder, total)
    else:
        log.info("Opened %s read-only (%d messages)", args.mail_folder, total)
    return conn


MAIL_PARSE_BATCH = 10


def mail_search_uids(args: argparse.Namespace, uid_floor: int = 0) -> list[int]:
    """Return matching IMAP UIDs, oldest first, then close the mailbox."""
    import falconfeeds_mail as mail

    conn = mail_connect(args)
    try:
        uids = mail.search_uids(conn, sender=args.mail_from,
                                since=args.mail_since, before=args.mail_before,
                                subject=args.mail_subject)
        if uid_floor:
            uids = [uid for uid in uids if uid > uid_floor]
        if args.mail_limit:
            uids = uids[:args.mail_limit] if args.backfill else uids[-args.mail_limit:]
        return uids
    finally:
        close_mailbox(conn)


def targets_from_alerts(alerts: Sequence[Any], mail_mod: Any) -> tuple[list[Target], int, int]:
    """Turn parsed emails into scrape targets. Returns (targets, highest uid, no_link)."""
    targets: list[Target] = []
    highest = 0
    no_link = 0
    for alert in alerts:
        highest = max(highest, alert.uid)
        if mail_mod.is_non_alert(alert):
            log.info("Skipping non-alert %r (uid %d)", alert.subject[:60], alert.uid)
            continue
        if not alert.post_url:
            no_link += 1
            log.warning("No post link in %r (uid %d)", alert.subject[:60], alert.uid)
            continue
        targets.append(Target(url=alert.post_url, es_id=alert.es_id,
                              message_id=alert.message_id))
    return dedupe_targets(targets), highest, no_link


def parse_mail_uids(args: argparse.Namespace, uids: Sequence[int]) -> tuple[list[Target], int]:
    """Fetch and parse a slice of UIDs. Reconnects so a long scrape cannot idle out IMAP."""
    import falconfeeds_mail as mail

    if not uids:
        return [], 0
    conn = mail_connect(args, quiet=True)
    try:
        alerts = list(mail.iter_alerts(
            conn, uids, batch=len(uids),
            follow_links=not args.mail_no_follow,
        ))
        targets, highest, no_link = targets_from_alerts(alerts, mail)
        if no_link:
            log.warning("%d email(s) in this batch had no post link", no_link)
        return targets, highest
    finally:
        close_mailbox(conn)


def mail_targets(
    args: argparse.Namespace, uid_floor: int = 0
) -> tuple[list[Target], int]:
    """Read matching mail and return all scrape targets (watch / small runs)."""
    uids = mail_search_uids(args, uid_floor)
    if not uids:
        return [], uid_floor
    log.info("Found %d alert email(s) from '%s'", len(uids), args.mail_from)
    targets, highest = parse_mail_uids(args, uids)
    return targets, max(highest, uid_floor)


def close_mailbox(conn: Any) -> None:
    """Log out of IMAP without letting teardown errors mask a real one."""
    try:
        conn.close()
    except Exception:
        pass
    try:
        conn.logout()
    except Exception:
        pass


def dedupe_targets(targets: Sequence[Target]) -> list[Target]:
    """Drop repeated post URLs, keeping the first occurrence."""
    seen: set[str] = set()
    out: list[Target] = []
    for target in targets:
        if target.url in seen:
            continue
        seen.add(target.url)
        out.append(target)
    return out


def es_client(args: argparse.Namespace) -> Any:
    """Connect to Elasticsearch, or return None when no URL is configured."""
    if not args.es_url:
        return None
    import falconfeeds_es as es

    return es.connect(args.es_url, args.es_user, args.es_password,
                      ca_cert=args.es_ca_cert, insecure=args.es_insecure)


def drop_already_filled(
    client: Any, index: str, targets: list[Target], batch: int = 500
) -> list[Target]:
    """Remove targets whose Elasticsearch document already has a source_url."""
    import falconfeeds_es as es

    known = [t for t in targets if t.es_id]
    if client is None or not known:
        return targets
    filled: dict[str, str] = {}
    for start in range(0, len(known), batch):
        ids = [t.es_id for t in known[start:start + batch]]
        filled.update(es.existing_source_urls(client, index, ids))
    if not filled:
        return targets
    log.info("Skipping %d alert(s) that already have a source_url", len(filled))
    return [t for t in targets if t.es_id not in filled]


def image_fetcher(page: Page, args: argparse.Namespace) -> Any:
    """Build a callable that downloads a screenshot with the session's token."""
    def fetch_via_browser(url: str) -> tuple[bytes, str]:
        # The browser's own HTTP stack, so Cloudflare sees a familiar client.
        response = page.request.get(url, headers=api_headers(page),
                                    timeout=args.timeout * 1000)
        if response.status == 401:
            raise SessionExpired("Session token rejected fetching an image")
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        return response.body(), (response.headers or {}).get("content-type", "")
    return fetch_via_browser


def build_relay(page: Page, args: argparse.Namespace) -> Any:
    """Build the image re-hosting relay, or None when it is not configured."""
    if args.no_upload_images or not args.blob_sas_url:
        return None
    import falconfeeds_blob as blob

    if any(arg.startswith("--blob-sas-url") for arg in sys.argv):
        log.warning("The SAS token is visible to anyone who can run 'ps'. "
                    "Put AZURE_BLOB_SAS_URL in .env instead")
    target = blob.BlobTarget.parse(args.blob_sas_url)
    log.info("Re-hosting screenshots to %s", target.base)
    return blob.ImageRelay(target, image_fetcher(page, args), timeout=args.timeout)


def process(
    page: Page,
    targets: list[Target],
    args: argparse.Namespace,
    append: bool,
    sink: Any = None,
    capture: PostApiCapture | None = None,
) -> tuple[int, int]:
    """Scrape every target and append rows to the CSV. Returns (ok, failed)."""
    ok = 0
    failed = 0
    streak = 0
    append = append or args.resume
    if append and args.output.is_file():
        check_csv_header(args.output)
    mode = "a" if append and args.output.is_file() else "w"
    relay = build_relay(page, args)
    with args.output.open(mode, newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        if mode == "w":
            writer.writeheader()
        for index, target in enumerate(targets, start=1):
            log.info("[%d/%d] %s", index, len(targets), target.url)
            try:
                row = scrape_post_dom(page, target.url, args.timeout, capture)
            except SessionExpired:
                raise
            except (RuntimeError, PlaywrightTimeout, PlaywrightError) as exc:
                log.error("Failed: %s", str(exc).splitlines()[0])
                row = {"input_url": target.url, "source_url": "", "post_id": ""}
            row.setdefault("screenshot_url", "")
            row["es_id"] = target.es_id
            shots = row["screenshot_url"].split()
            if shots and relay is not None:
                shots = relay.relay(shots)
                row["screenshot_url"] = " ".join(shots)
            if row["source_url"]:
                ok += 1
                streak = 0
                log.info("  -> %s (%s)%s", row["source_url"], row["post_id"],
                         f" +{len(shots)} image(s)" if shots else "")
                if sink is not None and target.es_id:
                    sink.update(target.es_id, row["source_url"],
                                screenshot=shots[0] if shots else "")
            else:
                failed += 1
                streak += 1
                log.warning("  -> no source URL found")
            writer.writerow(row)
            handle.flush()
            pause_between_posts(args, index, len(targets), streak)
    if relay is not None and (relay.uploaded or relay.failed):
        log.info("%s", relay.summary())
    return ok, failed


def watch(context: Any, page: Page, args: argparse.Namespace, sink: Any = None) -> int:
    """Stay resident, keeping the session warm and scraping new posts."""
    state = load_state(args.state_file)
    search = getattr(sink, "client", None)
    if args.source == "mail":
        log.info("Watching %s on %s for new alerts", args.mail_folder, args.mail_host)
    else:
        log.info("Watching %s for new lines", args.input)
    failures = 0
    last_activity = time.monotonic()
    keepalive = args.keepalive_minutes * 60
    capture = PostApiCapture(page)
    while True:
        try:
            uid = 0
            if args.source == "mail":
                targets, uid = mail_targets(args, int(state.get("mail_uid") or 0))
                if not args.no_es_skip:
                    targets = drop_already_filled(search, args.es_index, targets)
            else:
                targets = read_targets(args.input)
            done = read_done_urls(args.output)
            targets = [t for t in targets if t.url not in done]
            if args.max_per_run:
                targets = targets[:args.max_per_run]
            if targets:
                ok, failed = process(page, targets, args, append=True,
                                     sink=sink, capture=capture)
                log.info("Batch complete: %d with a source URL, %d without", ok, failed)
                last_activity = time.monotonic()
            if args.source == "mail" and uid and uid != state.get("mail_uid"):
                state["mail_uid"] = uid
                save_state(args.state_file, state)
            if time.monotonic() - last_activity > keepalive:
                log.debug("Keepalive: refreshing the dashboard session")
                previous, page = page, ensure_session(context, page, args)
                if page is not previous:
                    capture = PostApiCapture(page)
                last_activity = time.monotonic()
            failures = 0
        except SessionExpired as exc:
            log.warning("%s, re-authenticating", exc)
            previous, page = page, ensure_session(context, page, args)
            if page is not previous:
                capture = PostApiCapture(page)
            last_activity = time.monotonic()
        except LoginRequired:
            raise
        except Exception as exc:
            failures += 1
            log.error("Poll failed (%d/%d): %s", failures, args.max_failures, exc)
            if failures >= args.max_failures:
                log.error("Giving up after %d consecutive failures", failures)
                return EXIT_ERROR
        time.sleep(args.poll_seconds)


def mail_diagnostics(args: argparse.Namespace) -> int:
    """Handle the mailbox inspection flags, which never touch the browser."""
    import falconfeeds_mail as mail

    conn = mail_connect(args)
    try:
        uids = mail.search_uids(conn, sender=args.mail_from,
                                since=args.mail_since, before=args.mail_before,
                                subject=args.mail_subject)
        print(f"{len(uids)} message(s) match sender '{args.mail_from}'")
        if not uids:
            print("Nothing matched. Check IMAP_FROM / IMAP_FOLDER if alerts "
                  "are filed under a label.")
            return EXIT_OK
        sample = uids[-args.mail_inspect:]
        client = es_client(args)
        for alert in mail.iter_alerts(conn, sample,
                                      follow_links=not args.mail_no_follow):
            print("-" * 72)
            print(mail.describe(alert))
            if client is not None and alert.es_id:
                found = bool(es_lookup(client, args.es_index, alert.es_id))
                print(f"  in {args.es_index:<9} {'yes' if found else 'NO MATCH'}")
        return EXIT_OK
    finally:
        close_mailbox(conn)


def verify_mapping(args: argparse.Namespace) -> int:
    """Check that this mailbox is the one that feeds the Elasticsearch index.

    Alerts are stored under FALCON_<message-id>, and a mail provider gives
    every recipient a different Message-ID for the same alert. So a mailbox
    that merely receives the same alerts will produce ids that are not in the
    index, which is indistinguishable from a broken pipeline until nothing
    gets written. This tells the two apart before that happens.
    """
    import falconfeeds_es as es
    import falconfeeds_mail as mail

    if not args.es_url:
        log.error("--verify-mapping needs --es-url (or ES_URL in .env)")
        return EXIT_ERROR
    client = es_client(args)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=args.settled_hours)
    conn = mail_connect(args)
    try:
        uids = mail.search_uids(
            conn, sender=args.mail_from,
            before=cutoff.strftime("%Y-%m-%d"), subject=args.mail_subject,
        )[-args.verify_mapping:]
        if not uids:
            log.error("No alert mail older than %dh from '%s' to check",
                      args.settled_hours, args.mail_from)
            return EXIT_ERROR
        sampled = [
            (mail.es_id_for(mail.header(msg, "Message-ID")), mail.sent_at(msg))
            for _, msg in mail.fetch_messages(conn, uids, headers_only=True)
        ]
    finally:
        close_mailbox(conn)

    sampled = [(i, when) for i, when in sampled if i and when]
    ids = [i for i, _ in sampled]
    present = set(ids) - set(es.missing_ids(client, args.es_index, ids))
    near = sum(
        1 for i, when in sampled
        if i not in present
        and len(es.candidates_near(client, args.es_index, when)) == 1
    )
    total = len(sampled)
    exact = len(present)

    print(f"\nChecked {total} alert email(s) older than {args.settled_hours}h")
    print(f"  {exact:>4} found in {args.es_index} by Message-ID   "
          f"({pct(exact, total)})")
    print(f"  {near:>4} of the rest matched by send time alone "
          f"({pct(near, total)})")
    print(f"  {total - exact - near:>4} not found at all\n")

    if exact >= total * 0.9:
        print("PASS: this mailbox feeds that index. Message-IDs line up, so "
              "--es-write will update the right documents.")
        return EXIT_OK
    if near >= total * 0.5:
        print("WRONG MAILBOX: these alerts are in the index, but stored under\n"
              "different Message-IDs. Mail providers issue a distinct\n"
              "Message-ID per recipient, so this inbox only receives copies of\n"
              "the alerts the pipeline ingests elsewhere. Point --mail-user at\n"
              "the mailbox the pipeline actually reads before enabling writes.")
        return EXIT_ERROR
    print("NO OVERLAP: almost none of these alerts are in the index. Either\n"
          "the index or the sender filter is wrong, or the pipeline that\n"
          "populates it is not running.")
    return EXIT_ERROR


def pct(part: int, whole: int) -> str:
    """Format a percentage for the verification report."""
    return f"{100 * part / whole:.0f}%" if whole else "n/a"


def es_lookup(client: Any, index: str, doc_id: str) -> dict[str, Any]:
    """Return a document by id, or {} when it is absent."""
    try:
        return client.get(index=index, id=doc_id).get("_source", {})
    except Exception:
        return {}


def collect_targets(args: argparse.Namespace, client: Any) -> list[Target]:
    """Gather the posts to scrape from whichever source is configured."""
    if args.source == "mail":
        targets, _ = mail_targets(args)
    else:
        targets = read_targets(args.input)
    if not args.no_es_skip:
        targets = drop_already_filled(client, args.es_index, targets)
    return targets


def run_mail_scrape(
    page: Page, args: argparse.Namespace, sink: Any, capture: Any,
) -> int:
    """Parse the mailbox in small IMAP batches and scrape each batch immediately.

    Loading every body before the first dashboard page is what looked like a
    hang on --backfill (289 messages, minutes of silence after 'Found N').
    """
    uids = mail_search_uids(args)
    log.info("Found %d alert email(s) from '%s'", len(uids), args.mail_from)
    if not uids:
        log.info("Nothing to scrape")
        return EXIT_OK
    log.info(
        "Will read %d emails at a time, then scrape that batch, so the first "
        "post starts after one IMAP fetch instead of after the whole mailbox",
        MAIL_PARSE_BATCH,
    )
    done = read_done_urls(args.output) if args.resume else set()
    if done:
        log.info("Resuming: %d URLs already in %s", len(done), args.output)
    seen = set(done)
    client = getattr(sink, "client", None)
    ok = failed = scraped = 0
    append = bool(done) and args.output.is_file()
    cap = args.max_per_run or 0
    for start in range(0, len(uids), MAIL_PARSE_BATCH):
        chunk = uids[start:start + MAIL_PARSE_BATCH]
        log.info("Mail %d–%d of %d", start + 1, start + len(chunk), len(uids))
        batch, _ = parse_mail_uids(args, chunk)
        if not args.no_es_skip:
            batch = drop_already_filled(client, args.es_index, batch)
        batch = [t for t in batch if t.url not in seen]
        for target in batch:
            seen.add(target.url)
        if cap:
            room = cap - scraped
            if room <= 0:
                break
            batch = batch[:room]
        if not batch:
            continue
        if scraped == 0:
            announce_pace(batch, args)
        try:
            b_ok, b_fail = process(
                page, batch, args,
                append=append or scraped > 0,
                sink=sink, capture=capture,
            )
        except SessionExpired as exc:
            log.error("%s, re-run with --login", exc)
            return EXIT_LOGIN_REQUIRED
        append = True
        ok += b_ok
        failed += b_fail
        scraped += len(batch)
        if cap and scraped >= cap:
            break
    log.info(
        "Wrote %d rows to %s (%d with a source URL, %d without)",
        ok + failed, args.output, ok, failed,
    )
    if sink is not None:
        log.info("%s", sink.summary())
    return EXIT_OK


def run(args: argparse.Namespace) -> int:
    """Drive the browser. Returns an exit code."""
    if args.backfill:
        args.source = "mail"
        args.resume = True
        args.safe = True
    apply_safe_pace(args)
    if args.verify_mapping:
        return verify_mapping(args)
    if args.mail_inspect:
        return mail_diagnostics(args)
    if args.source == "file" and not (args.login or args.watch):
        if not read_targets(args.input):
            return EXIT_ERROR
    # Fail on a mismatched CSV now rather than after logging in.
    if args.resume or args.watch:
        check_csv_header(args.output)
    args.profile.mkdir(parents=True, exist_ok=True)

    with profile_lock(args.profile), sync_playwright() as player:
        context = launch_context(player, args)
        context.set_default_timeout(args.timeout * 1000)
        page = context.pages[0] if context.pages else context.new_page()
        try:
            page = ensure_session(context, page, args)
            if args.login:
                log.info("Session saved to %s", args.profile)
                return EXIT_OK
            sink = build_sink(args)
            if args.watch:
                return watch(context, page, args, sink)
            capture = PostApiCapture(page)
            if args.source == "mail":
                return run_mail_scrape(page, args, sink, capture)
            targets = collect_targets(args, getattr(sink, "client", None))
            done = read_done_urls(args.output) if args.resume else set()
            if done:
                log.info("Resuming: %d URLs already in %s", len(done), args.output)
                targets = [t for t in targets if t.url not in done]
            if args.max_per_run:
                targets = targets[:args.max_per_run]
            if not targets:
                log.info("Nothing left to scrape")
                return EXIT_OK
            announce_pace(targets, args)
            try:
                ok, failed = process(
                    page, targets, args, append=bool(done),
                    sink=sink, capture=capture,
                )
            except SessionExpired as exc:
                log.error("%s, re-run with --login", exc)
                return EXIT_LOGIN_REQUIRED
            log.info(
                "Wrote %d rows to %s (%d with a source URL, %d without)",
                ok + failed, args.output, ok, failed,
            )
            if sink is not None:
                log.info("%s", sink.summary())
        finally:
            try:
                context.close()
            except Exception:
                pass
    return EXIT_OK


def build_sink(args: argparse.Namespace) -> Any:
    """Build the Elasticsearch writer, or None when no cluster is configured."""
    if not args.es_url:
        if args.es_write:
            log.error("--es-write needs --es-url (or ES_URL in .env)")
        return None
    import falconfeeds_es as es

    client = es_client(args)
    if args.es_write:
        log.warning("Elasticsearch writing is ENABLED, %s will be modified",
                    args.es_index)
    else:
        log.info("Elasticsearch writing is off; updates will only be logged")
    return es.AlertWriter(client, index=args.es_index, enabled=args.es_write)


def announce_pace(targets: Sequence[Target], args: argparse.Namespace) -> None:
    """Log how long the run should take, so a big backfill is not a surprise."""
    per_post = args.delay + (args.jitter / 2) + 8.0
    if args.cooldown_every:
        per_post += args.cooldown / args.cooldown_every
    minutes = len(targets) * per_post / 60
    if minutes < 5:
        return
    shape = f"{minutes / 60:.1f} hours" if minutes > 90 else f"{minutes:.0f} minutes"
    log.info("%d post(s) at ~%.0fs each: roughly %s. Ctrl-C is safe, rows are "
             "flushed as they go and --resume picks up where it stopped.",
             len(targets), per_post, shape)


def main() -> int:
    """CLI entry point. Returns exit code."""
    args = parse_args()
    apply_env_credentials(args)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    try:
        return run(args)
    except LoginRequired as exc:
        log.error("%s", exc)
        log.error("Run once with a terminal attached: falconfeeds_scraper.py --login")
        return EXIT_LOGIN_REQUIRED
    except RuntimeError as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        log.warning("Interrupted")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
