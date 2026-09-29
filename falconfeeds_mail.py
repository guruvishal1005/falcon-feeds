#!/usr/bin/env python
"""Read FalconFeeds alert emails over IMAP and pull the post links out of them.

The Message-ID of each alert is the join key back to Elasticsearch, which
stores the alert under the id "FALCON_<message-id>". That makes the mapping
from an email to its database record exact rather than inferred.

The mailbox is always opened read-only and bodies are fetched with
BODY.PEEK, so nothing here marks mail as read or alters a flag.
"""
from __future__ import annotations

import email
import email.header
import html
import imaplib
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import Message
from email.utils import parsedate_to_datetime
from typing import Iterator, Sequence

log = logging.getLogger("ff-mail")

ES_ID_PREFIX = "FALCON_"

POST_URL_RE = re.compile(
    r"https?://[^\s\"'<>]*?dash\.falconfeeds\.io/threat-feed/posts/(POST-[0-9A-Za-z]+)",
    re.IGNORECASE,
)
POST_ID_RE = re.compile(r"POST-[0-9A-Za-z]{8,}")
HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
BARE_URL_RE = re.compile(r"""https?://[^\s<>"'\)\]]+""")
UID_RE = re.compile(rb"UID\s+(\d+)")

# SendGrid and friends rewrite every link for click tracking, which hides the
# real post URL behind a redirect that has to be followed to be read.
TRACKING_HINTS = (
    "sendgrid.net",
    "sendgrid.com",
    "/ls/click",
    "/wf/click",
    "list-manage.com",
    "mailgun.org",
    "mandrillapp.com",
    "sparkpostmail",
    "amazonses.com",
    "url9149.falconfeeds.io",
)

POST_URL_TEMPLATE = "https://dash.falconfeeds.io/threat-feed/posts/{post_id}"

# Welcome mail, OTP, newsletters: same From: as alerts, no post link, but full of
# SendGrid click trackers. Following those is what made `--source mail --resume`
# look hung after the "No post link" warnings.
NON_ALERT_SUBJECT_RE = re.compile(
    r"verification code|welcome to falconfeeds|one step ahead of the game|"
    r"unsubscribe|password reset|confirm your (email|account)|newsletter|"
    r"you.?re invited",
    re.IGNORECASE,
)
ALERT_SUBJECT_RE = re.compile(r"^\s*alert\b", re.IGNORECASE)
CTA_TEXT_RE = re.compile(
    r"read\s*more|view\s+(the\s+)?(full\s+)?post|view\s+(full\s+)?alert|"
    r"open\s+post|see\s+(full\s+)?(post|details)",
    re.IGNORECASE,
)
ANCHOR_RE = re.compile(r"<a\b([^>]*)>(.*?)</a>", re.IGNORECASE | re.DOTALL)
HREF_ATTR_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

IMAP_MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)


class MailError(RuntimeError):
    """Raised when the mailbox cannot be read."""


@dataclass
class MailAlert:
    """One FalconFeeds alert email and the links found inside it."""

    uid: int
    message_id: str
    subject: str
    sent_at: str
    post_urls: list[str] = field(default_factory=list)
    tracking_urls: list[str] = field(default_factory=list)
    other_urls: list[str] = field(default_factory=list)
    cta_urls: list[str] = field(default_factory=list)

    @property
    def es_id(self) -> str:
        """The Elasticsearch _id this alert is stored under, or ''."""
        return es_id_for(self.message_id)

    @property
    def post_url(self) -> str:
        """The first dashboard post URL found in the email, or ''."""
        return self.post_urls[0] if self.post_urls else ""


def es_id_for(message_id: str) -> str:
    """Map a Message-ID header to the Elasticsearch document id.

    Documents are keyed as FALCON_<message-id>, angle brackets included.
    """
    value = (message_id or "").strip()
    if not value:
        return ""
    if not value.startswith("<"):
        value = f"<{value}>"
    return ES_ID_PREFIX + value


def imap_date(value: str) -> str:
    """Convert YYYY-MM-DD (or an already-IMAP date) to IMAP's DD-MMM-YYYY."""
    text = (value or "").strip()
    if not text:
        return ""
    try:
        parsed = datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        return text
    return f"{parsed.day:02d}-{IMAP_MONTHS[parsed.month - 1]}-{parsed.year}"


def connect(host: str, port: int, user: str, password: str,
            quiet: bool = False) -> imaplib.IMAP4_SSL:
    """Open an authenticated IMAP connection."""
    if not quiet:
        log.info("Connecting to %s:%d as %s", host, port, user)
    else:
        log.debug("Connecting to %s:%d as %s", host, port, user)
    try:
        conn = imaplib.IMAP4_SSL(host, port)
    except OSError as exc:
        raise MailError(f"cannot reach {host}:{port}: {exc}") from exc
    try:
        conn.login(user, password)
    except imaplib.IMAP4.error as exc:
        hint = ""
        if "gmail" in host.lower():
            hint = " (Gmail needs an App Password, not your normal password)"
        raise MailError(f"login failed for {user}{hint}: {exc}") from exc
    return conn


def select_folder(conn: imaplib.IMAP4_SSL, folder: str) -> int:
    """Select a mailbox read-only and return how many messages it holds."""
    typ, data = conn.select(f'"{folder}"', readonly=True)
    if typ != "OK":
        raise MailError(f"cannot open folder {folder!r}: {_first(data)}")
    return int(_first(data) or 0)


def search_uids(
    conn: imaplib.IMAP4_SSL,
    sender: str = "",
    since: str = "",
    before: str = "",
    subject: str = "",
) -> list[int]:
    """Return the UIDs of messages matching the given criteria, oldest first."""
    criteria: list[str] = []
    if sender:
        criteria += ["FROM", f'"{sender}"']
    if subject:
        criteria += ["SUBJECT", f'"{subject}"']
    if since:
        criteria += ["SINCE", imap_date(since)]
    if before:
        criteria += ["BEFORE", imap_date(before)]
    if not criteria:
        criteria = ["ALL"]
    log.debug("IMAP search: %s", " ".join(criteria))
    typ, data = conn.uid("SEARCH", None, *criteria)
    if typ != "OK":
        raise MailError(f"search failed: {_first(data)}")
    raw = _first(data)
    return sorted(int(part) for part in raw.split()) if raw else []


def fetch_messages(
    conn: imaplib.IMAP4_SSL,
    uids: Sequence[int],
    batch: int = 10,
    headers_only: bool = False,
) -> Iterator[tuple[int, Message]]:
    """Yield (uid, message) for each UID, fetched in batches without marking read."""
    what = "BODY.PEEK[HEADER]" if headers_only else "BODY.PEEK[]"
    total = len(uids)
    for start in range(0, total, batch):
        chunk = uids[start:start + batch]
        log.info("IMAP fetch %d–%d of %d", start + 1, start + len(chunk), total)
        typ, data = conn.uid("FETCH", ",".join(str(u) for u in chunk), f"(UID {what})")
        if typ != "OK":
            log.warning("Fetch failed for %d messages, skipping", len(chunk))
            continue
        for item in data:
            if not isinstance(item, tuple) or len(item) < 2:
                continue
            header, payload = item[0], item[1]
            match = UID_RE.search(header if isinstance(header, bytes) else b"")
            uid = int(match.group(1)) if match else 0
            if not isinstance(payload, (bytes, bytearray)):
                continue
            yield uid, email.message_from_bytes(bytes(payload))


def message_bodies(msg: Message) -> tuple[str, str]:
    """Return the (plain text, html) bodies of a message, decoded."""
    texts: list[str] = []
    htmls: list[str] = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if (part.get_content_disposition() or "") == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            text = payload.decode("utf-8", errors="replace")
        (htmls if ctype == "text/html" else texts).append(text)
    return "\n".join(texts), "\n".join(htmls)


def collect_urls(text: str, html_body: str) -> list[str]:
    """Return every URL in the message, hrefs first, de-duplicated in order."""
    found: list[str] = []
    seen: set[str] = set()
    for candidate in HREF_RE.findall(html_body) + BARE_URL_RE.findall(
        html.unescape(html_body)
    ) + BARE_URL_RE.findall(text):
        url = html.unescape(candidate).strip().rstrip(".,;)")
        if not url.lower().startswith("http") or url in seen:
            continue
        seen.add(url)
        found.append(url)
    return found


def is_tracking(url: str) -> bool:
    """Report whether a URL looks like an email click-tracking redirect."""
    lowered = url.lower()
    if "/wf/open" in lowered:
        return False
    return any(hint in lowered for hint in TRACKING_HINTS)


def cta_hrefs(html_body: str) -> list[str]:
    """Return hrefs whose visible text is a CTA like 'Read more'."""
    found: list[str] = []
    seen: set[str] = set()
    for match in ANCHOR_RE.finditer(html_body or ""):
        inner = re.sub(r"<[^>]+>", " ", match.group(2))
        inner = html.unescape(re.sub(r"\s+", " ", inner)).strip()
        if not CTA_TEXT_RE.search(inner):
            continue
        href = HREF_ATTR_RE.search(match.group(1) or "")
        if not href:
            continue
        url = html.unescape(href.group(1)).strip()
        if url.lower().startswith("http") and url not in seen:
            seen.add(url)
            found.append(url)
    return found


def click_trackers(urls: Sequence[str]) -> list[str]:
    """Keep only click-tracking redirects, not open-pixel /ls noise."""
    out = []
    for url in urls:
        lowered = url.lower()
        if "/ls/click" in lowered or "/wf/click" in lowered:
            out.append(url)
    return out


def is_non_alert(alert: MailAlert) -> bool:
    """True for promotional / account mail that will never contain a post link."""
    return bool(NON_ALERT_SUBJECT_RE.search(alert.subject or ""))


def should_follow_tracking(alert: MailAlert) -> bool:
    """Only chase click trackers when this still looks like a threat alert."""
    if alert.post_urls or is_non_alert(alert):
        return False
    if ALERT_SUBJECT_RE.search(alert.subject or ""):
        return True
    return False


def classify_urls(urls: Sequence[str]) -> tuple[list[str], list[str], list[str]]:
    """Split URLs into (dashboard post links, tracking links, everything else)."""
    posts: list[str] = []
    tracking: list[str] = []
    other: list[str] = []
    for url in urls:
        match = POST_URL_RE.search(url)
        if match:
            canonical = POST_URL_TEMPLATE.format(post_id=match.group(1))
            if canonical not in posts:
                posts.append(canonical)
        elif is_tracking(url):
            tracking.append(url)
        else:
            other.append(url)
    return posts, tracking, other


def header(msg: Message, name: str) -> str:
    """Return a decoded header value, or ''."""
    raw = msg.get(name, "")
    if not raw:
        return ""
    try:
        parts = email.header.decode_header(raw)
    except (ValueError, UnicodeDecodeError):
        return str(raw).strip()
    out = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            out.append(chunk.decode(charset or "utf-8", errors="replace"))
        else:
            out.append(chunk)
    return "".join(out).strip()


def sent_at(msg: Message) -> str:
    """Return the message date as an ISO-8601 UTC string, or ''."""
    raw = msg.get("Date", "")
    if not raw:
        return ""
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return str(raw)
    if parsed is None:
        return str(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_alert(uid: int, msg: Message) -> MailAlert:
    """Turn a fetched message into a MailAlert, without following redirects."""
    text, html_body = message_bodies(msg)
    posts, tracking, other = classify_urls(collect_urls(text, html_body))
    if not posts:
        # Some templates print the id as text without ever linking it.
        for match in POST_ID_RE.finditer(f"{text}\n{html_body}"):
            url = POST_URL_TEMPLATE.format(post_id=match.group(0))
            if url not in posts:
                posts.append(url)
    ctas = cta_hrefs(html_body)
    return MailAlert(
        uid=uid,
        message_id=header(msg, "Message-ID"),
        subject=header(msg, "Subject"),
        sent_at=sent_at(msg),
        post_urls=posts,
        tracking_urls=tracking,
        other_urls=other,
        cta_urls=ctas,
    )


def resolve_redirect(url: str, timeout: int = 8) -> str:
    """Follow a tracking link and return where it lands, or '' on failure."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
            )
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.geturl() or ""
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.debug("Could not resolve %s: %s", url[:80], exc)
        return ""


def resolve_post_url(alert: MailAlert, timeout: int = 8, limit: int = 1) -> str:
    """Find the post URL by following the 'Read more' click tracker.

    Older FalconFeeds alerts wrap the dashboard link in SendGrid /ls/click.
    Newer ones also put dash.falconfeeds.io in the HTML; those never reach here.
    """
    if alert.post_urls:
        return alert.post_url
    candidates = click_trackers(alert.cta_urls) or click_trackers(alert.tracking_urls)
    for url in candidates[:limit]:
        landed = resolve_redirect(url, timeout)
        if not landed:
            continue
        in_url = POST_URL_RE.search(landed)
        bare = POST_ID_RE.search(landed)
        post_id = in_url.group(1) if in_url else (bare.group(0) if bare else "")
        if post_id:
            resolved = POST_URL_TEMPLATE.format(post_id=post_id)
            alert.post_urls.append(resolved)
            log.info("Resolved Read more to %s", resolved)
            return resolved
    return ""


def iter_alerts(
    conn: imaplib.IMAP4_SSL,
    uids: Sequence[int],
    batch: int = 25,
    follow_links: bool = True,
    timeout: int = 8,
) -> Iterator[MailAlert]:
    """Yield a parsed MailAlert for every UID, resolving tracking links."""
    for uid, msg in fetch_messages(conn, uids, batch=batch):
        alert = parse_alert(uid, msg)
        if follow_links and not alert.post_urls and should_follow_tracking(alert):
            resolve_post_url(alert, timeout=timeout)
        yield alert


def describe(alert: MailAlert) -> str:
    """Render an alert as a human-readable block for the inspect command."""
    lines = [
        f"uid          {alert.uid}",
        f"date         {alert.sent_at}",
        f"subject      {alert.subject}",
        f"message-id   {alert.message_id}",
        f"es _id       {alert.es_id}",
        f"post url     {alert.post_url or '(none found)'}",
    ]
    if alert.tracking_urls:
        lines.append(f"tracking     {len(alert.tracking_urls)} link(s), "
                     f"first: {alert.tracking_urls[0][:100]}")
    if alert.other_urls:
        shown = ", ".join(url[:70] for url in alert.other_urls[:5])
        lines.append(f"other urls   {shown}")
    return "\n".join("  " + line for line in lines)


def _first(data: Sequence[object]) -> str:
    """Return the first element of an IMAP response as text."""
    if not data:
        return ""
    head = data[0]
    if isinstance(head, bytes):
        return head.decode("utf-8", "replace")
    return str(head or "")
