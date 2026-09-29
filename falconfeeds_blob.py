#!/usr/bin/env python
"""Re-host FalconFeeds post screenshots in Azure Blob Storage.

FalconFeeds serves screenshots from an authenticated API endpoint, so the URL
on a post is useless to anything without a dashboard token. This downloads the
image with the session's token and uploads it to a blob container, returning a
URL that points at our own storage instead.

Uploads go over plain REST with a container SAS, so there is no Azure SDK
dependency. The SAS grants write only and is a credential: it is never logged,
never put in an error message, and never written to the CSV.
"""
from __future__ import annotations

import logging
import mimetypes
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger("ff-blob")

# Deterministic names: the same FalconFeeds image always maps to the same
# blob, so re-running the scraper overwrites rather than piling up copies.
BLOB_NAMESPACE = uuid.UUID("6f1d5b1e-0c3a-5a1e-9b4e-2f8b7a1c4d55")

DEFAULT_CONTENT_TYPE = "application/octet-stream"
MAX_BYTES = 64 * 1024 * 1024


class BlobError(RuntimeError):
    """Raised when an upload fails. Never contains the SAS token."""


@dataclass
class BlobTarget:
    """A container URL split into its address and its SAS query string."""

    base: str
    query: str

    @classmethod
    def parse(cls, sas_url: str) -> "BlobTarget":
        """Split a container SAS URL into the container address and the token."""
        parts = urllib.parse.urlsplit((sas_url or "").strip())
        if not parts.scheme or not parts.netloc:
            raise BlobError("blob SAS URL is not a valid URL")
        if not parts.query:
            raise BlobError("blob SAS URL has no ?sas query string")
        base = urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path.rstrip("/"), "", "")
        )
        return cls(base=base, query=parts.query)

    def public_url(self, name: str) -> str:
        """The blob's address without the credential, safe to store and log."""
        return f"{self.base}/{urllib.parse.quote(name)}"

    def upload_url(self, name: str) -> str:
        """The blob's address with the SAS attached. Never log this."""
        return f"{self.public_url(name)}?{self.query}"


def source_file_name(image_url: str) -> str:
    """Return the fileName the FalconFeeds image URL refers to."""
    parts = urllib.parse.urlsplit(image_url)
    query = urllib.parse.parse_qs(parts.query)
    name = (query.get("fileName") or [""])[0]
    return name or parts.path.rsplit("/", 1)[-1]


def blob_name(image_url: str) -> str:
    """Build a stable, unique blob name for a FalconFeeds image URL."""
    original = source_file_name(image_url)
    suffix = ""
    if "." in original:
        candidate = original.rsplit(".", 1)[-1]
        if candidate.isalnum() and len(candidate) <= 5:
            suffix = "." + candidate.lower()
    return f"{uuid.uuid5(BLOB_NAMESPACE, original or image_url)}{suffix}"


def content_type_for(name: str, reported: str) -> str:
    """Pick the content type to store the blob under."""
    value = (reported or "").split(";")[0].strip().lower()
    if value and value != DEFAULT_CONTENT_TYPE:
        return value
    guessed, _ = mimetypes.guess_type(name)
    return guessed or DEFAULT_CONTENT_TYPE


def upload(target: BlobTarget, name: str, payload: bytes, content_type: str,
           timeout: int = 60) -> str:
    """PUT one blob and return its credential-free URL."""
    if not payload:
        raise BlobError("refusing to upload an empty image")
    if len(payload) > MAX_BYTES:
        raise BlobError(f"image is {len(payload)} bytes, over the {MAX_BYTES} limit")
    request = urllib.request.Request(
        target.upload_url(name),
        data=payload,
        method="PUT",
        headers={
            "x-ms-blob-type": "BlockBlob",
            "Content-Type": content_type,
        },
    )
    public = target.public_url(name)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status not in (200, 201):
                raise BlobError(f"upload of {name} returned {response.status}")
    except urllib.error.HTTPError as exc:
        raise BlobError(f"upload of {name} failed: {exc.code} "
                        f"{azure_error(exc)}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise BlobError(f"upload of {name} failed: {exc.reason}") from None
    log.debug("Uploaded %s (%d bytes) to %s", name, len(payload), public)
    return public


def azure_error(exc: urllib.error.HTTPError) -> str:
    """Pull Azure's error code out of a failure response, without the URL."""
    try:
        body = exc.read().decode("utf-8", "replace")
    except Exception:
        return exc.reason or ""
    start = body.find("<Code>")
    end = body.find("</Code>")
    if start >= 0 and end > start:
        return body[start + 6:end]
    return (exc.reason or "").strip()


class ImageRelay:
    """Downloads post screenshots and re-hosts them in blob storage.

    `fetch` takes an image URL and returns (bytes, content type). It needs the
    dashboard's bearer token, so it is supplied by the caller that owns the
    browser session.
    """

    def __init__(
        self,
        target: BlobTarget,
        fetch: Callable[[str], tuple[bytes, str]],
        timeout: int = 60,
    ) -> None:
        self.target = target
        self.fetch = fetch
        self.timeout = timeout
        self.uploaded = 0
        self.failed = 0

    def relay_one(self, image_url: str) -> str:
        """Move one image across. Returns the FalconFeeds URL if that fails."""
        name = blob_name(image_url)
        try:
            payload, reported = self.fetch(image_url)
        except Exception as exc:
            self.failed += 1
            log.error("Could not download %s: %s", source_file_name(image_url), exc)
            return image_url
        try:
            public = upload(self.target, name, payload,
                            content_type_for(name, reported), self.timeout)
        except BlobError as exc:
            self.failed += 1
            log.error("%s", exc)
            return image_url
        self.uploaded += 1
        return public

    def relay(self, image_urls: list[str]) -> list[str]:
        """Move a post's images across, preserving order."""
        return [self.relay_one(url) for url in image_urls]

    def summary(self) -> str:
        """One-line tally for the end of a run."""
        return (f"Blob storage: {self.uploaded} image(s) uploaded, "
                f"{self.failed} failed")
