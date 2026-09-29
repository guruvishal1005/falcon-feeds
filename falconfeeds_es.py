#!/usr/bin/env python
"""Elasticsearch side of the FalconFeeds pipeline.

Two jobs: look up which alerts already carry a source URL so they can be
skipped, and write a scraped source URL back onto its document.

Writing is off unless it is explicitly enabled. The account in use today is
read-only, so every write path defaults to a dry run that logs the update it
would have made and touches nothing.

Works with both the 7.x and 8.x Python clients, since the cluster is 7.10 and
the two client majors disagree about keyword arguments.
"""
from __future__ import annotations

import logging
from typing import Any, Sequence

log = logging.getLogger("ff-es")

DEFAULT_INDEX = "df_breaches"
SOURCE_FIELD = "source_url"
SCREENSHOT_FIELD = "screenshot"
ALERT_SOURCE = "falcon_feed"


class EsError(RuntimeError):
    """Raised when Elasticsearch cannot be reached or refuses a request."""


def client_major() -> int:
    """Return the installed elasticsearch client's major version."""
    import elasticsearch

    version = getattr(elasticsearch, "VERSION", None) or getattr(
        elasticsearch, "__version__", None
    )
    try:
        return int(version[0])
    except (TypeError, ValueError, IndexError):
        return 8


def connect(
    url: str,
    user: str = "",
    password: str = "",
    ca_cert: str = "",
    insecure: bool = False,
    timeout: int = 30,
) -> Any:
    """Open an Elasticsearch connection, papering over 7.x/8.x differences."""
    import elasticsearch

    major = client_major()
    kwargs: dict[str, Any] = {"hosts": [url]}
    if user:
        key = "http_auth" if major < 8 else "basic_auth"
        kwargs[key] = (user, password)
    kwargs["timeout" if major < 8 else "request_timeout"] = timeout
    if url.lower().startswith("https"):
        if ca_cert:
            kwargs["ca_certs"] = ca_cert
        if insecure:
            kwargs["verify_certs"] = False
            if major < 8:
                kwargs["ssl_show_warn"] = False
    try:
        client = elasticsearch.Elasticsearch(**kwargs)
        info = client.info()
    except Exception as exc:  # the client raises a wide variety of types
        raise EsError(f"cannot connect to {url}: {exc}") from exc
    version = (info.get("version") or {}).get("number", "?")
    log.info("Connected to Elasticsearch %s (client %d.x)", version, major)
    return client


def existing_source_urls(
    client: Any, index: str, ids: Sequence[str]
) -> dict[str, str]:
    """Return {doc id: source_url} for the ids that exist and have one set.

    Ids that are missing from the index, or whose source_url is null, are
    simply absent from the result.
    """
    if not ids:
        return {}
    try:
        response = client.mget(index=index, body={"ids": list(ids)})
    except TypeError:
        response = client.mget(index=index, ids=list(ids))
    except Exception as exc:
        raise EsError(f"mget failed on {index}: {exc}") from exc
    found: dict[str, str] = {}
    for doc in response.get("docs", []):
        if not doc.get("found"):
            continue
        value = (doc.get("_source") or {}).get(SOURCE_FIELD)
        if isinstance(value, str) and value.strip():
            found[doc["_id"]] = value.strip()
    return found


def missing_ids(client: Any, index: str, ids: Sequence[str]) -> list[str]:
    """Return the ids that do not exist in the index at all."""
    if not ids:
        return []
    try:
        response = client.mget(index=index, body={"ids": list(ids)})
    except TypeError:
        response = client.mget(index=index, ids=list(ids))
    return [doc["_id"] for doc in response.get("docs", []) if not doc.get("found")]


def candidates_near(
    client: Any,
    index: str,
    when: str,
    window: str = "10s",
    source: str = ALERT_SOURCE,
    size: int = 5,
) -> list[dict[str, Any]]:
    """Return alerts published within `window` of a timestamp.

    Used to tell "this alert is not in the index" apart from "this alert is
    in the index but under a different id", which is what a mailbox mismatch
    looks like.
    """
    body = {
        "query": {"bool": {"filter": [
            {"term": {"source": source}},
            {"range": {"published_date": {
                "gte": f"{when}||-{window}", "lte": f"{when}||+{window}"}}},
        ]}},
        "size": size,
        "_source": ["entity", "published_date", "threat_actor"],
    }
    try:
        response = client.search(index=index, body=body)
    except TypeError:
        response = client.search(index=index, **body)
    return response.get("hits", {}).get("hits", [])


class AlertWriter:
    """Writes scraped values back onto their alert documents.

    Defaults to a dry run. Nothing reaches the cluster until `enabled` is
    True, which the CLI only sets when --es-write is passed.
    """

    def __init__(
        self,
        client: Any,
        index: str = DEFAULT_INDEX,
        enabled: bool = False,
        extra_fields: Sequence[str] = (SCREENSHOT_FIELD,),
    ) -> None:
        self.client = client
        self.index = index
        self.enabled = enabled
        self.extra_fields = tuple(extra_fields)
        self.written = 0
        self.pending = 0
        self.skipped = 0
        self.missing = 0
        self.failed = 0

    def update(self, doc_id: str, source_url: str, **extra: str) -> bool:
        """Set source_url on one document. Returns True if it was written."""
        if not doc_id or not source_url:
            self.skipped += 1
            return False
        doc: dict[str, str] = {SOURCE_FIELD: source_url}
        for key in self.extra_fields:
            value = extra.get(key, "")
            if value:
                doc[key] = value
        if not self.enabled:
            log.info("[dry run] would set %s on %s to %s",
                     ", ".join(doc), doc_id, " | ".join(doc.values()))
            self.pending += 1
            return False
        try:
            try:
                self.client.update(index=self.index, id=doc_id, body={"doc": doc})
            except TypeError:
                self.client.update(index=self.index, id=doc_id, doc=doc)
        except Exception as exc:
            self.failed += 1
            log.error("Update failed for %s: %s", doc_id, exc)
            return False
        self.written += 1
        log.debug("Updated %s", doc_id)
        return True

    def summary(self) -> str:
        """One-line tally suitable for the end of a run."""
        if not self.enabled:
            return (
                f"Elasticsearch dry run: {self.pending} document(s) would be "
                f"updated, {self.skipped} had nothing to write. "
                "Pass --es-write to apply."
            )
        return (
            f"Elasticsearch: updated {self.written} document(s), "
            f"{self.skipped} skipped, {self.failed} failed"
        )
