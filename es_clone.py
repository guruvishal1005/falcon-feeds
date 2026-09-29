#!/usr/bin/env python
"""Clone an index from a remote ES cluster to a local ES cluster."""
from __future__ import annotations

import argparse
import logging
import sys
import time
from typing import Any

from elasticsearch import Elasticsearch, helpers

log = logging.getLogger("es-clone")


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Clone an index from a remote ES cluster to a local ES cluster",
    )
    src = parser.add_argument_group("source Elasticsearch")
    src.add_argument(
        "--src-url",
        required=True,
        help="Source ES URL (e.g. https://remote-es:9200)",
    )
    src.add_argument(
        "--src-user",
        default="",
        help="Source ES username (default: no auth)",
    )
    src.add_argument(
        "--src-password",
        default="",
        help="Source ES password",
    )
    src.add_argument(
        "--src-ca-cert",
        default=None,
        help="Source CA certificate path",
    )
    src.add_argument(
        "--src-client-cert",
        default=None,
        help="Source client certificate path",
    )
    src.add_argument(
        "--src-client-key",
        default=None,
        help="Source client key path",
    )
    dest = parser.add_argument_group("destination Elasticsearch")
    dest.add_argument(
        "--dest-url",
        default="http://localhost:9200",
        help="Destination ES URL (default: http://localhost:9200)",
    )
    opts = parser.add_argument_group("clone options")
    opts.add_argument(
        "--index",
        required=True,
        help="Index name to clone",
    )
    opts.add_argument(
        "--batch-size",
        type=int,
        default=10_000,
        help="Bulk insert batch size (default: 10000)",
    )
    opts.add_argument(
        "--delete-dest",
        action="store_true",
        help="Delete destination index before cloning",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Request timeout in seconds (default: 300)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def connect_es(
    url: str,
    user: str = "",
    password: str = "",
    ca_cert: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    timeout: int = 300,
) -> Elasticsearch:
    """Connect to an Elasticsearch cluster and return the client.

    Logs cluster name and version on success.
    Raises SystemExit on failure.
    """
    kwargs: dict[str, Any] = {
        "hosts": [url],
        "timeout": timeout,
    }
    if user and password:
        kwargs["http_auth"] = (user, password)
    if ca_cert:
        kwargs["verify_certs"] = True
        kwargs["use_ssl"] = url.startswith("https")
        kwargs["ca_certs"] = ca_cert
        if client_cert:
            kwargs["client_cert"] = client_cert
        if client_key:
            kwargs["client_key"] = client_key
    elif url.startswith("https"):
        kwargs["verify_certs"] = True
        kwargs["use_ssl"] = True
    client = Elasticsearch(**kwargs)
    if not client.ping():
        log.error("Cannot connect to ES at %s", url)
        sys.exit(1)
    info = client.info()
    log.info(
        "Connected to %s (cluster: %s, version: %s)",
        url,
        info["cluster_name"],
        info["version"]["number"],
    )
    return client


_MIGRATION_FIELDS = frozenset({"migration_state", "worker_id", "migration_error"})


def generate_actions(
    docs: Any,
    index: str,
) -> dict[str, Any]:
    """Yield bulk actions from a scan result."""
    for doc in docs:
        source = {
            k: v for k, v in doc["_source"].items()
            if k not in _MIGRATION_FIELDS
        }
        yield {
            "_index": index,
            "_id": doc["_id"],
            "_source": source,
        }


def clone_index(args: argparse.Namespace) -> int:
    """Clone the index from source to destination. Returns exit code."""
    start = time.monotonic()
    log.info("Connecting to source: %s", args.src_url)
    src = connect_es(
        args.src_url,
        user=args.src_user,
        password=args.src_password,
        ca_cert=args.src_ca_cert,
        client_cert=args.src_client_cert,
        client_key=args.src_client_key,
        timeout=args.timeout,
    )
    log.info("Connecting to destination: %s", args.dest_url)
    dest = connect_es(args.dest_url, timeout=args.timeout)
    try:
        if not src.indices.exists(index=args.index):
            log.error("Index not found on source: %s", args.index)
            return 1
    except Exception as exc:
        log.warning("Cannot verify index existence (may still work): %s", exc)
    try:
        doc_count = src.count(index=args.index)["count"]
    except Exception as exc:
        log.warning("Cannot count docs (may still work): %s", exc)
        doc_count = 0
    log.info("Source doc count: %d", doc_count)
    if args.delete_dest:
        if dest.indices.exists(index=args.index):
            log.info("Deleting destination index: %s", args.index)
            dest.indices.delete(index=args.index)
        else:
            log.info("Destination index does not exist, skipping delete")
    log.info(
        "Cloning index: %s (batch_size=%d)",
        args.index,
        args.batch_size,
    )
    src_docs = helpers.scan(
        src,
        index=args.index,
        size=args.batch_size,
    )
    success_count = 0
    error_count = 0
    last_log_time = time.monotonic()

    def actions_with_progress():
        nonlocal success_count, last_log_time
        for action in generate_actions(src_docs, args.index):
            success_count += 1
            now = time.monotonic()
            if now - last_log_time >= 10:
                pct = (success_count / doc_count * 100) if doc_count > 0 else 0
                log.info(
                    "Progress: %d / %d docs (%.1f%%)",
                    success_count,
                    doc_count,
                    pct,
                )
                last_log_time = now
            yield action

    try:
        bulk_success, errors = helpers.bulk(
            dest,
            actions_with_progress(),
            raise_on_error=False,
            raise_on_exception=False,
            stats_only=False,
            chunk_size=args.batch_size,
        )
        if errors:
            error_count = len(errors)
            log.warning("Encountered %d bulk errors", error_count)
            if args.verbose:
                for err in errors[:10]:  # Log first 10 errors
                    log.debug("  Error: %s", err)
                if len(errors) > 10:
                    log.debug("  ... and %d more", len(errors) - 10)
    except Exception as exc:
        log.error("Clone failed: %s", exc)
        return 1
    elapsed = time.monotonic() - start
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    log.info(
        "Clone complete: %d docs indexed, %d errors",
        bulk_success,
        error_count,
    )
    log.info("Duration: %dm %ds", minutes, seconds)
    return 1 if error_count > 0 else 0


def main() -> int:
    """CLI entry point. Returns exit code."""
    args = parse_args()
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    return clone_index(args)


if __name__ == "__main__":
    sys.exit(main())
