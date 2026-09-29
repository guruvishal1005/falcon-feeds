# FalconFeeds source URL scraper

Reads FalconFeeds ALERT emails over IMAP, opens each post on the dashboard,
and writes `source_url` plus a re-hosted screenshot URL to CSV. With
`--es-write` it also updates those fields on the matching Elasticsearch
document.

The dashboard is an Angular SPA behind Cloudflare, so the scraper drives
Chromium via Playwright. The session lives in a persistent browser profile.
When it lapses, it logs back in from `.env`.

CSV columns: `input_url`, `source_url`, `screenshot_url`, `post_id`, `es_id`.

## Setup

```bash
cp .env.example .env && chmod 600 .env
```

Always set: `FALCONFEEDS_EMAIL`, `FALCONFEEDS_PASSWORD`, `IMAP_USER`,
`IMAP_PASSWORD`. Gmail needs an App Password, not your normal password.

`AZURE_BLOB_SAS_URL` re-hosts screenshots. Without it the CSV keeps FalconFeeds
image URLs, which need a dashboard token to fetch.

`docker compose` injects `.env` into the container. Do not bind-mount it: mode
`600` is unreadable to the image user. If `docker compose` cannot write
`./data`, set `user:` in `docker-compose.yml` to your host uid/gid.

## Production

Use this path when you have a **valid FalconFeeds account**, the **ingest
mailbox** (the one the pipeline reads, not a forwarded copy), and an
Elasticsearch user that can **read and write** `df_breaches`.

`--es-write` is the only flag that changes the cluster. Do not pass it until
step 4 prints `PASS`. `docker compose up -d` does **not** include `--es-write`;
pass it on the command, or add it to the compose `command`.

### 1. Fill `.env` for prod

Uncomment and set:

- `ES_URL`, `ES_INDEX=df_breaches`, `ES_USER`, `ES_PASSWORD`
- `ES_CA_CERT` if you have the cluster CA, otherwise `ES_INSECURE=1`
- `IMAP_HOST` / `IMAP_FOLDER` if the ingest box is not Gmail `INBOX`
  (`[Gmail]/All Mail` includes archived alerts)

If the CA file lives on the host, mount it in `docker-compose.yml` as
`/data/ca.pem` and set `ES_CA_CERT=/data/ca.pem`.

### 2. Build and log in

```bash
docker compose build
docker compose run --rm scraper --login
```

### 3. Confirm mail parses

```bash
docker compose run --rm scraper --mail-inspect 5
```

Each alert should show a `post url` of
`https://dash.falconfeeds.io/threat-feed/posts/POST-…` and an `es _id` of
`FALCON_<Message-ID>`.

### 4. Confirm this mailbox feeds the index

```bash
docker compose run --rm scraper --verify-mapping
```

Stop if this is not `PASS`. `WRONG MAILBOX` or `NO OVERLAP` means Message-IDs
will not match document `_id`s; `--es-write` would miss or update the wrong
records. A copy inbox (including a personal Gmail of the same alerts) always
fails here.

### 5. Smoke one post, Elasticsearch dry-run

```bash
docker compose run --rm scraper --mail-limit 1 --max-per-run 1
```

Check `data/source_urls.csv`. Logs should say writing is off.

### 6. Smoke one post, actually write Elasticsearch

```bash
docker compose run --rm scraper --mail-limit 1 --max-per-run 1 --es-write
```

Confirm that document in `df_breaches` now has `source_url` and `screenshot`.

### 7. Backfill history

One long run. Safe pace (8–11s between posts, rest every 20). Skips CSV rows
already present and docs that already have `source_url`. Ctrl-C is safe; run
the same command again to resume. Tens of thousands of alerts take days.

```bash
docker compose run --rm scraper --backfill --es-write
```

### 8. Watch for new mail

Do not start another backfill. New alerts are `--watch` only.

```bash
docker compose run --rm -d scraper --watch --safe --es-write
```

Or set `command: ["--watch", "--safe", "--es-write"]` in `docker-compose.yml`
and run `docker compose up -d`.

Docs that already have `source_url` are skipped unless you pass `--no-es-skip`.

## Local venv (dev / this machine)

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python falconfeeds_scraper.py --login
.venv/bin/python falconfeeds_scraper.py --mail-limit 3 --headless
.venv/bin/python falconfeeds_scraper.py --backfill --headless
```

`--source file -i urls.txt` still works for a one-off list of post URLs.
Add the same `--es-write` / `--verify-mapping` flags as above once prod
credentials are in `.env`.

## Session

1. Reuse the saved profile.
2. If that is gone, log in at `/auth` (Turnstile is usually silent).
3. Otherwise prompt a human, unless `--no-interactive` / Docker.
4. Exit `2` if nobody can log in.

`--watch` keeps one browser open and reloads the dashboard every
`--keepalive-minutes` while idle.

## Exit codes

- `0` success
- `1` error
- `2` login required
- `130` interrupted

Rows are flushed per post. `--resume` / `--backfill` skip URLs already in the CSV.

See [HOW_IT_WORKS.md](HOW_IT_WORKS.md) for the mail → post → blob path in detail.
