# How the scraper works

Normal path: IMAP ALERT mail → dashboard post → CSV row + Azure blob screenshot.

## 1. Credentials

`.env` is loaded first. Empty shell variables do not hide file values. Gmail
App Passwords have spaces stripped. `.env` should be mode `600`.

## 2. Mail

The mailbox is opened **read-only** (`BODY.PEEK`). Search is `FROM falconfeeds`
and `SUBJECT ALERT`. UIDs are oldest-first. `--mail-limit` without `--backfill`
takes the newest N; `--backfill` walks all of them.

Bodies are fetched 10 at a time, then that batch is scraped immediately, so
the first post starts after one IMAP fetch.

Post URL extraction, in order:

1. A raw `dash.falconfeeds.io/threat-feed/posts/POST-…` href (newer templates).
2. A bare `POST-…` id in the body.
3. The **Read more** button. Older templates wrap that in SendGrid
   `url9149.falconfeeds.io/ls/click`. That one redirect is followed (~1s).
   Open-pixel `/wf/open` links and welcome/OTP mail are never followed.

`es_id` is `FALCON_` plus the Message-ID, angle brackets included. That only
matches Elasticsearch when the mailbox is the one the ingest pipeline reads.

## 3. Browser session

A lockfile next to the profile directory stops two runs sharing Chrome data.

Inside Docker the browser is bundled Chromium with `--no-sandbox`. On the host
it prefers system Chrome and falls back to Chromium.

Session order: reuse the profile → auto-login at `/auth` (wait for Turnstile)
→ prompt a human if a terminal is attached. Docker always passes
`--no-interactive`, so a missing session exits `2`.

The dashboard often serves an empty shell on first navigation. `open_page`
reloads until `app-post-details` appears.

## 4. Source URL and screenshots

While the post page loads, the scraper captures the JSON from
`https://integrite.tech/falcon/post/POST-…`. That payload has
`meta.publishedURL` and `meta.images`. The Info-card DOM is a fallback for
the URL only. Image tags in the DOM are `blob:` URLs and are ignored.

Screenshot files are fetched with the session bearer token. If
`AZURE_BLOB_SAS_URL` is set they are uploaded as BlockBlob; the CSV stores
the public URL **without** the SAS. Blob names are UUID5 of the FalconFeeds
filename, so re-runs overwrite. Upload failure keeps the FalconFeeds URL.

## 5. CSV

Columns: `input_url,source_url,screenshot_url,post_id,es_id`. Each row is
flushed before the next post. `--resume` skips `input_url` values already
present. `--safe` / `--backfill` wait 8–11s between posts and rest ~60s every 20.

## 6. Elasticsearch (optional)

With `--es-url` and no `--es-write`, updates are logged only. `--es-write`
partial-updates `source_url` and `screenshot` on an existing document. Run
`--verify-mapping` against the ingest mailbox first.

## 7. Docker

`docker-entrypoint.sh` always sets headless Chromium, `/data/profile`,
`/data/source_urls.csv` and `/data/falconfeeds.state.json`. Compose mounts
`./data` and injects `.env` as environment variables (not a bind mount).
Default command is `--watch --safe`.
