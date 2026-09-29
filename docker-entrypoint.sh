#!/bin/sh
set -e
exec python falconfeeds_scraper.py \
  --headless \
  --no-interactive \
  --channel "" \
  --profile "${FF_PROFILE:-/data/profile}" \
  --output "${FF_OUTPUT:-/data/source_urls.csv}" \
  --state-file "${FF_STATE:-/data/falconfeeds.state.json}" \
  "$@"
