#!/usr/bin/env bash
# TenantCheck 365 — start the web app (Python standard library only).
set -e
cd "$(dirname "$0")"
# If a persistent disk is mounted at /var/data (Render), use it for app data
# so founding signups and scan records survive restarts and redeploys.
if [ -d /var/data ] && [ ! -L data ]; then
  cp -n data/*.json /var/data/ 2>/dev/null || true
  rm -rf data
  ln -s /var/data data
fi
export PORT="${PORT:-8795}"
export HOST="${HOST:-127.0.0.1}"
exec python3 app.py
