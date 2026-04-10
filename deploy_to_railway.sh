#!/bin/bash
set -euo pipefail

SERVICE="suna-control"

echo "🚀 Deploying $SERVICE to Railway..."

# Require Railway CLI
if ! command -v railway &> /dev/null; then
  echo "❌ Railway CLI not found."
  echo "   Install: npm i -g @railway/cli"
  exit 1
fi

# Require login
if ! railway whoami &> /dev/null; then
  echo "❌ Not logged in to Railway."
  echo "   Run: railway login"
  exit 1
fi

echo ""
echo "⚠️  Ensure these env vars are set in the Railway dashboard before deploying:"
echo "   SHARED_SECRET              — HMAC secret for agent command signing"
echo "   GITHUB_WEBHOOK_SECRET      — GitHub webhook secret"
echo "   DB_PATH                    — SQLite path (default: control.db)"
echo ""
read -p "Continue? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

# Deploy
railway up --detach

echo ""
echo "✅ Deployed $SERVICE!"
echo "   Status : railway status"
echo "   Logs   : railway logs --tail"
echo "   Health : curl \$(railway domain)/health"
