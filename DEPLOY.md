# VEXIS Deployment Guide

## Railway (recommended — fastest path to public URL)

Railway deploys each service separately. Total time: ~10 minutes.

### 1. Install Railway CLI

```bash
npm install -g @railway/cli
railway login
```

### 2. Create project

```bash
railway init  # from repo root — creates a new Railway project
```

### 3. Add database and cache

In the Railway dashboard (or CLI):

```bash
railway add postgres   # provisions Railway Postgres
railway add redis      # provisions Railway Redis
```

Railway automatically sets `DATABASE_URL` and `REDIS_URL` environment variables.

### 4. Deploy the backend

```bash
cd backend
railway up --service vexis-api
```

Set environment variables in the Railway dashboard → vexis-api → Variables:
```
GOOGLE_API_KEY=<your Gemini key>
ANTHROPIC_API_KEY=<your Claude key>   # optional fallback
DATABASE_URL=<auto-set by Railway Postgres plugin>
REDIS_URL=<auto-set by Railway Redis plugin>
VEXIS_LOG_LEVEL=INFO

# Auth (GitHub OAuth)
GITHUB_CLIENT_ID=<your GitHub OAuth App client ID>
GITHUB_CLIENT_SECRET=<your GitHub OAuth App client secret>
JWT_SECRET=<random 32+ char string>

# CORS — comma-separated list of allowed frontend origins
CORS_ORIGINS=["https://your-frontend.up.railway.app"]

# Object storage — see "Storage options" section below
MINIO_ENDPOINT=<see below>
MINIO_ACCESS_KEY=<see below>
MINIO_SECRET_KEY=<see below>
MINIO_SECURE=true
```

Note the deployed API URL (e.g., `https://vexis-api-production.up.railway.app`).

### 5. Deploy the frontend

```bash
cd ../frontend
railway up --service vexis-frontend
```

Set environment variables:
```
NEXT_PUBLIC_API_URL=https://vexis-api-production.up.railway.app
NEXT_PUBLIC_WS_URL=wss://vexis-api-production.up.railway.app
```

> **Note:** `NEXT_PUBLIC_*` variables must be set before the build runs — they're baked into the Next.js bundle. After setting them, trigger a redeploy.

### 6. Verify

```bash
# Health check
curl https://vexis-api-production.up.railway.app/health

# Run a test scan
curl -s -X POST https://vexis-api-production.up.railway.app/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"source_type": "raw_code", "source": "from flask import request\nimport sqlite3\ndef search():\n    q = request.args.get(\"q\")\n    db = sqlite3.connect(\"app.db\")\n    db.execute(f\"SELECT * FROM items WHERE name = '\"'\"'{q}'\"'\"'\")\n"}' \
  | python3 -m json.tool
```

---

## Fly.io (alternative)

### 1. Install flyctl

```bash
curl -L https://fly.io/install.sh | sh
fly auth login
```

### 2. Launch the backend

```bash
cd backend
fly launch --name vexis-api --region ord --no-deploy
fly postgres create --name vexis-db --region ord
fly postgres attach vexis-db --app vexis-api
fly redis create --name vexis-redis --region ord
# Note the redis URL from output
fly secrets set GOOGLE_API_KEY=<key> REDIS_URL=<redis-url>
fly deploy
```

### 3. Launch the frontend

```bash
cd ../frontend
fly launch --name vexis-frontend --region ord --no-deploy
fly secrets set \
  NEXT_PUBLIC_API_URL=https://vexis-api.fly.dev \
  NEXT_PUBLIC_WS_URL=wss://vexis-api.fly.dev
fly deploy
```

---

## Storage options

VEXIS uses MinIO-compatible object storage for code snapshots, scan artifacts, and PDF
report caching. MinIO's SDK speaks S3, so any S3-compatible provider works.

### Option A — Railway MinIO plugin (simplest)

```bash
railway add minio   # provisions a MinIO instance inside your project
```

Railway sets `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, and `MINIO_SECRET_KEY` automatically.
Set `MINIO_SECURE=false` (Railway handles TLS at the edge).

### Option B — Cloudflare R2 (generous free tier, no egress fees)

1. Create an R2 bucket in the Cloudflare dashboard.
2. Create an R2 API token (S3-compatible).
3. Set env vars:

```
MINIO_ENDPOINT=<account-id>.r2.cloudflarestorage.com
MINIO_ACCESS_KEY=<R2 access key ID>
MINIO_SECRET_KEY=<R2 secret>
MINIO_SECURE=true
```

### Option C — AWS S3

```
MINIO_ENDPOINT=s3.amazonaws.com
MINIO_ACCESS_KEY=<AWS access key>
MINIO_SECRET_KEY=<AWS secret>
MINIO_SECURE=true
```

> **Note:** Storage failures are non-fatal — VEXIS logs a warning and continues. PDF reports
> are still generated on demand; they just won't be cached between requests.

---

## Environment variable reference

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string (asyncpg format) |
| `REDIS_URL` | Yes | Redis connection URL |
| `GOOGLE_API_KEY` | Recommended | Gemini API key (primary LLM) |
| `ANTHROPIC_API_KEY` | Optional | Claude fallback |
| `OLLAMA_BASE_URL` | Optional | Local LLM (not useful in cloud) |
| `NEXT_PUBLIC_API_URL` | Yes (frontend) | Backend HTTP URL |
| `NEXT_PUBLIC_WS_URL` | Yes (frontend) | Backend WebSocket URL (wss:// in prod) |
| `GITHUB_CLIENT_ID` | Optional | GitHub OAuth App client ID (enables login) |
| `GITHUB_CLIENT_SECRET` | Optional | GitHub OAuth App client secret |
| `JWT_SECRET` | Recommended | Secret key for JWT signing (random 32+ chars) |
| `JWT_EXPIRE_MINUTES` | Optional | JWT TTL in minutes (default: 10080 = 7 days) |
| `CORS_ORIGINS` | Optional | JSON array of allowed frontend origins |
| `MINIO_ENDPOINT` | Optional | S3-compatible storage endpoint |
| `MINIO_ACCESS_KEY` | Optional | Storage access key |
| `MINIO_SECRET_KEY` | Optional | Storage secret key |
| `MINIO_SECURE` | Optional | Use TLS for storage connection (default: false) |

---

## Database migrations

Migrations run automatically on startup via the Railway `startCommand`:

```
uv run alembic upgrade head && uv run uvicorn app.main:app ...
```

To run manually:

```bash
DATABASE_URL=<your-url> uv run alembic upgrade head
```
