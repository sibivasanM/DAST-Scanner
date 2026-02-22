# Vulnerability scanner — AI-Enhanced Automated Penetration Testing Platform

Production-ready SaaS platform combining **Nuclei** scanning, **OWASP ZAP** authenticated DAST, **OpenAI GPT-4o** analysis, intelligent **deduplication**, and **Playwright** proof-of-concept generation.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                       React Dashboard                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐   │
│  │Dashboard │ │  Scans   │ │ Findings │ │  Auth Config  │   │
│  │  Stats   │ │ Manager  │ │  Browser │ │  (ZAP Panel)  │   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └───────┬───────┘   │
│       └─────────────┴────────────┴───────────────┘           │
└───────────────────────────┬──────────────────────────────────┘
                            │ REST API
┌───────────────────────────┴──────────────────────────────────┐
│                      FastAPI Backend                          │
│                                                               │
│  ┌──────────────── Async Scan Pipeline ─────────────────────┐│
│  │                                                          ││
│  │  ┌──────────┐   ┌───────────┐                            ││
│  │  │  Nuclei  │   │   OWASP   │   Scanner selection:       ││
│  │  │ Scanner  │   │    ZAP    │   nuclei | zap | both      ││
│  │  └────┬─────┘   └─────┬─────┘                            ││
│  │       └────────┬───────┘                                  ││
│  │                ▼                                          ││
│  │  ┌──────────┐  ┌──────────┐  ┌───────────┐               ││
│  │  │  Dedup   │─▶│  OpenAI  │─▶│ Playwright│               ││
│  │  │  Engine  │  │  GPT-4o  │  │  PoC Gen  │               ││
│  │  └──────────┘  └──────────┘  └───────────┘               ││
│  └──────────────────────────────────────────────────────────┘│
│                                                               │
│  ┌──────────────────────────────────────────────────────────┐│
│  │              SQLite Database (WAL mode)                    ││
│  │  scans (engine, auth_config) │ findings (scanner_source)  ││
│  └──────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│               ZAP Docker Sidecar (daemon mode)                │
│  Spider │ AJAX Spider │ Active Scanner │ Auth Engine          │
└──────────────────────────────────────────────────────────────┘
```

## Scan Pipeline (5 Phases)

| Phase | Engine | Description |
|-------|--------|-------------|
| **1. Scanning** | `NucleiScanner` / `ZapScanner` | Nuclei for fast vuln templates, ZAP for authenticated DAST. Select `both` for combined coverage |
| **2. Deduplication** | `DeduplicationEngine` | 3-level hashing: exact, fuzzy URL normalization, cross-scan dedup. Works across both engines |
| **3. Persistence** | `Database` | SQLite with WAL mode, `scanner_source` field tracks which engine found each vuln |
| **4. AI Analysis** | `AIAnalyzer` | **OpenAI GPT-4o** — attack chains, CWE mapping, risk scoring. Analyzes combined Nuclei+ZAP findings |
| **5. PoC Generation** | `PoCGenerator` | AI-generated Playwright scripts + evidence screenshots |

## ZAP Authenticated Scanning

ZAP runs as a Docker sidecar daemon and supports 4 auth modes:

### Auth Types

| Type | Use Case | Required Fields |
|------|----------|-----------------|
| **Form** | Login page with username/password form | `login_url`, `username`, `password`, `username_field`, `password_field` |
| **Bearer** | JWT / OAuth2 bearer tokens | `token` |
| **Cookie** | Pre-authenticated session cookies | `cookies` |
| **Header** | Custom API key headers | `header_name`, `header_value` |

### Example: Form-Based Auth Scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://app.example.com",
    "scan_type": "full",
    "scanner_engine": "zap",
    "ai_analysis": true,
    "auth_config": {
      "auth_type": "form",
      "login_url": "https://app.example.com/login",
      "username_field": "email",
      "password_field": "password",
      "username": "testuser@example.com",
      "password": "TestP@ss123",
      "logged_in_indicator": "Dashboard|Logout|Welcome",
      "logged_out_indicator": "Login|Sign in",
      "exclude_urls": [".*logout.*", ".*reset-password.*"]
    }
  }'
```

### Example: Bearer Token Scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://api.example.com",
    "scanner_engine": "both",
    "auth_config": {
      "auth_type": "bearer",
      "token": "eyJhbGciOiJIUzI1NiIs..."
    }
  }'
```

## Quick Start

### Prerequisites

- **Docker & Docker Compose** (recommended)
- OR: Python 3.12+, Node.js 20+, Go 1.21+ (for Nuclei)

### Docker Deployment

```bash
# Clone and configure
cp .env.example .env
# Edit .env — set OPENAI_API_KEY

# Launch
docker compose up -d

# Dashboard:  http://localhost:3000
# API docs:   http://localhost:8000/docs
```

### Manual Setup

```bash
# 1. Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# 2. Configure
cp .env.example .env
# Edit .env — set OPENAI_API_KEY

# 3. One-command start (installs deps + launches both servers)
chmod +x start-dev.sh
./start-dev.sh

# OR start manually:

# Backend (terminal 1)
cd backend
pip install -r requirements.txt
playwright install chromium
export OPENAI_API_KEY=sk-xxxxx
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (terminal 2)
cd frontend
npm install --legacy-peer-deps
npx vite --host 0.0.0.0
```

## API Reference

### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scans` | Launch new scan |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}` | Scan details + AI analysis |
| `DELETE`| `/api/scans/{id}` | Delete scan + findings |
| `GET` | `/api/scans/{id}/findings` | Findings for a scan |

### Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/findings` | All findings (filterable) |
| `GET` | `/api/findings/{id}` | Full detail + AI + PoC |
| `PATCH`| `/api/findings/{id}` | Update status/notes |

### Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dashboard/stats` | Aggregate statistics |
| `GET` | `/api/dashboard/severity-trend` | Severity over time |
| `GET` | `/api/dashboard/top-vulnerabilities` | Most common vulns |
| `GET` | `/api/dashboard/attack-surface` | Attack surface map |

### Launch a Scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "scan_type": "full",
    "severity_filter": ["critical", "high", "medium"],
    "generate_poc": true,
    "ai_analysis": true
  }'
```

## OpenAI Integration Details

### API Configuration

| Env Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | *(required)* | Your OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o` | Model to use (`gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`) |

### How AI is Used

**Vulnerability Analysis** (`ai_analyzer.py`) — Calls `POST /v1/chat/completions` with `response_format: {"type": "json_object"}` for guaranteed structured output containing:
- Executive summary + composite risk score (0-100)
- Attack chain detection with multi-step exploitation paths
- Correlation groups linking related findings
- Prioritized remediation with effort estimates
- Per-finding enrichment: exploitability, CWE mapping, business impact, false positive likelihood

**PoC Generation** (`poc_generator.py`) — Calls GPT-4o to generate Playwright Python scripts tailored to each vulnerability type. Falls back to template-based generation if the API is unavailable.

**Graceful Degradation** — Without an API key, the platform falls back to rule-based heuristic analysis (tag-based chain detection, severity grouping, template PoC scripts).

## Deduplication Strategy

3-level deduplication eliminates redundant findings:

1. **Level 1 — Exact**: `SHA256(template_id | host | matched_at | matcher_name)`
2. **Level 2 — Fuzzy**: URL normalization (numeric segments → `{N}`, UUIDs → `{UUID}`, strips query values)
3. **Level 3 — Cross-scan**: `SHA256(template_id | host | severity)` across all scan runs

## Project Structure

```
vulnforge/
├── docker-compose.yml          # Backend + Frontend + ZAP sidecar
├── .env.example                # Configuration template
├── .gitignore
├── start-dev.sh                # One-command local dev startup
├── backend/
│   ├── Dockerfile              # Python 3.12 + Nuclei + Playwright
│   ├── .dockerignore
│   ├── main.py                 # FastAPI + dual-engine scan pipeline
│   ├── requirements.txt
│   └── modules/
│       ├── __init__.py
│       ├── database.py         # SQLite (scanner_engine + auth_config)
│       ├── scanner.py          # Nuclei async subprocess wrapper
│       ├── zap_scanner.py      # ZAP REST API authenticated scanner
│       ├── dedup.py            # 3-level deduplication engine
│       ├── ai_analyzer.py      # OpenAI GPT-4o analysis
│       └── poc_generator.py    # GPT-4o PoC + Playwright screenshots
└── frontend/
    ├── Dockerfile              # Node 20 multi-stage → Nginx
    ├── .dockerignore
    ├── package.json            # React + Recharts + Vite
    ├── vite.config.js          # Dev proxy + build config
    ├── index.html              # SPA entry point
    ├── nginx.conf              # Production reverse proxy
    ├── main.jsx                # React DOM entry
    └── Dashboard.jsx           # Full dashboard + ZAP auth UI
```

## Security Notes

- This platform is for **authorized** penetration testing only
- Always obtain written permission before scanning targets
- The AI analyzer sends finding data to OpenAI's API — review data handling requirements
- PoC scripts are generated for verification purposes — use responsibly
