#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# VulnForge — Local Development Startup Script
# ──────────────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${CYAN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       VulnForge — Local Dev Setup         ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════╝${NC}"
echo ""

# ── Check prerequisites ──────────────────────────────────────────────────────

check_cmd() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $1 found"
        return 0
    else
        echo -e "  ${RED}✗${NC} $1 not found"
        return 1
    fi
}

echo -e "${YELLOW}Checking prerequisites...${NC}"
MISSING=0
check_cmd python3   || MISSING=1
check_cmd pip       || MISSING=1
check_cmd node      || MISSING=1
check_cmd npm       || MISSING=1

if check_cmd nuclei; then
    NUCLEI_OK=1
else
    NUCLEI_OK=0
    echo -e "  ${YELLOW}⚠${NC}  Nuclei not installed — scans will fail"
    echo -e "     Install: ${CYAN}go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
fi

if [ "$MISSING" -eq 1 ]; then
    echo -e "\n${RED}Missing required tools. Install them and retry.${NC}"
    exit 1
fi

# ── Load .env ─────────────────────────────────────────────────────────────────

if [ -f "$ROOT_DIR/.env" ]; then
    echo -e "\n${GREEN}Loading .env${NC}"
    set -a
    source "$ROOT_DIR/.env"
    set +a
else
    echo -e "\n${YELLOW}No .env file found. Copying from .env.example${NC}"
    cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
    echo -e "${YELLOW}⚠  Edit .env and add your OPENAI_API_KEY, then re-run.${NC}"
fi

if [ -z "${OPENAI_API_KEY:-}" ]; then
    echo -e "${YELLOW}⚠  OPENAI_API_KEY not set — AI features will use heuristic fallback${NC}"
else
    echo -e "${GREEN}✓  OPENAI_API_KEY configured${NC}"
fi

# ── Install Backend ──────────────────────────────────────────────────────────

echo -e "\n${CYAN}[1/4] Installing Python dependencies...${NC}"
cd "$ROOT_DIR/backend"
pip install -r requirements.txt --break-system-packages -q 2>/dev/null \
    || pip install -r requirements.txt -q

# ── Install Playwright ───────────────────────────────────────────────────────

echo -e "${CYAN}[2/4] Installing Playwright browsers...${NC}"
python3 -m playwright install chromium 2>/dev/null || echo -e "${YELLOW}⚠  Playwright install skipped (run manually: playwright install chromium)${NC}"

# ── Install Frontend ─────────────────────────────────────────────────────────

echo -e "${CYAN}[3/4] Installing frontend dependencies...${NC}"
cd "$ROOT_DIR/frontend"
npm install --legacy-peer-deps --silent 2>/dev/null || npm install --legacy-peer-deps

# ── Launch ────────────────────────────────────────────────────────────────────

echo -e "\n${CYAN}[4/4] Starting services...${NC}"
echo -e "${GREEN}  Backend  → http://localhost:8000      (API docs: http://localhost:8000/docs)${NC}"
echo -e "${GREEN}  Frontend → http://localhost:5173${NC}"
echo ""

# Start backend in background
cd "$ROOT_DIR/backend"
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# Start frontend
cd "$ROOT_DIR/frontend"
npx vite --host 0.0.0.0 &
FRONTEND_PID=$!

# Trap to clean up on Ctrl+C
trap "echo -e '\n${YELLOW}Shutting down...${NC}'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" SIGINT SIGTERM

echo -e "\n${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          VulnForge is running!             ║${NC}"
echo -e "${GREEN}║  Dashboard:  http://localhost:5173          ║${NC}"
echo -e "${GREEN}║  API:        http://localhost:8000/docs     ║${NC}"
echo -e "${GREEN}║  Press Ctrl+C to stop                      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"

wait
