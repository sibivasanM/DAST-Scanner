"""
Vulnerability scanner — Automated Penetration Testing Platform
Core API Server — Nuclei + ZAP authenticated scanning, OpenAI GPT-4o analysis
"""

import asyncio
import json
import logging
import os
import re
import traceback
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, Field

from modules.database import Database
from modules.scanner import NucleiScanner
from modules.zap_scanner import ZapScanner
from modules.dedup import DeduplicationEngine
from modules.fp_filter import filter_false_positives
from modules.finding_consolidator import consolidate_findings
from modules.verify_filter import ReplayVerifier
from modules.ai_analyzer import AIAnalyzer
from modules.ai_fp_scorer import AIFalsePositiveScorer
from modules.poc_generator import PoCGenerator
from modules.pdf_report import PDFReportGenerator
from modules.selenium_auth import SeleniumAuthCapture
from modules.zap_session_injector import ZapSessionInjector
from modules.zap_context_config import ZapContextConfig
from modules.zap_scan_orchestrator import ZapScanOrchestrator
from modules.integrated_auth_scanner import IntegratedAuthenticatedScanner
from modules.dep_scanner import DepScanner
from modules.ssl_scanner import SSLScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("vulnforge")

# ── Pydantic Models ──────────────────────────────────────────────────────────

class AuthConfig(BaseModel):
    auth_type: str = Field(default="none", description="none | form | bearer | cookie | header | script")
    login_url: Optional[str] = None
    username_field: Optional[str] = Field(default="username")
    password_field: Optional[str] = Field(default="password")
    username: Optional[str] = None
    password: Optional[str] = None
    logged_in_indicator: Optional[str] = None
    logged_out_indicator: Optional[str] = None
    token: Optional[str] = None
    header_name: Optional[str] = Field(default="Authorization")
    header_value: Optional[str] = None
    cookies: Optional[str] = None
    exclude_urls: list[str] = Field(default=[])
    script_name:   Optional[str] = None   # filename saved in the shared zap-scripts volume
    script_engine: Optional[str] = None   # "ZEST" | "GraalVM" | None (auto-detect)


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target URL or CIDR range")
    scan_type: str = Field(default="full", description="full | quick | custom | deep")
    scanner_engine: str = Field(default="nuclei", description="nuclei | zap | both")
    severity_filter: list[str] = Field(default=["critical", "high", "medium", "low", "info"])
    tags: list[str] = Field(default=[])
    custom_templates: Optional[str] = Field(default=None)
    generate_poc: bool = Field(default=True)
    ai_analysis: bool = Field(default=True)
    auth_config: Optional[AuthConfig] = Field(default=None, description="Authentication configuration for ZAP")
    force_full_scan: bool = Field(default=False, description="Skip incremental URL exclusion — rescan everything")


class ScanScheduleRequest(BaseModel):
    target: str = Field(..., description="Target URL to scan on schedule")
    scan_type: str = Field(default="full")
    scanner_engine: str = Field(default="nuclei")
    severity_filter: list[str] = Field(default=["critical", "high", "medium", "low", "info"])
    tags: list[str] = Field(default=[])
    generate_poc: bool = Field(default=True)
    ai_analysis: bool = Field(default=True)
    interval: str = Field(default="weekly", description="daily | weekly | monthly")
    auth_config: Optional[AuthConfig] = Field(default=None)


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None


class AuthenticatedScanRequest(BaseModel):
    target: str = Field(..., description="Target URL to scan")
    auth_method: str = Field(..., description="curl | python | selenium")
    auth_data: dict = Field(..., description="Auth method configuration")
    scan_type: str = Field(default="full", description="full | quick | deep | insane")
    severity_filter: list[str] = Field(default=["critical", "high", "medium", "low", "info"])
    tags: list[str] = Field(default=[])
    ai_analysis: bool = Field(default=True)


class AuthTokenResponse(BaseModel):
    success: bool
    auth_type: Optional[str]
    token: Optional[str]
    cookies: Optional[str]
    headers: dict
    error: Optional[str]


class SeleniumAuthRequest(BaseModel):
    """Request to perform Selenium-based login and capture session."""
    login_url: str = Field(..., description="Login page URL")
    username: Optional[str] = Field(default=None, description="Username (or use env var LOGIN_USER)")
    password: Optional[str] = Field(default=None, description="Password (or use env var LOGIN_PASS)")
    username_field: str = Field(default="username", description="Form field name for username")
    password_field: str = Field(default="password", description="Form field name for password")
    logged_in_indicator: Optional[str] = Field(default=None, description="Regex to detect logged-in state")
    authenticated_pages: Optional[list[str]] = Field(default=None, description="Pages to visit after login")
    zap_proxy_host: str = Field(default="localhost", description="ZAP proxy host")
    zap_proxy_port: int = Field(default=8080, description="ZAP proxy port")


class AuthenticatedScanOrchestrationRequest(BaseModel):
    """Complete workflow: Selenium login → ZAP injection → scanning."""
    target: str = Field(..., description="Target URL to scan")
    login_url: str = Field(..., description="Login page URL")
    username: Optional[str] = Field(default=None, description="Username (env: LOGIN_USER)")
    password: Optional[str] = Field(default=None, description="Password (env: LOGIN_PASS)")
    username_field: str = Field(default="username")
    password_field: str = Field(default="password")
    logged_in_indicator: Optional[str] = Field(default=None)
    authenticated_pages: Optional[list[str]] = Field(default=None)
    exclude_logout_urls: Optional[list[str]] = Field(default=None)
    scan_type: str = Field(default="full", description="full | quick | deep")
    severity_filter: list[str] = Field(default=["critical", "high", "medium", "low", "info"])
    timeout_minutes: int = Field(default=60, description="Max scan duration in minutes")
    generate_poc: bool = Field(default=True)
    ai_analysis: bool = Field(default=True)


# ── Application Lifecycle ────────────────────────────────────────────────────

db = Database()
nuclei_scanner = NucleiScanner()
zap_scanner = ZapScanner()
dedup = DeduplicationEngine()
ai_analyzer = AIAnalyzer()
ai_fp_scorer = AIFalsePositiveScorer()
poc_gen = PoCGenerator()
pdf_generator = PDFReportGenerator()
dep_scanner = DepScanner()
ssl_scanner = SSLScanner()


def _make_replay_verifier(auth: Optional[dict], auth_status_json: Optional[str] = None) -> ReplayVerifier:
    """Build a ReplayVerifier from the scan's auth config and/or captured session.

    Priority:
      1. Selenium-captured cookies/token stored in auth_status (most reliable —
         these are real live session values from a browser login).
      2. auth_config bearer token or cookie string (user-supplied static creds).
      3. No auth (unauthenticated replay).
    """
    auth_cookies: dict = {}
    auth_token:   Optional[str] = None
    auth_headers: dict = {}

    # 1. Use Selenium-captured session from auth_status if available
    if auth_status_json:
        try:
            ast = json.loads(auth_status_json) if isinstance(auth_status_json, str) else auth_status_json
            if isinstance(ast, dict):
                # auth_status may carry cookies captured during Selenium login
                for k, v in ast.get("cookies", {}).items():
                    auth_cookies[k] = v
                if ast.get("token"):
                    auth_token = ast["token"]
        except Exception:
            pass

    # 2. Fall back to static auth_config
    if not auth_cookies and not auth_token and auth:
        atype = auth.get("auth_type", "none")
        if atype == "bearer":
            auth_token = auth.get("token", "")
        elif atype == "cookie":
            for part in (auth.get("cookies") or "").split(";"):
                if "=" in part:
                    k, _, v = part.strip().partition("=")
                    auth_cookies[k.strip()] = v.strip()
        elif atype == "header":
            name = auth.get("header_name", "")
            val  = auth.get("header_value", "")
            if name and val:
                auth_headers[name] = val

    return ReplayVerifier(
        auth_cookies=auth_cookies,
        auth_token=auth_token,
        auth_headers=auth_headers,
    )

# New authenticated scan modules
selenium_auth = SeleniumAuthCapture()
zap_session_injector = ZapSessionInjector()
zap_context_config = ZapContextConfig()
zap_scan_orchestrator = ZapScanOrchestrator()


async def _scheduler_loop():
    """Background task: fire due scheduled scans every 60 seconds."""
    INTERVAL_HOURS = {"daily": 24, "weekly": 168, "monthly": 720}
    while True:
        try:
            await asyncio.sleep(60)
            due = db.get_due_schedules()
            for sched in due:
                try:
                    config = json.loads(sched["config"])
                    req = ScanRequest(**config)
                    new_scan_id = str(uuid.uuid4())
                    auth_json = req.auth_config.model_dump_json() if req.auth_config else None
                    db.create_scan(
                        scan_id=new_scan_id, target=req.target, scan_type=req.scan_type,
                        config=sched["config"], scanner_engine=req.scanner_engine,
                        auth_config=auth_json,
                    )
                    db.update_scan(new_scan_id, parent_scan_id=sched["id"])
                    asyncio.create_task(run_scan_pipeline(new_scan_id, req))

                    # Advance next_run
                    hours = INTERVAL_HOURS.get(sched["interval"], 168)
                    next_run = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
                    db.update_schedule(
                        sched["id"],
                        last_run=datetime.now(timezone.utc).isoformat(),
                        last_scan_id=new_scan_id,
                        next_run=next_run,
                    )
                    logger.info(f"[Scheduler] Fired scan {new_scan_id} for {sched['target']} "
                                f"(interval={sched['interval']}, next={next_run})")
                except Exception as exc:
                    logger.error(f"[Scheduler] Failed to launch scheduled scan {sched['id']}: {exc}")
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error(f"[Scheduler] Unexpected error: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Vulnerability scanner...")
    db.initialize()
    nuclei_ok = await nuclei_scanner.check_health()
    logger.info(f"Nuclei available: {nuclei_ok}")
    zap_ok = await zap_scanner.check_health()
    logger.info(f"ZAP available: {zap_ok}")
    logger.info(f"OpenAI enabled: {ai_analyzer.enabled} (model: {ai_analyzer.model})")
    await poc_gen.initialize()
    logger.info("Playwright initialized — Vulnerability scanner ready")
    # Pre-fetch dep scanner databases in background so first scan is fast
    from modules.dep_db_cache import prefetch_databases
    asyncio.create_task(prefetch_databases())
    # Start scheduled scan background loop
    scheduler_task = asyncio.create_task(_scheduler_loop())
    yield
    scheduler_task.cancel()
    try:
        await scheduler_task
    except asyncio.CancelledError:
        pass
    await poc_gen.shutdown()
    logger.info("Vulnerability scanner shut down")


app = FastAPI(
    title="Vulnerability scanner",
    description="AI-Enhanced Penetration Testing — Nuclei + ZAP + OpenAI GPT-4o",
    version="2.0.0",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

os.makedirs("screenshots", exist_ok=True)
app.mount("/screenshots", StaticFiles(directory="screenshots"), name="screenshots")

# ── ZST Session File Parsing ─────────────────────────────────────────────────

def _parse_zst_bytes(content: bytes) -> bytes:
    """Try zstandard decompression; return content unchanged if not compressed."""
    try:
        import zstandard as zstd  # optional dependency
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(content)
    except Exception:
        return content


def _parse_har_to_auth(har: dict) -> dict:
    """Extract auth cookies / headers from a browser HAR export."""
    entries = har.get("log", {}).get("entries", [])
    all_cookies: dict = {}
    auth_header: str | None = None
    custom_header: tuple | None = None

    for entry in entries:
        req = entry.get("request", {})
        for c in req.get("cookies", []):
            name, value = c.get("name", ""), c.get("value", "")
            if name and value:
                all_cookies[name] = value
        for h in req.get("headers", []):
            hname = h.get("name", "").lower()
            hval  = h.get("value", "")
            if hname == "authorization" and hval:
                auth_header = hval
            elif hname.startswith("x-") and ("key" in hname or "token" in hname or "auth" in hname) and hval:
                custom_header = (h["name"], hval)

    base = {
        "logged_in_indicator": "", "logged_out_indicator": "",
        "exclude_urls": [], "login_url": None,
        "username_field": "username", "password_field": "password",
        "username": None, "password": None,
    }

    if auth_header:
        if auth_header.lower().startswith("bearer "):
            return {**base, "auth_type": "bearer", "token": auth_header[7:],
                    "header_name": "Authorization", "header_value": None, "cookies": None}
        return {**base, "auth_type": "header", "header_name": "Authorization",
                "header_value": auth_header, "token": None, "cookies": None}

    if custom_header:
        return {**base, "auth_type": "header", "header_name": custom_header[0],
                "header_value": custom_header[1], "token": None, "cookies": None}

    if all_cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in all_cookies.items())
        return {**base, "auth_type": "cookie", "cookies": cookie_str,
                "header_name": "Authorization", "header_value": None, "token": None}

    raise HTTPException(400, "No usable auth data found in HAR file")


def _extract_auth_config(data: dict) -> dict:
    """
    Build a normalised AuthConfig dict from a .zst payload.

    Supported formats:
      1. Native  — has 'auth_type' key (matches AuthConfig schema)
      2. HAR     — {'log': {'entries': [...]}}
      3. Cookie  — {'cookies': '...'}
      4. Bearer  — {'token': '...'}
      5. Header  — {'header_name': '...', 'header_value': '...'}
    """
    base = {
        "auth_type": "none", "login_url": None,
        "username_field": "username", "password_field": "password",
        "username": None, "password": None,
        "logged_in_indicator": None, "logged_out_indicator": None,
        "token": None, "header_name": "Authorization", "header_value": None,
        "cookies": None, "exclude_urls": [],
    }

    # Format 1 — Native AuthConfig
    if "auth_type" in data:
        allowed_keys = set(base.keys()) | {"script_name"}
        merged = {**base, **{k: v for k, v in data.items() if k in allowed_keys}}
        valid = {"none", "form", "bearer", "cookie", "header", "script"}
        if merged["auth_type"] not in valid:
            merged["auth_type"] = "cookie"
        excl = merged.get("exclude_urls", [])
        if isinstance(excl, str):
            merged["exclude_urls"] = [x.strip() for x in excl.split(",") if x.strip()]
        return merged

    # Format 2 — HAR
    if "log" in data and isinstance(data.get("log"), dict):
        return _parse_har_to_auth(data)

    # Format 3 — Cookie shorthand
    if "cookies" in data:
        return {**base, "auth_type": "cookie", "cookies": data["cookies"],
                "logged_in_indicator": data.get("logged_in_indicator"),
                "logged_out_indicator": data.get("logged_out_indicator"),
                "exclude_urls": data.get("exclude_urls", [])}

    # Format 4 — Bearer token
    if "token" in data:
        return {**base, "auth_type": "bearer", "token": data["token"],
                "logged_in_indicator": data.get("logged_in_indicator"),
                "exclude_urls": data.get("exclude_urls", [])}

    # Format 5 — Custom header
    if "header_name" in data and "header_value" in data:
        return {**base, "auth_type": "header",
                "header_name": data["header_name"],
                "header_value": data["header_value"],
                "logged_in_indicator": data.get("logged_in_indicator"),
                "exclude_urls": data.get("exclude_urls", [])}

    raise HTTPException(
        400,
        "Unrecognised .zst format. Expected: auth_type / cookies / token / "
        "header_name+header_value / HAR (log.entries[])"
    )


# Directory shared with ZAP container (mounted at /zap/scripts/vulnforge inside ZAP)
ZAP_SCRIPTS_DIR = os.getenv("ZAP_SCRIPTS_DIR", "/app/zap-scripts")

_AUTH_BASE = {
    "login_url": None, "username_field": "username", "password_field": "password",
    "username": None, "password": None, "logged_in_indicator": None,
    "logged_out_indicator": None, "token": None,
    "header_name": "Authorization", "header_value": None,
    "cookies": None, "exclude_urls": [],
}


def _is_zest_script(data: dict) -> bool:
    """Return True if the JSON payload is a ZAP ZEST script recording."""
    return (
        "zestVersion" in data
        or data.get("about") == "This is a ZEST script"
        or ("statements" in data and "type" in data)
    )


def _parse_zest_to_auth(data: dict) -> dict:
    """
    Convert a ZAP ZEST recording to an AuthConfig dict.

    Handles two ZEST recording styles:

    1. ZestRequest  — HTTP-level recording (older ZAP proxy recording)
       Looks for POST statements with form body → extracts login URL + fields.

    2. ZestClient   — Browser-automation recording (newer ZAP client recorder)
       Looks for ZestClientLaunch (page URL) + ZestClientElementSendKeys
       (field element IDs and typed values) to infer form auth parameters.
    """
    from urllib.parse import parse_qs

    _USER = {"user", "login", "email", "uid", "uname", "account", "username"}
    _PASS = {"pass", "pwd", "secret", "psw", "passw", "password", "passwd"}

    statements = data.get("statements", [])

    # ── Style 1: ZestRequest (HTTP-level POST) ────────────────────────────────
    for stmt in statements:
        if stmt.get("elementType") != "ZestRequest":
            continue
        if stmt.get("method", "").upper() != "POST":
            continue
        url  = stmt.get("url", "").strip()
        body = stmt.get("data", "").strip()
        if not url:
            continue
        params = {}
        if body:
            try:
                params = parse_qs(body, keep_blank_values=True)
            except Exception:
                pass
        uf = pf = uv = pv = None
        for key, vals in params.items():
            val = vals[0] if vals else ""
            kl  = key.lower()
            if any(h in kl for h in _USER) and uf is None:
                uf, uv = key, val
            elif any(h in kl for h in _PASS) and pf is None:
                pf, pv = key, val
        logger.info(f"[ZEST] HTTP POST: url={url} user={uf} pass={pf}")
        return {**_AUTH_BASE,
                "auth_type": "form", "login_url": url,
                "username_field": uf or "username", "password_field": pf or "password",
                "username": uv or "", "password": pv or ""}

    # ── Style 2: ZestClient (browser-automation) ──────────────────────────────
    launch_url = None
    uf = pf = uv = pv = None
    for stmt in statements:
        elem_type = stmt.get("elementType", "")
        if elem_type == "ZestClientLaunch" and not launch_url:
            launch_url = stmt.get("url", "").strip()
        elif elem_type == "ZestClientElementSendKeys":
            element = stmt.get("element", "")   # HTML element id / name
            value   = stmt.get("value", "")
            kl      = element.lower()
            if any(h in kl for h in _USER) and uf is None:
                uf, uv = element, value
            elif any(h in kl for h in _PASS) and pf is None:
                pf, pv = element, value

    if launch_url and uf and pf:
        logger.info(f"[ZEST] Client script: url={launch_url} user={uf}={uv!r} pass={pf}=***")
        return {**_AUTH_BASE,
                "auth_type": "form", "login_url": launch_url,
                "username_field": uf, "password_field": pf,
                "username": uv or "", "password": pv or ""}

    raise HTTPException(
        400,
        "Could not extract authentication details from ZEST recording. "
        "The recording must contain either a POST login request (ZestRequest) "
        "or browser-level field interactions (ZestClientElementSendKeys)."
    )


def _save_zap_script(content: bytes, filename: str, engine_hint: str = None) -> dict:
    """Save an uploaded ZAP auth script to the shared volume and return AuthConfig dict."""
    os.makedirs(ZAP_SCRIPTS_DIR, exist_ok=True)
    safe_name = re.sub(r"[^\w\-.]", "_", filename)
    dest = os.path.join(ZAP_SCRIPTS_DIR, safe_name)
    with open(dest, "wb") as fh:
        fh.write(content)
    logger.info(f"[ZST] Saved ZAP auth script → {dest}")
    result = {**_AUTH_BASE, "auth_type": "script", "script_name": safe_name}
    if engine_hint:
        result["script_engine"] = engine_hint
    return result


# ── PoC helpers ─────────────────────────────────────────────────────────────

def _build_template_steps(finding: dict) -> dict:
    """
    Build steps-to-reproduce from finding metadata — no AI required.
    Works for both Nuclei and ZAP findings.
    """
    url = finding.get("matched_at") or finding.get("url") or finding.get("host", "")
    name = finding.get("name", "Unknown vulnerability")
    scanner = finding.get("scanner_source", "nuclei")
    curl = (finding.get("curl_command") or "").strip()

    # Pull ZAP evidence fields from extracted_results
    extracted: dict = {}
    raw = finding.get("extracted_results")
    if raw:
        try:
            extracted = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            pass

    param = extracted.get("param", "")
    attack = extracted.get("attack", "")
    evidence = extracted.get("evidence", "")
    other = extracted.get("other", "")

    steps: list[str] = []

    # Step 1 — navigate
    if url:
        steps.append(f"Open a browser and navigate to: {url}")

    # Step 2 — identify vulnerable parameter
    if param:
        steps.append(f"Locate the vulnerable parameter: '{param}'")

    # Step 3 — send the attack / payload
    if attack:
        steps.append(f"Inject the following payload: {attack[:300]}")
    elif curl:
        steps.append(f"Send the following request:\n{curl[:500]}")
    else:
        steps.append(f"Trigger the vulnerability by interacting with the identified endpoint")

    # Step 4 — observe result
    if evidence:
        steps.append(f"Observe the server response; look for: {evidence[:300]}")
    elif other:
        steps.append(f"Observe the server response; note: {other[:300]}")
    else:
        steps.append(
            f"Observe the response for signs of {name} "
            f"(unexpected data, error messages, or altered behavior)"
        )

    # Step 5 — capture evidence
    steps.append("Take a screenshot or save the HTTP response as evidence")

    return {
        "steps": steps,
        "param": param,
        "attack": attack,
        "evidence": evidence,
        "curl": curl,
        "scanner": scanner,
    }


# ── Background Scan Pipeline ────────────────────────────────────────────────

async def run_scan_pipeline(scan_id: str, request: ScanRequest):
    """Pipeline: Nuclei/ZAP/Both → Dedup → Store → AI → Steps + Screenshot"""
    try:
        engine = request.scanner_engine
        auth = request.auth_config.model_dump() if request.auth_config else None
        logger.info(f"[{scan_id}] Starting {engine} scan for {request.target}")

        # ── Phase 1: Scanning ─────────────────────────────────────────────────
        db.update_scan(scan_id, status="scanning", phase="scanning")
        all_raw_findings = []

        # Nuclei scan
        if engine in ("nuclei", "both"):
            # ── Template update before every Nuclei scan ──────────────────────
            db.update_scan(scan_id, phase="template_update")
            logger.info(f"[{scan_id}] Updating Nuclei templates before scan…")
            await nuclei_scanner.update_templates()

            db.update_scan(scan_id, phase="nuclei_scan")
            logger.info(f"[{scan_id}] Running Nuclei ({request.scan_type}) with all templates…")
            try:
                # ── Incremental: build exclude-urls file from previous crawled URLs ──
                # Skipped when force_full_scan=True (rescan button)
                prev_nuclei_urls = set() if request.force_full_scan else db.get_previous_crawled_urls(request.target)
                exclude_urls_file: Optional[str] = None
                if prev_nuclei_urls:
                    import tempfile
                    exclude_urls_file = tempfile.mktemp(suffix="_exclude_urls.txt")
                    with open(exclude_urls_file, "w") as _eu:
                        _eu.write("\n".join(prev_nuclei_urls))
                    logger.info(f"[{scan_id}] Incremental Nuclei: excluding {len(prev_nuclei_urls)} previously scanned URLs")
                    db.update_scan(scan_id, is_incremental="1")

                nuclei_findings = await nuclei_scanner.execute(
                    target=request.target,
                    severity=request.severity_filter,
                    tags=request.tags if request.tags else None,
                    custom_templates=request.custom_templates,
                    scan_type=request.scan_type,
                    exclude_urls_file=exclude_urls_file,
                )
                # Clean up temp exclude file
                if exclude_urls_file and os.path.exists(exclude_urls_file):
                    os.unlink(exclude_urls_file)

                for f in nuclei_findings:
                    f["scanner_source"] = "nuclei"
                all_raw_findings.extend(nuclei_findings)
                logger.info(f"[{scan_id}] Nuclei: {len(nuclei_findings)} findings")

                # Save crawled URLs (matched_at) for use by next incremental scan
                nuclei_urls = list({
                    f.get("matched_at") or f.get("url") or ""
                    for f in nuclei_findings
                    if f.get("matched_at") or f.get("url")
                })
                if nuclei_urls:
                    existing_crawled = db.get_previous_crawled_urls(request.target)
                    merged_urls = list(existing_crawled | set(nuclei_urls))
                    db.update_scan(scan_id, crawled_urls=json.dumps(merged_urls))

            except Exception as e:
                if exclude_urls_file and os.path.exists(exclude_urls_file):
                    try: os.unlink(exclude_urls_file)
                    except Exception: pass
                logger.error(f"[{scan_id}] Nuclei scan failed: {e}")
                if engine == "nuclei":
                    raise

        # ZAP scan
        if engine in ("zap", "both"):
            db.update_scan(scan_id, phase="zap_scan")
            logger.info(f"[{scan_id}] Running ZAP (auth={auth.get('auth_type') if auth else 'none'})...")
            try:
                # For form-based auth, ZAP's native form-auth is unreliable on modern apps.
                # Use Playwright/Selenium to do the actual login, capture the session, then
                # inject it into ZAP as cookie/bearer auth — same approach as the full
                # authenticated scan pipeline.
                effective_auth = auth.copy() if auth else None
                if effective_auth and effective_auth.get("auth_type") == "form":
                    logger.info(f"[{scan_id}] Form auth detected — running Selenium login first…")
                    db.update_scan(scan_id, phase="selenium_login")
                    try:
                        from modules.selenium_auth import SeleniumAuthCapture
                        from modules.zap_session_injector import ZapSessionInjector
                        selenium = SeleniumAuthCapture(
                            zap_proxy_host=os.getenv("ZAP_HOST", "zap"),
                            zap_proxy_port=int(os.getenv("ZAP_PORT", "8080")),
                        )
                        session_result = await selenium.capture_session(
                            login_url=effective_auth["login_url"],
                            username=effective_auth.get("username"),
                            password=effective_auth.get("password"),
                            username_field=effective_auth.get("username_field", "username"),
                            password_field=effective_auth.get("password_field", "password"),
                            logged_in_indicator=effective_auth.get("logged_in_indicator"),
                        )
                        if session_result["success"]:
                            logger.info(f"[{scan_id}] Selenium login OK — injecting session into ZAP")
                            db.update_scan(scan_id, phase="zap_session_injection")
                            injector = ZapSessionInjector(
                                api_url=os.getenv("ZAP_API_URL", "http://localhost:8080"),
                                api_key=os.getenv("ZAP_API_KEY", ""),
                            )
                            await injector.inject_session(
                                target_url=request.target,
                                session_data=session_result,
                                session_name=f"vulnforge-{scan_id[:8]}",
                            )
                            # Persist auth screenshot if captured
                            if session_result.get("auth_screenshot"):
                                db.update_scan(scan_id, auth_status=json.dumps({
                                    "verified": session_result.get("session_valid", False),
                                    "message": session_result.get("message", ""),
                                    "auth_screenshot": session_result["auth_screenshot"],
                                }))
                            # Convert to cookie auth so ZAP uses the captured session
                            if session_result.get("cookies"):
                                cookie_str = "; ".join(f"{k}={v}" for k, v in session_result["cookies"].items())
                                effective_auth = dict(effective_auth)
                                effective_auth["auth_type"] = "cookie"
                                effective_auth["cookies"] = cookie_str
                            elif session_result.get("token"):
                                effective_auth = dict(effective_auth)
                                effective_auth["auth_type"] = "bearer"
                                effective_auth["token"] = session_result["token"]
                        else:
                            logger.warning(f"[{scan_id}] Selenium login failed: {session_result.get('message')} — continuing with ZAP native form auth")
                    except Exception as se:
                        logger.error(f"[{scan_id}] Selenium pre-auth failed: {se} — continuing with ZAP native form auth")
                    db.update_scan(scan_id, phase="zap_scan")

                zap_findings = await zap_scanner.execute(
                    target=request.target,
                    auth_config=effective_auth,
                    scan_type=request.scan_type,
                    severity=request.severity_filter,
                )
                for f in zap_findings:
                    f["scanner_source"] = "zap"
                all_raw_findings.extend(zap_findings)
                logger.info(f"[{scan_id}] ZAP: {len(zap_findings)} findings")

                # Persist auth verification result
                ar = zap_scanner.last_auth_result
                if ar:
                    existing_as = {}
                    try:
                        row = db.get_scan(scan_id)
                        existing_as = json.loads(row.get("auth_status") or "{}") if row else {}
                    except Exception:
                        pass
                    db.update_scan(scan_id, auth_status=json.dumps({**existing_as, **ar}))
                    if not ar.get("verified"):
                        logger.warning(f"[{scan_id}] ZAP auth may have failed: {ar.get('message')}")
            except Exception as e:
                logger.error(f"[{scan_id}] ZAP scan failed: {e}")
                if engine == "zap":
                    raise

        db.update_scan(scan_id, raw_finding_count=len(all_raw_findings))

        # ── Phase 1b: Dependency / SCA Scan (parallel) ───────────────────────
        # Runs concurrently with the main pipeline — page probing + Retire.js +
        # Wappalyzer + OSV/NVD CVE lookup.  Auth cookies are passed so the dep
        # scanner can fingerprint authenticated pages as well.
        db.update_scan(scan_id, phase="dep_scan")
        logger.info(f"[{scan_id}] Running dependency scan…")
        try:
            dep_auth_cookies: dict = {}
            if auth:
                atype = auth.get("auth_type", "none")
                if atype == "cookie":
                    for part in (auth.get("cookies") or "").split(";"):
                        if "=" in part:
                            k, _, v = part.strip().partition("=")
                            dep_auth_cookies[k.strip()] = v.strip()
            # Also pick up any Selenium-captured cookies stored in auth_status
            try:
                row = db.get_scan(scan_id)
                ast = json.loads(row.get("auth_status") or "{}") if row else {}
                dep_auth_cookies.update(ast.get("cookies", {}))
            except Exception:
                pass

            dep_findings = await dep_scanner.scan(
                url=request.target,
                scan_id=scan_id,
                auth_cookies=dep_auth_cookies or None,
            )
            for f in dep_findings:
                f["scanner_source"] = "dep-scan"
            all_raw_findings.extend(dep_findings)
            logger.info(f"[{scan_id}] Dep scan: {len(dep_findings)} vulnerable dependency findings")
        except Exception as dep_err:
            logger.error(f"[{scan_id}] Dependency scan failed (non-fatal): {dep_err}")

        db.update_scan(scan_id, raw_finding_count=len(all_raw_findings))

        # ── Phase 1c: SSL/TLS Scan ────────────────────────────────────────────
        db.update_scan(scan_id, phase="ssl_scan")
        logger.info(f"[{scan_id}] Running SSL/TLS scan…")
        try:
            ssl_findings = await ssl_scanner.scan(target=request.target, scan_id=scan_id)
            for f in ssl_findings:
                f["scanner_source"] = "ssl-scan"
            all_raw_findings.extend(ssl_findings)
            logger.info(f"[{scan_id}] SSL scan: {len(ssl_findings)} finding(s)")
        except Exception as ssl_err:
            logger.error(f"[{scan_id}] SSL scan failed (non-fatal): {ssl_err}")

        db.update_scan(scan_id, raw_finding_count=len(all_raw_findings))

        # ── Phase 2: Dedup ────────────────────────────────────────────────────
        db.update_scan(scan_id, phase="deduplication")
        unique_findings = dedup.deduplicate(all_raw_findings, scan_id)
        logger.info(f"[{scan_id}] {len(unique_findings)} unique findings after dedup")

        # ── Phase 2a: Consolidation ───────────────────────────────────────────
        # Group findings that share the same vulnerability class on the same host
        # (same template_id / name / CVE across multiple URLs) into one
        # representative finding with a vulnerable_urls list.
        # Groups smaller than 3 pass through unchanged.
        db.update_scan(scan_id, phase="consolidation")
        try:
            unique_findings, savings = consolidate_findings(unique_findings)
            if savings:
                logger.info(
                    f"[{scan_id}] Consolidation: {savings} findings collapsed "
                    f"→ {len(unique_findings)} after grouping"
                )
        except Exception as con_err:
            logger.error(f"[{scan_id}] Consolidation failed (non-fatal): {con_err}")

        # ── Phase 2b: Rule-Based False-Positive Filter ───────────────────────
        db.update_scan(scan_id, phase="fp_filtering")
        unique_findings, fp_findings = filter_false_positives(unique_findings)
        if fp_findings:
            logger.info(
                f"[{scan_id}] FP filter: {len(fp_findings)} removed, "
                f"{len(unique_findings)} retained"
            )

        # ── Phase 2c: HTTP Replay Verification ───────────────────────────────
        # Re-send each injection finding's original attack request and check
        # if the evidence still appears in the response.
        # Uses the live session (cookies/token) for authenticated scans so
        # the replayed request hits the same auth-protected endpoints as the scan.
        db.update_scan(scan_id, phase="fp_filtering")
        try:
            scan_row = db.get_scan(scan_id)
            auth_status_json = scan_row.get("auth_status") if scan_row else None
            verifier = _make_replay_verifier(auth, auth_status_json)
            unique_findings, unverified = await verifier.verify(unique_findings)
            if unverified:
                logger.info(
                    f"[{scan_id}] Replay: {len(unverified)} transient FPs removed, "
                    f"{len(unique_findings)} confirmed"
                )
        except Exception as re_err:
            logger.error(f"[{scan_id}] Replay verification failed (non-fatal): {re_err}")

        # ── Phase 2d: AI-Assisted FP Scoring (low/medium confidence ZAP) ─────
        db.update_scan(scan_id, phase="ai_fp_scoring")
        unique_findings, ai_fp_findings = await ai_fp_scorer.score(unique_findings)
        if ai_fp_findings:
            logger.info(
                f"[{scan_id}] AI-FP scorer: {len(ai_fp_findings)} removed, "
                f"{len(unique_findings)} retained"
            )

        db.update_scan(scan_id, unique_finding_count=len(unique_findings))

        # ── Phase 3: Store ────────────────────────────────────────────────────
        db.update_scan(scan_id, phase="storing_findings")
        for finding in unique_findings:
            finding["scan_id"] = scan_id
            finding["id"] = str(uuid.uuid4())
            finding["status"] = "open"
            finding["created_at"] = datetime.now(timezone.utc).isoformat()
            db.insert_finding(finding)

        # ── Phase 4: AI Analysis ──────────────────────────────────────────────
        if request.ai_analysis and unique_findings:
            db.update_scan(scan_id, phase="ai_analysis")
            logger.info(f"[{scan_id}] Running AI analysis on {len(unique_findings)} findings...")
            try:
                ai_results = await ai_analyzer.analyze_findings(unique_findings, request.target)
                db.update_scan(scan_id, ai_analysis=json.dumps(ai_results))
                for enrichment in ai_results.get("enrichments", []):
                    fid = enrichment.get("finding_id")
                    if fid:
                        db.update_finding(fid, ai_analysis=json.dumps(enrichment))
                logger.info(f"[{scan_id}] AI: risk_score={ai_results.get('risk_score', '?')}")
            except Exception as e:
                logger.error(f"[{scan_id}] AI analysis failed: {e}")

        # ── Phase 5: Evidence Capture (steps + screenshot) ────────────────────
        if request.generate_poc and unique_findings:
            db.update_scan(scan_id, phase="evidence_capture")
            # Raised to 8 — matches context pool size; all ops are I/O-bound
            semaphore = asyncio.Semaphore(8)
            # Inner semaphore for per-instance screenshots inside a group slot
            inst_semaphore = asyncio.Semaphore(3)
            # Hard cap per screenshot so a hung page never blocks a slot forever
            SCREENSHOT_TIMEOUT = 12  # seconds

            async def _take_screenshot(url: str, path: str, f: dict) -> bool:
                """Take one screenshot with a hard timeout. Returns True on success."""
                try:
                    await asyncio.wait_for(
                        poc_gen._capture_screenshot(url, path, finding=f),
                        timeout=SCREENSHOT_TIMEOUT,
                    )
                    return os.path.exists(path)
                except asyncio.TimeoutError:
                    logger.warning(f"[{scan_id}] Screenshot timed out after {SCREENSHOT_TIMEOUT}s: {url[:70]}")
                    return False
                except Exception as e:
                    logger.warning(f"[{scan_id}] Screenshot failed for {url[:70]}: {e}")
                    return False

            async def _run_poc(finding: dict):
                async with semaphore:
                    try:
                        url = finding.get("matched_at") or finding.get("url") or finding.get("host", "")
                        screenshot_path = os.path.join("screenshots", f"{finding['id']}.png")

                        # Primary screenshot
                        if poc_gen._browser and url:
                            await _take_screenshot(url, screenshot_path, finding)

                        # Build template-based steps (no AI, always works)
                        steps = _build_template_steps(finding)

                        # Preserve any existing extracted_results
                        existing = {}
                        if finding.get("extracted_results"):
                            try:
                                existing = json.loads(finding["extracted_results"]) \
                                    if isinstance(finding["extracted_results"], str) \
                                    else finding["extracted_results"]
                            except (json.JSONDecodeError, TypeError):
                                pass

                        # Per-instance screenshots for consolidated groups — run in parallel
                        instance_screenshots = []
                        if existing.get("is_consolidated_group") and poc_gen._browser:
                            inst_urls = existing.get("vulnerable_urls", [])[:5]

                            async def _inst_shot(inst_url: str):
                                async with inst_semaphore:
                                    inst_shot = os.path.join(
                                        "screenshots",
                                        f"{finding['id']}_{abs(hash(inst_url)) % 100000}.png",
                                    )
                                    ok = await _take_screenshot(inst_url, inst_shot, finding)
                                    if ok:
                                        return {"url": inst_url, "screenshot": inst_shot}
                                    return None

                            inst_results = await asyncio.gather(*[_inst_shot(u) for u in inst_urls])
                            instance_screenshots = [r for r in inst_results if r]

                        existing["steps_to_reproduce"] = steps
                        if instance_screenshots:
                            existing["instance_screenshots"] = instance_screenshots

                        db.update_finding(
                            finding["id"],
                            poc_screenshot=screenshot_path if os.path.exists(screenshot_path) else "",
                            extracted_results=json.dumps(existing),
                        )
                        logger.info(f"[{scan_id}] Evidence done: {finding.get('name', '')[:50]}")
                    except Exception as e:
                        logger.error(f"[{scan_id}] Evidence capture failed for {finding.get('id')}: {e}")

            await asyncio.gather(*[_run_poc(f) for f in unique_findings])

        # ── Done ──────────────────────────────────────────────────────────────
        db.update_scan(scan_id, status="completed", phase="done",
                       completed_at=datetime.now(timezone.utc).isoformat())
        logger.info(f"[{scan_id}] ✓ Complete — {len(unique_findings)} findings for {request.target}")

    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"[{scan_id}] FAILED: {e}\n{tb}")
        db.update_scan(scan_id, status="failed", phase="error", error=f"{type(e).__name__}: {e}")


# ── API Routes ───────────────────────────────────────────────────────────────

@app.post("/api/scans", response_model=ScanResponse, status_code=201)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    auth_json = request.auth_config.model_dump_json() if request.auth_config else None
    db.create_scan(
        scan_id=scan_id, target=request.target, scan_type=request.scan_type,
        config=request.model_dump_json(), scanner_engine=request.scanner_engine,
        auth_config=auth_json,
    )
    background_tasks.add_task(run_scan_pipeline, scan_id, request)
    return ScanResponse(scan_id=scan_id, status="queued", message=f"{request.scanner_engine} scan queued for {request.target}")


@app.post("/api/scans/auth/fetch-token")
async def fetch_auth_token(auth_method: str, auth_data: dict):
    """
    Fetch authentication token/cookies using specified method (curl, python, or selenium).
    Returns the fetched credentials for inspection or direct use.
    """
    try:
        if auth_method == "curl":
            result = await zap_scanner.fetch_auth_via_curl(auth_data.get("curl_command", ""))
        elif auth_method == "python":
            result = await zap_scanner.fetch_auth_via_python(
                auth_data.get("login_url", ""),
                auth_data.get("credentials", {})
            )
        elif auth_method == "selenium":
            result = await zap_scanner.fetch_auth_via_selenium(auth_data.get("script", ""))
        else:
            raise ValueError(f"Unknown auth_method: {auth_method}. Use 'curl', 'python', or 'selenium'")
        
        return result
    except Exception as e:
        logger.error(f"Auth token fetch failed: {e}")
        raise HTTPException(400, f"Auth fetch failed: {e}")


@app.post("/api/scans/auth/scan", response_model=ScanResponse, status_code=201)
async def create_authenticated_scan(request: AuthenticatedScanRequest, background_tasks: BackgroundTasks):
    """
    Initiate a ZAP scan with automatically fetched authentication credentials.
    
    Supports three methods:
    - curl: Execute a curl command to fetch token
    - python: POST to login URL and extract token/cookies
    - selenium: Browser automation to fetch token
    
    Example auth_data for python method:
    {
        "login_url": "https://app.com/login",
        "credentials": {"username": "admin", "password": "secret"},
        "logged_in_indicator": "Dashboard|Home",
        "logged_out_indicator": "Login|Sign in"
    }
    
    Example auth_data for curl method:
    {
        "curl_command": "curl -X POST https://app.com/api/login -d 'user=admin&pass=secret'",
        "logged_in_indicator": "Dashboard"
    }
    
    Example auth_data for selenium method:
    {
        "script": "from selenium import webdriver; driver = webdriver.Chrome(); ..."
    }
    """
    try:
        scan_id = str(uuid.uuid4())
        
        # Store scan with auth method info
        config_dict = request.model_dump()
        db.create_scan(
            scan_id=scan_id, 
            target=request.target, 
            scan_type=request.scan_type,
            config=json.dumps(config_dict),
            scanner_engine="zap",
            auth_config=json.dumps({"auth_method": request.auth_method})
        )
        
        # Run the authenticated scan in background
        async def run_auth_scan():
            try:
                db.update_scan(scan_id, status="running", phase="initializing")
                
                findings = await zap_scanner.initiate_authenticated_scan(
                    target=request.target,
                    auth_method=request.auth_method,
                    auth_data=request.auth_data,
                    scan_type=request.scan_type,
                    severity=request.severity_filter
                )
                
                # Store findings
                for finding in findings:
                    finding_id = str(uuid.uuid4())
                    db.create_finding(
                        finding_id=finding_id,
                        scan_id=scan_id,
                        **finding
                    )
                
                db.update_scan(
                    scan_id, 
                    status="completed", 
                    phase="done",
                    findings_count=len(findings)
                )
                logger.info(f"[{scan_id}] Auth scan completed: {len(findings)} findings")
            
            except Exception as e:
                tb = traceback.format_exc()
                logger.error(f"[{scan_id}] Auth scan FAILED: {e}\n{tb}")
                db.update_scan(scan_id, status="failed", phase="error", error=f"{type(e).__name__}: {e}")
        
        background_tasks.add_task(run_auth_scan)
        
        return ScanResponse(
            scan_id=scan_id, 
            status="queued", 
            message=f"ZAP authenticated scan ({request.auth_method}) queued for {request.target}"
        )
    
    except Exception as e:
        logger.error(f"Failed to create authenticated scan: {e}")
        raise HTTPException(400, f"Failed to create authenticated scan: {e}")


@app.get("/api/scans")
async def list_scans(limit: int = Query(50, le=200), offset: int = Query(0, ge=0),
                     status: Optional[str] = None, target: Optional[str] = None):
    if target:
        return db.get_scans_by_target(target, limit=limit)
    return db.get_scans(limit=limit, offset=offset, status=status)

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan

@app.get("/api/scans/{scan_id}/progress/stream")
async def stream_scan_progress(scan_id: str):
    """
    Server-Sent Events (SSE) stream that pushes real-time scan phase updates to the browser.
    Emits a JSON event every 2 seconds until the scan reaches 'completed' or 'failed'.
    """
    async def event_generator():
        try:
            while True:
                scan = db.get_scan(scan_id)
                if not scan:
                    yield f"data: {json.dumps({'error': 'Scan not found'})}\n\n"
                    break

                payload = {
                    "scan_id": scan_id,
                    "status": scan["status"],
                    "phase": scan.get("phase", "initializing"),
                    "raw_finding_count": scan.get("raw_finding_count", 0),
                    "unique_finding_count": scan.get("unique_finding_count", 0),
                    "error": scan.get("error"),
                }
                yield f"data: {json.dumps(payload)}\n\n"

                if scan["status"] in ("completed", "failed"):
                    break

                await asyncio.sleep(2)
        except asyncio.CancelledError:
            pass  # Client disconnected

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    db.delete_scan(scan_id)
    return {"message": "Scan deleted"}


@app.post("/api/scans/{scan_id}/rescan", response_model=ScanResponse, status_code=201)
async def rescan(scan_id: str, background_tasks: BackgroundTasks):
    """Re-run a scan using the original configuration (full rescan — incremental is skipped)."""
    original = db.get_scan(scan_id)
    if not original:
        raise HTTPException(404, "Scan not found")
    try:
        config_dict = json.loads(original["config"])
        # Always force a full rescan — do not skip any URLs from previous runs
        config_dict["force_full_scan"] = True
        request = ScanRequest(**config_dict)
    except Exception as e:
        raise HTTPException(400, f"Could not parse original scan config: {e}")
    new_id = str(uuid.uuid4())
    auth_json = request.auth_config.model_dump_json() if request.auth_config else None
    db.create_scan(
        scan_id=new_id, target=request.target, scan_type=request.scan_type,
        config=request.model_dump_json(), scanner_engine=request.scanner_engine,
        auth_config=auth_json,
    )
    db.update_scan(new_id, parent_scan_id=scan_id)
    background_tasks.add_task(run_scan_pipeline, new_id, request)
    return ScanResponse(scan_id=new_id, status="queued",
                        message=f"Full rescan queued for {request.target} (parent: {scan_id})")


@app.get("/api/targets")
async def list_targets():
    """Return each unique scanned target with scan counts."""
    return db.get_distinct_targets()


@app.get("/api/targets/{target:path}/history")
async def get_target_history(target: str, limit: int = Query(20, le=100)):
    """Return all scans for a specific target, newest first."""
    return db.get_scans_by_target(target, limit=limit)


# ── Schedule endpoints ────────────────────────────────────────────────────────

@app.get("/api/schedules")
async def list_schedules():
    return db.get_schedules()


@app.post("/api/schedules", status_code=201)
async def create_schedule(request: ScanScheduleRequest):
    INTERVAL_HOURS = {"daily": 24, "weekly": 168, "monthly": 720}
    hours = INTERVAL_HOURS.get(request.interval, 168)
    next_run = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    sched_id = str(uuid.uuid4())
    # Store a ScanRequest-compatible config (drop interval field)
    scan_cfg = ScanRequest(
        target=request.target, scan_type=request.scan_type,
        scanner_engine=request.scanner_engine, severity_filter=request.severity_filter,
        tags=request.tags, generate_poc=request.generate_poc,
        ai_analysis=request.ai_analysis, auth_config=request.auth_config,
    )
    db.create_schedule(
        schedule_id=sched_id, target=request.target,
        config=scan_cfg.model_dump_json(), interval=request.interval, next_run=next_run,
    )
    return db.get_schedule(sched_id)


@app.patch("/api/schedules/{schedule_id}")
async def update_schedule(schedule_id: str, enabled: Optional[bool] = None,
                          interval: Optional[str] = None):
    sched = db.get_schedule(schedule_id)
    if not sched:
        raise HTTPException(404, "Schedule not found")
    updates = {}
    if enabled is not None:
        updates["enabled"] = 1 if enabled else 0
    if interval:
        INTERVAL_HOURS = {"daily": 24, "weekly": 168, "monthly": 720}
        hours = INTERVAL_HOURS.get(interval, 168)
        updates["interval"] = interval
        updates["next_run"] = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    if updates:
        db.update_schedule(schedule_id, **updates)
    return db.get_schedule(schedule_id)


@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    if not db.get_schedule(schedule_id):
        raise HTTPException(404, "Schedule not found")
    db.delete_schedule(schedule_id)
    return {"message": "Schedule deleted"}


@app.get("/api/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: str, severity: Optional[str] = None, status: Optional[str] = None, scanner_source: Optional[str] = None, limit: int = Query(500, le=2000)):
    return db.get_findings(scan_id=scan_id, severity=severity, status=status, scanner_source=scanner_source, limit=limit)

@app.get("/api/findings")
async def list_findings(severity: Optional[str] = None, status: Optional[str] = None,
                        scanner_source: Optional[str] = None,
                        limit: int = Query(100, le=500), offset: int = Query(0, ge=0)):
    return db.get_findings(severity=severity, status=status, scanner_source=scanner_source, limit=limit, offset=offset)

@app.get("/api/findings/{finding_id}")
async def get_finding(finding_id: str):
    finding = db.get_finding(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    return finding

@app.patch("/api/findings/{finding_id}")
async def update_finding(finding_id: str, update: FindingUpdate):
    db.update_finding(finding_id, status=update.status, notes=update.notes, assigned_to=update.assigned_to)
    return {"message": "Finding updated"}

@app.get("/api/dashboard/stats")
async def dashboard_stats():
    return db.get_dashboard_stats()

@app.get("/api/dashboard/severity-trend")
async def severity_trend(days: int = Query(30, le=90)):
    return db.get_severity_trend(days=days)

@app.get("/api/dashboard/top-vulnerabilities")
async def top_vulnerabilities(limit: int = Query(10, le=50)):
    return db.get_top_vulnerabilities(limit=limit)

@app.get("/api/dashboard/attack-surface")
async def attack_surface():
    return db.get_attack_surface()

@app.get("/api/health")
async def health():
    nuclei_ok = await nuclei_scanner.check_health()
    zap_ok = await zap_scanner.check_health()
    return {
        "status": "healthy",
        "nuclei_available": nuclei_ok,
        "zap_available": zap_ok,
        "zap_url": zap_scanner.api_url,
        "ai_provider": "openai",
        "ai_model": ai_analyzer.model,
        "ai_enabled": ai_analyzer.enabled,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── ZST Auth Session Upload ──────────────────────────────────────────────────

@app.post("/api/upload/auth-session")
async def upload_auth_session(file: UploadFile = File(...)):
    """
    Upload a .zst file for ZAP authenticated scanning.

    Two modes are auto-detected from the file content:

    A) JSON auth config (existing behaviour)
       • Native AuthConfig  — {auth_type, cookies/token/…}
       • Browser HAR export — {log: {entries: [...]}}
       • Cookie shorthand   — {cookies: "session=abc; …"}
       • Bearer token       — {token: "eyJ…"}
       • Custom header      — {header_name: "X-API-Key", header_value: "…"}

    B) ZAP authentication script (JS / Groovy / Python)
       Non-JSON content is treated as a ZAP auth script, saved to the
       shared volume (/app/zap-scripts) and loaded into ZAP at scan time.
    """
    if not file.filename or not file.filename.lower().endswith(".zst"):
        raise HTTPException(400, "Only .zst files are supported")

    content = await file.read()
    if not content:
        raise HTTPException(400, "Uploaded file is empty")
    if len(content) > 10 * 1024 * 1024:  # 10 MB guard
        raise HTTPException(400, "File too large (max 10 MB)")

    raw = _parse_zst_bytes(content)

    # Try JSON first; fall back to treating the file as a ZAP auth script
    try:
        data = json.loads(raw.decode("utf-8"))
        if _is_zest_script(data):
            # ZAP ZEST recording — parse browser actions / HTTP requests to
            # extract credentials and configure ZAP's native form auth.
            auth_config = _parse_zest_to_auth(data)
            logger.info(
                f"[ZST] Parsed ZEST recording '{file.filename}' "
                f"→ auth_type={auth_config.get('auth_type')} "
                f"login_url={auth_config.get('login_url')}"
            )
        else:
            auth_config = _extract_auth_config(data)
            logger.info(f"[ZST] Parsed JSON session '{file.filename}': auth_type={auth_config.get('auth_type')}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Not valid JSON — treat as a JS/Groovy/Python ZAP auth script
        auth_config = _save_zap_script(raw, file.filename)
        logger.info(f"[ZST] Saved text auth script '{file.filename}' → script_name={auth_config['script_name']}")
    except HTTPException:
        # Valid JSON but unrecognised structure — treat as a ZAP auth script
        auth_config = _save_zap_script(raw, file.filename)
        logger.info(f"[ZST] Unrecognised JSON; saved as auth script '{file.filename}' → script_name={auth_config['script_name']}")

    return {"auth_config": auth_config, "source_file": file.filename}


# ── SIDE File Upload (Selenium IDE)────────────────────────────────────────────

def _parse_side_file(content: bytes) -> Dict[str, Any]:
    """
    Parse a Selenium IDE .side file (JSON format) to extract test data and auth flows.

    SIDE file format:
    {
        "tests": [
            {
                "name": "Login Test",
                "commands": [
                    {"command": "open", "target": "/login", ...},
                    {"command": "settext", "target": "id=username", "value": "admin"},
                    {"command": "settext", "target": "id=password", "value": "password"},
                    {"command": "click", "target": "id=loginBtn"},
                    {"command": "waitforelementtobeclickable", "target": "id=dashboard"}
                ]
            }
        ],
        "suites": [...]
    }
    """
    try:
        data = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise HTTPException(400, f"Invalid .side file format: {str(e)}")

    result = {
        "format": "selenium-ide",
        "base_url": data.get("url", "").rstrip("/"),
        "tests": [],
        "auth_hints": {
            "login_url": None,
            "username_field": None,
            "password_field": None,
            "username_value": None,
            "password_value": None,
            "success_indicator": None,
        },
    }

    # Extract test information
    tests = data.get("tests", [])
    if not tests:
        raise HTTPException(400, "No tests found in .side file. Ensure the file contains at least one test.")

    for test in tests:
        test_name = test.get("name", "Unknown")
        commands = test.get("commands", [])

        if not commands:
            logger.warning(f"[SIDE] Test '{test_name}' has no commands, skipping")
            continue

        # Parse commands to find auth-related actions
        login_test = {
            "name": test_name,
            "commands": commands,
            "is_login_test": False,
            "login_url": None,
            "form_fields": {},
        }

        # Track if we found any auth-related data
        found_username = False
        found_password = False
        has_text_input = False
        first_url = None

        for i, cmd in enumerate(commands):
            cmd_type = cmd.get("command", "").lower()
            target = cmd.get("target", "")
            value = cmd.get("value", "")

            # Detect login page open (optional, but helpful)
            if cmd_type == "open":
                # Capture first URL as fallback
                if first_url is None:
                    first_url = target
                
                login_test["login_url"] = target
                if "login" in target.lower() or "auth" in target.lower() or "signin" in target.lower():
                    login_test["is_login_test"] = True
                # Always set login_url from first open command if not set
                if not result["auth_hints"]["login_url"]:
                    result["auth_hints"]["login_url"] = target

            # Detect form field fills - more flexible matching
            if cmd_type in ("settext", "type"):
                has_text_input = True
                # Extract field name/id - handle both "id=xyz" and "css=..." patterns
                field_name = ""
                if "=" in target:
                    field_name = target.split("=", 1)[1]  # Get everything after first =
                else:
                    field_name = target
                
                field_name_lower = field_name.lower()

                # Check for username/email fields
                if (any(word in field_name_lower for word in ["user", "login", "email", "username", "uid", "handle", "account"]) 
                    and "pass" not in field_name_lower):  # Exclude password fields
                    result["auth_hints"]["username_field"] = field_name
                    result["auth_hints"]["username_value"] = value
                    login_test["form_fields"]["username"] = field_name
                    found_username = True
                    logger.debug(f"[SIDE] Found username field: {field_name}")

                # Check for password fields
                elif any(word in field_name_lower for word in ["pass", "pwd", "password", "secret", "pw"]):
                    result["auth_hints"]["password_field"] = field_name
                    result["auth_hints"]["password_value"] = value
                    login_test["form_fields"]["password"] = field_name
                    found_password = True
                    logger.debug(f"[SIDE] Found password field: {field_name}")

            # Detect success indicators (wait for element, verify, etc)
            if cmd_type in ("waitforelementtobeclickable", "waitforelementvisible", "verifyelementpresent", "assertelementpresent"):
                success_text = target.lower()
                if any(x in success_text for x in ["dashboard", "home", "welcome", "profile", "logout", "main", "workspace", "app"]):
                    result["auth_hints"]["success_indicator"] = target
                    login_test["success_target"] = target

        # Mark as login test if we found username/password fields OR if it has text inputs
        if found_username or found_password or (has_text_input and len(commands) > 2):
            login_test["is_login_test"] = True

        result["tests"].append(login_test)

    logger.info(f"[SIDE] Parsed SIDE file: {len(result['tests'])} tests")
    logger.debug(f"[SIDE] Auth hints: {result['auth_hints']}")

    # Validate and provide defaults for login_url
    if not result["auth_hints"]["login_url"]:
        # Try to get login_url from tests
        for test in result["tests"]:
            if test.get("login_url"):
                result["auth_hints"]["login_url"] = test["login_url"]
                break
    
    # If still no login_url, provide helpful error
    if not result["auth_hints"]["login_url"]:
        raise HTTPException(400, "No 'open' command found in test. Ensure the test starts with 'open' command to navigate to login page.")

    # Set sensible defaults if fields weren't auto-detected
    if not result["auth_hints"]["username_field"] and not result["auth_hints"]["password_field"]:
        # If no explicit fields found, use generic instructions
        logger.warning("[SIDE] Could not automatically detect auth fields. User must specify manually.")
        result["auth_hints"]["username_field"] = "username"
        result["auth_hints"]["password_field"] = "password"

    logger.info(f"[SIDE] Extracted auth config: login_url={result['auth_hints']['login_url']}, "
                f"username_field={result['auth_hints']['username_field']}, "
                f"password_field={result['auth_hints']['password_field']}")

    return result


@app.post("/api/upload/selenium-test")
async def upload_side_file(file: UploadFile = File(...)):
    """
    Upload a .side (Selenium IDE) file for automated authenticated scanning.

    Supports:
      - Selenium IDE test recording (.side JSON format)
      - Extracts login flows and authentication data
      - Returns test data and suggested auth configuration
    """
    if not file.filename or not file.filename.lower().endswith(".side"):
        raise HTTPException(400, "Only .side files are supported")

    content = await file.read()
    if not content:
        raise HTTPException(400, "Uploaded file is empty")
    if len(content) > 10 * 1024 * 1024:  # 10 MB guard
        raise HTTPException(400, "File too large (max 10 MB)")

    try:
        side_data = _parse_side_file(content)
        logger.info(f"[SIDE] Processed file '{file.filename}' → {len(side_data['tests'])} tests")

        return {
            "format": "selenium-ide",
            "filename": file.filename,
            "tests_count": len(side_data["tests"]),
            "auth_configuration": side_data["auth_hints"],
            "tests": side_data["tests"],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SIDE] File parsing failed: {e}")
        raise HTTPException(400, f"Failed to parse .side file: {str(e)}")


# ── Selenium Authentication Capture ──────────────────────────────────────────

@app.post("/api/auth/capture-session-selenium")
async def capture_session_selenium(request: SeleniumAuthRequest):
    """
    Perform browser-based login using Selenium and capture session data.

    Captures cookies, JWT tokens, and localStorage/sessionStorage data.
    Browser is connected to ZAP proxy for traffic monitoring.
    """
    try:
        logger.info(f"[Selenium] Capturing session for {request.login_url}")

        selenium_auth = SeleniumAuthCapture(
            zap_proxy_host=request.zap_proxy_host,
            zap_proxy_port=request.zap_proxy_port,
        )

        result = await selenium_auth.capture_session(
            login_url=request.login_url,
            username=request.username,
            password=request.password,
            username_field=request.username_field,
            password_field=request.password_field,
            logged_in_indicator=request.logged_in_indicator,
            authenticated_pages=request.authenticated_pages,
        )

        if result["success"]:
            logger.info(f"[Selenium] ✓ Session captured: {result['auth_type']}")
            return result
        else:
            logger.warning(f"[Selenium] ✗ Capture failed: {result['message']}")
            raise HTTPException(400, result["message"])

    except Exception as e:
        logger.error(f"[Selenium] Capture failed: {e}")
        raise HTTPException(500, f"Session capture failed: {str(e)}")


# ── Authenticated Scan Orchestration ─────────────────────────────────────────

async def run_authenticated_scan_pipeline(
    scan_id: str,
    request: AuthenticatedScanOrchestrationRequest,
    background_tasks: BackgroundTasks,
):
    """
    Complete authenticated scan workflow:
    1. Selenium browser login → 2. Session capture → 3. ZAP injection → 4. Scanning.
    """
    try:
        logger.info(f"[Auth Scan] ▶ Starting authenticated scan pipeline for {scan_id}")
        db.update_scan(scan_id, status="authenticating", phase="initializing")

        # Step 1: Selenium login and session capture
        logger.info(f"[Auth Scan] Phase 1: Browser login to {request.login_url}")
        db.update_scan(scan_id, phase="selenium_login")

        selenium_auth = SeleniumAuthCapture()
        session_result = await selenium_auth.capture_session(
            login_url=request.login_url,
            username=request.username,
            password=request.password,
            username_field=request.username_field,
            password_field=request.password_field,
            logged_in_indicator=request.logged_in_indicator,
            authenticated_pages=request.authenticated_pages,
        )

        if not session_result["success"]:
            logger.error(f"[Auth Scan] Login failed: {session_result['message']}")
            db.update_scan(
                scan_id,
                status="failed",
                phase="error",
                error=session_result["message"],
            )
            return

        db.update_scan(scan_id, auth_status=json.dumps({
            "verified": session_result.get("success", False),
            "message": session_result.get("message", ""),
            "auth_type": session_result.get("auth_type"),
            "cookies_captured": len(session_result.get("cookies") or {}),
            "auth_screenshot": session_result.get("auth_screenshot"),
        }))
        logger.info(f"[Auth Scan] ✓ Session captured: {session_result['auth_type']}")

        # Step 2: Inject session into ZAP
        logger.info(f"[Auth Scan] Phase 2: Injecting session into ZAP")
        db.update_scan(scan_id, phase="zap_session_injection")

        zap_injector = ZapSessionInjector()
        injection_result = await zap_injector.inject_session(
            target_url=request.target,
            session_data=session_result,
        )

        if not injection_result["success"]:
            logger.warning(
                f"[Auth Scan] Session injection had issues: {injection_result['message']}"
            )

        logger.info(f"[Auth Scan] ✓ Session injected: {injection_result['auth_type']}")

        # Step 3: Configure ZAP context
        logger.info(f"[Auth Scan] Phase 3: Configuring ZAP context")
        db.update_scan(scan_id, phase="zap_context_config")

        zap_context = ZapContextConfig()
        exclude_urls = request.exclude_logout_urls or [r".*logout.*", r".*signout.*"]

        context_result = await zap_context.create_context(
            target_url=request.target,
            context_name=f"scan_{scan_id}",
            exclude_urls=exclude_urls,
        )

        if not context_result["success"]:
            logger.warning(
                f"[Auth Scan] Context creation had issues: {context_result['message']}"
            )

        logger.info(f"[Auth Scan] ✓ Context created: {context_result['context_name']}")

        # Step 4: Run authenticated scan
        logger.info(f"[Auth Scan] Phase 4: Running authenticated scan")
        db.update_scan(scan_id, status="scanning", phase="zap_spider")

        # Build re-auth config so the orchestrator can re-login if the session expires mid-scan
        reauth_config = {
            "login_url": request.login_url,
            "username": request.username,
            "password": request.password,
            "username_field": request.username_field,
            "password_field": request.password_field,
            "logged_in_indicator": request.logged_in_indicator,
        }

        # Fetch crawled URLs from the previous scan of this target for incremental mode
        previous_urls = db.get_previous_crawled_urls(request.target)
        if previous_urls:
            logger.info(
                f"[Auth Scan] Incremental mode: {len(previous_urls)} known URLs from previous scan of {request.target}"
            )

        zap_orchestrator = ZapScanOrchestrator()
        scan_result = await zap_orchestrator.run_authenticated_scan(
            target_url=request.target,
            context_name=context_result["context_name"],
            scan_type=request.scan_type,
            timeout_minutes=request.timeout_minutes,
            logged_in_indicator=request.logged_in_indicator,
            reauth_config=reauth_config,
            previous_urls=previous_urls if previous_urls else None,
        )

        if not scan_result["success"]:
            logger.error(f"[Auth Scan] Scan failed: {scan_result['message']}")
            db.update_scan(
                scan_id,
                status="failed",
                phase="error",
                error=scan_result["message"],
            )
            return

        logger.info(
            f"[Auth Scan] ✓ Scan completed: {scan_result['urls_found']} URLs, "
            f"{scan_result['alerts_found']} alerts"
        )

        # Step 5: Process findings (similar to regular scan)
        db.update_scan(scan_id, phase="processing")

        # Normalize ZAP alerts to our format
        findings = []
        for alert in scan_result.get("alerts", []):
            finding = zap_scanner._normalize_alert(alert)
            if finding and finding["severity"] in request.severity_filter:
                findings.append(finding)

        logger.info(f"[Auth Scan] {len(findings)} findings after filtering")

        # Deduplication
        db.update_scan(scan_id, phase="deduplication")
        unique_findings = dedup.deduplicate(findings, scan_id)
        logger.info(f"[Auth Scan] {len(unique_findings)} unique findings after dedup")

        # False positive filtering
        db.update_scan(scan_id, phase="fp_filtering")
        unique_findings, _fp = filter_false_positives(unique_findings)

        # HTTP Replay Verification — re-send attack requests with the live session
        try:
            scan_row = db.get_scan(scan_id)
            verifier = _make_replay_verifier(
                auth=None,
                auth_status_json=scan_row.get("auth_status") if scan_row else None,
            )
            unique_findings, _unverified = await verifier.verify(unique_findings)
            if _unverified:
                logger.info(f"[Auth Scan] Replay: {len(_unverified)} transient FPs removed")
        except Exception as re_err:
            logger.error(f"[Auth Scan] Replay verification failed (non-fatal): {re_err}")

        # AI-assisted FP scoring (low/medium confidence ZAP findings)
        db.update_scan(scan_id, phase="ai_fp_scoring")
        unique_findings, ai_fp_findings = await ai_fp_scorer.score(unique_findings)
        if ai_fp_findings:
            logger.info(
                f"[Auth Scan] AI-FP scorer: {len(ai_fp_findings)} removed, "
                f"{len(unique_findings)} retained"
            )

        # Store findings
        db.update_scan(scan_id, phase="storing_findings")
        for finding in unique_findings:
            finding["scan_id"] = scan_id
            finding["id"] = str(uuid.uuid4())
            finding["status"] = "open"
            finding["created_at"] = datetime.now(timezone.utc).isoformat()
            db.insert_finding(finding)

        # AI analysis
        if request.ai_analysis and unique_findings:
            db.update_scan(scan_id, phase="ai_analysis")
            try:
                ai_results = await ai_analyzer.analyze_findings(unique_findings, request.target)
                db.update_scan(scan_id, ai_analysis=json.dumps(ai_results))
                for enrichment in ai_results.get("enrichments", []):
                    fid = enrichment.get("finding_id")
                    if fid:
                        db.update_finding(fid, ai_analysis=json.dumps(enrichment))
            except Exception as e:
                logger.error(f"[Auth Scan] AI analysis failed: {e}")

        # PoC generation
        if request.generate_poc and unique_findings:
            db.update_scan(scan_id, phase="evidence_capture")
            # Similar to regular scan pipeline...

        # Persist crawled URL list for use by the next incremental scan of this target
        crawled_urls = scan_result.get("crawled_urls", [])
        db.update_scan(
            scan_id,
            status="completed",
            phase="done",
            raw_finding_count=len(findings),
            unique_finding_count=len(unique_findings),
            completed_at=datetime.now(timezone.utc).isoformat(),
            crawled_urls=json.dumps(crawled_urls) if crawled_urls else None,
        )

        logger.info(
            f"[Auth Scan] ✓ Pipeline completed for {scan_id} "
            f"(stored {len(crawled_urls)} crawled URLs for incremental re-scan)"
        )

    except Exception as e:
        logger.error(f"[Auth Scan] Pipeline failed: {e}", exc_info=True)
        db.update_scan(
            scan_id,
            status="failed",
            phase="error",
            error=str(e),
        )


@app.post("/api/scans/authenticated/run")
async def run_authenticated_scan(
    request: AuthenticatedScanOrchestrationRequest,
    background_tasks: BackgroundTasks,
):
    """
    Start a complete authenticated security scan workflow.

    Orchestrates:
      1. Selenium-based browser login
      2. Session capture (cookies/JWT/Bearer token)
      3. Session injection into ZAP
      4. ZAP context setup with excluded URLs
      5. ZAP spidering and active scanning
      6. Finding processing (dedup, FP filter, AI analysis)

    Returns scan ID for monitoring progress.
    """
    try:
        scan_id = str(uuid.uuid4())
        logger.info(f"[Auth Scan] Starting authenticated scan {scan_id}")

        # Create scan record
        db.insert_scan(
            scan_id=scan_id,
            target=request.target,
            scan_type=request.scan_type,
            scanner_engine="zap",
            status="queued",
            phase="initializing",
        )

        # Queue the scanning pipeline as background task
        background_tasks.add_task(
            run_authenticated_scan_pipeline,
            scan_id,
            request,
            background_tasks,
        )

        logger.info(f"[Auth Scan] Scan {scan_id} queued; monitoring URL: /api/scans/{scan_id}")

        return ScanResponse(
            scan_id=scan_id,
            status="queued",
            message=f"Authenticated scan queued. Target: {request.target}. Monitor at /api/scans/{scan_id}",
        )

    except Exception as e:
        logger.error(f"[Auth Scan] Failed to start scan: {e}")
        raise HTTPException(500, f"Failed to start scan: {str(e)}")


async def run_integrated_auth_scan_pipeline(
    scan_id: str,
    side_file_content: bytes,
    target: str,
    run_scan: bool,
    timeout_minutes: int,
):
    """
    Background pipeline for integrated authenticated scanning.
    Parses .side file → Playwright login → ZAP injection → spider/active scan → stores findings.
    Uses the Playwright-based SeleniumAuthCapture (available in container) instead of
    spawning a subprocess for the Selenium WebDriver-based selinium tool.
    """
    import httpx as _httpx

    zap_api_url = os.getenv("ZAP_API_URL", "http://zap:8080")
    zap_api_key = os.getenv("ZAP_API_KEY", "vulnforge-zap-key")

    try:
        db.update_scan(scan_id, status="scanning", phase="initializing")

        # ── Phase 1: Parse .side file for login hints ─────────────────────────
        logger.info(f"[{scan_id}] Phase 1: Parsing .side file")
        side_data = _parse_side_file(side_file_content)
        hints = side_data["auth_hints"]
        # Use the base_url from the .side file itself; fall back to target
        side_base_url = side_data.get("base_url") or target.rstrip("/")

        # Collect raw commands from the first test for command-replay mode
        raw_commands = []
        if side_data.get("tests"):
            raw_commands = side_data["tests"][0].get("commands", [])

        logger.info(f"[{scan_id}] base_url={side_base_url}, commands={len(raw_commands)}, "
                    f"username_field={hints.get('username_field')}, "
                    f"password_field={hints.get('password_field')}")

        # ── Phase 2: Playwright browser login + session capture ───────────────
        db.update_scan(scan_id, phase="zap_auth_check")
        logger.info(f"[{scan_id}] Phase 2: Browser login via Playwright (command-replay mode)")

        zap_host = os.getenv("ZAP_HOST", "zap")
        pw_auth = SeleniumAuthCapture(
            zap_proxy_host=zap_host,
            zap_proxy_port=8080,
        )

        if raw_commands:
            # Replay the exact Selenium IDE command sequence — handles multi-step
            # flows like: open home → click Sign In → fill form → submit
            session_result = await pw_auth.capture_session_from_commands(
                commands=raw_commands,
                base_url=side_base_url,
                logged_in_indicator=hints.get("success_indicator"),
            )
        else:
            # Fallback: direct field-fill (single-page login forms)
            from urllib.parse import urljoin
            login_url = hints.get("login_url") or target
            if login_url and not login_url.startswith("http"):
                login_url = urljoin(target, login_url)
            session_result = await pw_auth.capture_session(
                login_url=login_url,
                username=hints.get("username_value"),
                password=hints.get("password_value"),
                username_field=hints.get("username_field") or "username",
                password_field=hints.get("password_field") or "password",
                logged_in_indicator=hints.get("success_indicator"),
            )

        if not session_result.get("success"):
            msg = session_result.get("message", "Login failed")
            logger.warning(f"[{scan_id}] Auth capture warning: {msg} — continuing with available session data")
            # Don't hard-fail; ZAP may still have captured some session data
        else:
            logger.info(f"[{scan_id}] ✓ Session captured: {session_result.get('auth_type')}")

        # Persist auth_status — cookies is a {name: value} dict
        cookies_dict = session_result.get("cookies") or {}
        cookies_captured = len(cookies_dict)
        auth_status_json = json.dumps({
            "verified": session_result.get("success", False),
            "message": session_result.get("message", "Session capture attempted"),
            "auth_type": session_result.get("auth_type", "unknown"),
            "cookies_captured": cookies_captured,
            "auth_screenshot": session_result.get("auth_screenshot"),
        })
        db.update_scan(scan_id, auth_status=auth_status_json)

        # ── Phase 3: Inject session into ZAP via Replacer API ─────────────────
        logger.info(f"[{scan_id}] Phase 3: Injecting session into ZAP")
        async with _httpx.AsyncClient(timeout=15.0) as client:
            # Fetch existing replacer rule descriptions so we only remove rules that exist
            async def _get_replacer_rule_descriptions(c) -> set:
                try:
                    resp = await c.get(
                        f"{zap_api_url}/JSON/replacer/view/rules/",
                        params={"apikey": zap_api_key},
                    )
                    return {r.get("description", "") for r in resp.json().get("rules", [])}
                except Exception:
                    return set()

            # Remove stale replacer rules first (best-effort, only if they exist)
            existing_rules = await _get_replacer_rule_descriptions(client)
            stale_desc = f"auth-cookies-{scan_id}"
            if stale_desc in existing_rules:
                try:
                    await client.get(
                        f"{zap_api_url}/JSON/replacer/action/removeRule/",
                        params={"apikey": zap_api_key, "description": stale_desc},
                    )
                except Exception:
                    pass

            # Build cookie string from the {name: value} dict
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies_dict.items() if k and v)
            if cookie_str:
                try:
                    r = await client.get(
                        f"{zap_api_url}/JSON/replacer/action/addRule/",
                        params={
                            "apikey": zap_api_key,
                            "description": f"auth-cookies-{scan_id}",
                            "enabled": "true",
                            "matchType": "REQ_HEADER",   # camelCase for ZAP 2.17+
                            "matchString": "Cookie",
                            "matchRegex": "false",
                            "replacement": cookie_str,
                            "initiators": "",
                            "url": "",
                        },
                    )
                    if r.status_code == 200:
                        logger.info(f"[{scan_id}] ✓ Cookie header injected into ZAP ({len(cookie_str)} chars)")
                    else:
                        logger.warning(f"[{scan_id}] ZAP replacer addRule returned {r.status_code}: {r.text[:200]}")
                except Exception as e:
                    logger.warning(f"[{scan_id}] Cookie injection warning: {e}")

            # Inject Bearer token if present
            token = session_result.get("token") or session_result.get("bearer_token")
            if token:
                try:
                    r = await client.get(
                        f"{zap_api_url}/JSON/replacer/action/addRule/",
                        params={
                            "apikey": zap_api_key,
                            "description": f"auth-bearer-{scan_id}",
                            "enabled": "true",
                            "matchType": "REQ_HEADER",
                            "matchString": "Authorization",
                            "matchRegex": "false",
                            "replacement": f"Bearer {token}",
                            "initiators": "",
                            "url": "",
                        },
                    )
                    if r.status_code == 200:
                        logger.info(f"[{scan_id}] ✓ Bearer token injected into ZAP")
                    else:
                        logger.warning(f"[{scan_id}] ZAP bearer injection returned {r.status_code}: {r.text[:200]}")
                except Exception as e:
                    logger.warning(f"[{scan_id}] Bearer token injection warning: {e}")

        if not run_scan:
            db.update_scan(
                scan_id, status="completed", phase="done",
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
            return

        # ── Phase 4: ZAP Spider + Active Scan ────────────────────────────────
        db.update_scan(scan_id, phase="zap_spider")
        logger.info(f"[{scan_id}] Phase 4: ZAP Spider + Active Scan for {target}")

        raw_alerts = []
        # Use longer read timeout — ZAP alerts endpoint can be slow with many findings
        _zap_timeout = _httpx.Timeout(connect=10.0, read=180.0, write=10.0, pool=10.0)
        async with _httpx.AsyncClient(timeout=_zap_timeout) as client:
            # Spider
            r = await client.get(f"{zap_api_url}/JSON/spider/action/scan/",
                                  params={"apikey": zap_api_key, "url": target})
            spider_id = r.json().get("scan", "0")
            logger.info(f"[{scan_id}] Spider started, id={spider_id}")

            deadline = asyncio.get_event_loop().time() + timeout_minutes * 60
            while asyncio.get_event_loop().time() < deadline:
                r = await client.get(f"{zap_api_url}/JSON/spider/view/status/",
                                      params={"apikey": zap_api_key, "scanid": spider_id})
                pct = int(r.json().get("status", 0))
                if pct >= 100:
                    break
                logger.info(f"[{scan_id}] Spider {pct}%")
                await asyncio.sleep(10)

            # Active scan
            db.update_scan(scan_id, phase="zap_scan")
            r = await client.get(f"{zap_api_url}/JSON/ascan/action/scan/",
                                  params={"apikey": zap_api_key, "url": target})
            ascan_id = r.json().get("scan", "0")
            logger.info(f"[{scan_id}] Active scan started, id={ascan_id}")

            while asyncio.get_event_loop().time() < deadline:
                r = await client.get(f"{zap_api_url}/JSON/ascan/view/status/",
                                      params={"apikey": zap_api_key, "scanid": ascan_id})
                pct = int(r.json().get("status", 0))
                if pct >= 100:
                    break
                logger.info(f"[{scan_id}] Active scan {pct}%")
                await asyncio.sleep(15)

            # Collect alerts
            r = await client.get(f"{zap_api_url}/JSON/core/view/alerts/",
                                  params={"apikey": zap_api_key, "baseurl": target})
            raw_alerts = r.json().get("alerts", [])
            logger.info(f"[{scan_id}] ZAP returned {len(raw_alerts)} alerts")

            # Clean up replacer rules (only remove rules that actually exist)
            try:
                existing_cleanup = {
                    r.get("description", "")
                    for r in (await client.get(
                        f"{zap_api_url}/JSON/replacer/view/rules/",
                        params={"apikey": zap_api_key},
                    )).json().get("rules", [])
                }
            except Exception:
                existing_cleanup = set()
            for desc in [f"auth-cookies-{scan_id}", f"auth-bearer-{scan_id}"]:
                if desc not in existing_cleanup:
                    continue
                try:
                    await client.get(f"{zap_api_url}/JSON/replacer/action/removeRule/",
                                      params={"apikey": zap_api_key, "description": desc})
                except Exception:
                    pass

        # ── Phase 5: Deduplicate, filter, store findings ───────────────────────
        db.update_scan(scan_id, raw_finding_count=len(raw_alerts), phase="deduplication")

        # Build messageId → alert lookup (first occurrence per URL+pluginId) for HTTP capture
        msg_id_map: dict[str, str] = {}  # dedup_key → messageId
        all_raw_findings = []
        for alert in raw_alerts:
            finding = zap_scanner._normalize_alert(alert)
            if finding:
                finding["scanner_source"] = "zap"
                # Store messageId temporarily (not a DB column yet) for later HTTP fetch
                finding["_zap_message_id"] = str(alert.get("messageId", ""))
                all_raw_findings.append(finding)

        unique_findings = dedup.deduplicate(all_raw_findings, scan_id)
        logger.info(f"[{scan_id}] {len(unique_findings)} unique findings after dedup")

        db.update_scan(scan_id, phase="fp_filtering")
        unique_findings, _fp = filter_false_positives(unique_findings)

        # AI-assisted FP scoring (low/medium confidence ZAP findings)
        db.update_scan(scan_id, phase="ai_fp_scoring")
        unique_findings, ai_fp_findings = await ai_fp_scorer.score(unique_findings)
        if ai_fp_findings:
            logger.info(
                f"[{scan_id}] AI-FP scorer: {len(ai_fp_findings)} removed, "
                f"{len(unique_findings)} retained"
            )

        # ── Fetch HTTP request/response from ZAP for unique findings ──────────
        logger.info(f"[{scan_id}] Fetching HTTP messages for {len(unique_findings)} unique findings")
        async with _httpx.AsyncClient(timeout=10.0) as msg_client:
            for finding in unique_findings:
                msg_id = finding.pop("_zap_message_id", None)
                if not msg_id:
                    continue
                try:
                    mr = await msg_client.get(
                        f"{zap_api_url}/JSON/core/view/message/",
                        params={"apikey": zap_api_key, "id": msg_id},
                    )
                    msg = mr.json().get("message", {})
                    req_header = msg.get("requestHeader", "").strip()
                    req_body = msg.get("requestBody", "").strip()
                    resp_header = msg.get("responseHeader", "").strip()
                    resp_body = msg.get("responseBody", "").strip()
                    if req_header:
                        finding["http_request"] = req_header + ("\r\n\r\n" + req_body if req_body else "")
                    if resp_header:
                        # Truncate large response bodies to 8KB for storage
                        resp_body_trunc = resp_body[:8192] + ("…[truncated]" if len(resp_body) > 8192 else "")
                        finding["http_response"] = resp_header + ("\r\n\r\n" + resp_body_trunc if resp_body_trunc else "")
                except Exception as e:
                    logger.debug(f"[{scan_id}] HTTP message fetch failed for msg {msg_id}: {e}")
                    finding.pop("_zap_message_id", None)

        # ── HTTP Replay Verification (runs after http_request is populated) ──
        # http_request is now filled above — replay can use the exact raw request.
        try:
            scan_row = db.get_scan(scan_id)
            verifier = _make_replay_verifier(
                auth=None,
                auth_status_json=scan_row.get("auth_status") if scan_row else None,
            )
            unique_findings, _unverified = await verifier.verify(unique_findings)
            if _unverified:
                logger.info(f"[{scan_id}] Replay: {len(_unverified)} transient FPs removed")
        except Exception as re_err:
            logger.error(f"[{scan_id}] Replay verification failed (non-fatal): {re_err}")

        db.update_scan(scan_id, unique_finding_count=len(unique_findings), phase="storing_findings")
        for finding in unique_findings:
            finding.pop("_zap_message_id", None)  # clean up any remaining temp field
            finding["scan_id"] = scan_id
            finding["id"] = str(uuid.uuid4())
            finding["status"] = "open"
            finding["created_at"] = datetime.now(timezone.utc).isoformat()
            db.insert_finding(finding)

        # ── Phase 6: AI analysis ──────────────────────────────────────────────
        if unique_findings:
            db.update_scan(scan_id, phase="ai_analysis")
            try:
                ai_results = await ai_analyzer.analyze_findings(unique_findings, target)
                db.update_scan(scan_id, ai_analysis=json.dumps(ai_results))
                for enrichment in ai_results.get("enrichments", []):
                    fid = enrichment.get("finding_id")
                    if fid:
                        db.update_finding(fid, ai_analysis=json.dumps(enrichment))
            except Exception as e:
                logger.error(f"[{scan_id}] AI analysis failed: {e}")

        # ── Phase 7: Evidence capture (steps + screenshots) ───────────────────
        if unique_findings:
            db.update_scan(scan_id, phase="evidence_capture")
            semaphore = asyncio.Semaphore(5)

            async def _run_poc(finding: dict):
                async with semaphore:
                    try:
                        url = finding.get("matched_at") or finding.get("url") or finding.get("host", "")
                        screenshot_path = os.path.join("screenshots", f"{finding['id']}.png")
                        if poc_gen._browser and url:
                            try:
                                await poc_gen._capture_screenshot(url, screenshot_path, finding=finding)
                            except Exception as e:
                                logger.warning(f"[{scan_id}] Screenshot failed for {url}: {e}")

                        steps = _build_template_steps(finding)
                        existing: dict = {}
                        if finding.get("extracted_results"):
                            try:
                                existing = (json.loads(finding["extracted_results"])
                                            if isinstance(finding["extracted_results"], str)
                                            else finding["extracted_results"])
                            except (json.JSONDecodeError, TypeError):
                                pass
                        existing["steps_to_reproduce"] = steps
                        db.update_finding(
                            finding["id"],
                            poc_screenshot=screenshot_path if os.path.exists(screenshot_path) else "",
                            extracted_results=json.dumps(existing),
                        )
                    except Exception as e:
                        logger.error(f"[{scan_id}] Evidence capture failed: {e}")

            await asyncio.gather(*[_run_poc(f) for f in unique_findings])

        db.update_scan(
            scan_id, status="completed", phase="done",
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        logger.info(f"[{scan_id}] ✓ Integrated auth scan complete — {len(unique_findings)} findings")

    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"[{scan_id}] Integrated auth pipeline FAILED: {e}\n{tb}")
        db.update_scan(scan_id, status="failed", phase="error", error=f"{type(e).__name__}: {e}")


@app.post("/api/scans/authenticated/integrated")
async def run_integrated_authenticated_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    target: str = Query(...),
    run_scan: bool = Query(default=True),
    timeout_minutes: int = Query(default=60),
):
    """
    Complete authenticated scanning using Selenium IDE (.side file) integrated with ZAP.

    This endpoint:
    1. Accepts a .side file (Selenium IDE recording)
    2. Runs Selenium to execute the login flow and extract session
    3. Injects session into ZAP
    4. Optionally runs spider + active scan
    5. Processes and stores all findings (dedup, FP filter, AI analysis, screenshots)

    Returns scan_id immediately; scan runs in the background.
    """
    if not file.filename or not file.filename.lower().endswith(".side"):
        raise HTTPException(400, "Only .side files are supported")

    content = await file.read()
    if not content:
        raise HTTPException(400, "Uploaded file is empty")
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(400, "File too large (max 10 MB)")

    scan_id = str(uuid.uuid4())
    logger.info(f"[Integrated Auth Scan] Queuing scan {scan_id} for {target}")

    db.create_scan(
        scan_id=scan_id,
        target=target,
        scan_type="integrated-auth",
        scanner_engine="zap",
        config=json.dumps({
            "file": file.filename,
            "run_scan": run_scan,
            "timeout_minutes": timeout_minutes,
        }),
        auth_config=json.dumps({"auth_type": "selenium-side", "side_file": file.filename}),
    )

    background_tasks.add_task(
        run_integrated_auth_scan_pipeline,
        scan_id, content, target, run_scan, timeout_minutes,
    )

    return {
        "scan_id": scan_id,
        "status": "queued",
        "target": target,
        "message": f"Authenticated scan queued. Monitor progress at /api/scans/{scan_id}",
    }


@app.get("/api/scans/{scan_id}/report/pdf")
async def export_scan_pdf(scan_id: str):
    """Generate and download a PDF report for a specific scan."""
    try:
        scan = db.get_scan(scan_id)
        if not scan:
            logger.warning(f"[PDF] Scan {scan_id} not found")
            raise HTTPException(404, "Scan not found")

        findings = db.get_findings(scan_id=scan_id)
        if not findings:
            findings = []

        # Convert scan row to dict
        scan_dict = dict(scan)

        logger.info(f"[PDF] Generating report for scan {scan_id} with {len(findings)} findings...")

        # Generate PDF
        pdf_buffer = pdf_generator.generate_report(
            scan=scan_dict,
            findings=findings,
            report_title=f"Vulnerability Scan Report — {scan_dict.get('target', 'Unknown')}",
        )

        pdf_data = pdf_buffer.getvalue()
        logger.info(f"[PDF] Report generated successfully — {len(pdf_data)} bytes")

        # Return as streaming response with proper headers
        return StreamingResponse(
            iter([pdf_data]),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="report_{scan_id}.pdf"',
                "Content-Length": str(len(pdf_data)),
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[PDF] Report generation failed for scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(500, f"Failed to generate report: {str(e)}")



@app.get("/api/scans/report/bulk-pdf")
async def export_bulk_pdf(target: Optional[str] = None, status: Optional[str] = None):
    """Generate PDF reports for multiple scans grouped by target."""
    scans = db.get_scans(limit=1000)
    if not scans:
        raise HTTPException(404, "No scans found")

    # Group by target
    grouped = {}
    for scan in scans:
        target_url = scan.get("target", "unknown")
        if target_url not in grouped:
            grouped[target_url] = []
        grouped[target_url].append(dict(scan))

    # For now, generate the first target's report
    if grouped:
        target_scans = list(grouped.values())[0]
        scan_dict = target_scans[0]

        findings = db.get_findings(scan_id=scan_dict["scan_id"])
        if not findings:
            findings = []

        try:
            pdf_buffer = pdf_generator.generate_report(
                scan=scan_dict,
                findings=findings,
                report_title=f"Vulnerability Scan Report — {scan_dict.get('target', 'Unknown')}",
            )

            return StreamingResponse(
                iter([pdf_buffer.getvalue()]),
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="report_{scan_dict.get("target", "scan").replace("/", "_").replace(":", "")}.pdf"'
                },
            )
        except Exception as e:
            logger.error(f"[PDF] Bulk report generation failed: {e}")
            raise HTTPException(500, f"Failed to generate report: {str(e)}")

    raise HTTPException(404, "No reports could be generated")
