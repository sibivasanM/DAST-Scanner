"""
Vulnerability scanner — Automated Penetration Testing Platform
Core API Server — Nuclei + ZAP authenticated scanning, OpenAI GPT-4o analysis
"""

import asyncio
import json
import logging
import os
import traceback
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from modules.database import Database
from modules.scanner import NucleiScanner
from modules.zap_scanner import ZapScanner
from modules.dedup import DeduplicationEngine
from modules.ai_analyzer import AIAnalyzer
from modules.poc_generator import PoCGenerator
from modules.pdf_report import PDFReportGenerator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("vulnforge")

# ── Pydantic Models ──────────────────────────────────────────────────────────

class AuthConfig(BaseModel):
    auth_type: str = Field(default="none", description="none | form | bearer | cookie | header")
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


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None


# ── Application Lifecycle ────────────────────────────────────────────────────

db = Database()
nuclei_scanner = NucleiScanner()
zap_scanner = ZapScanner()
dedup = DeduplicationEngine()
ai_analyzer = AIAnalyzer()
poc_gen = PoCGenerator()
pdf_generator = PDFReportGenerator()


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
    yield
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

# ── Background Scan Pipeline ────────────────────────────────────────────────

async def run_scan_pipeline(scan_id: str, request: ScanRequest):
    """Pipeline: Nuclei/ZAP/Both → Dedup → Store → AI → PoC"""
    try:
        engine = request.scanner_engine
        auth = request.auth_config.model_dump() if request.auth_config else None
        logger.info(f"[{scan_id}] Starting {engine} scan for {request.target}")

        # ── Phase 1: Scanning ─────────────────────────────────────────────────
        db.update_scan(scan_id, status="scanning", phase="scanning")
        all_raw_findings = []

        # Nuclei scan
        if engine in ("nuclei", "both"):
            db.update_scan(scan_id, phase="nuclei_scan")
            logger.info(f"[{scan_id}] Running Nuclei ({request.scan_type})...")
            try:
                nuclei_findings = await nuclei_scanner.execute(
                    target=request.target,
                    severity=request.severity_filter,
                    tags=request.tags if request.tags else None,
                    custom_templates=request.custom_templates,
                    scan_type=request.scan_type,
                )
                for f in nuclei_findings:
                    f["scanner_source"] = "nuclei"
                all_raw_findings.extend(nuclei_findings)
                logger.info(f"[{scan_id}] Nuclei: {len(nuclei_findings)} findings")
            except Exception as e:
                logger.error(f"[{scan_id}] Nuclei scan failed: {e}")
                if engine == "nuclei":
                    raise

        # ZAP scan
        if engine in ("zap", "both"):
            db.update_scan(scan_id, phase="zap_scan")
            logger.info(f"[{scan_id}] Running ZAP (auth={auth.get('auth_type') if auth else 'none'})...")
            try:
                zap_findings = await zap_scanner.execute(
                    target=request.target,
                    auth_config=auth,
                    scan_type=request.scan_type,
                    severity=request.severity_filter,
                )
                for f in zap_findings:
                    f["scanner_source"] = "zap"
                all_raw_findings.extend(zap_findings)
                logger.info(f"[{scan_id}] ZAP: {len(zap_findings)} findings")
            except Exception as e:
                logger.error(f"[{scan_id}] ZAP scan failed: {e}")
                if engine == "zap":
                    raise

        db.update_scan(scan_id, raw_finding_count=len(all_raw_findings))

        # ── Phase 2: Dedup ────────────────────────────────────────────────────
        db.update_scan(scan_id, phase="deduplication")
        unique_findings = dedup.deduplicate(all_raw_findings, scan_id)
        db.update_scan(scan_id, unique_finding_count=len(unique_findings))
        logger.info(f"[{scan_id}] {len(unique_findings)} unique findings after dedup")

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

        # ── Phase 5: PoC Generation ───────────────────────────────────────────
        if request.generate_poc and unique_findings:
            db.update_scan(scan_id, phase="poc_generation")
            for i, finding in enumerate(unique_findings):
                try:
                    poc_result = await poc_gen.generate(finding)
                    
                    # Generate steps to reproduce
                    steps_result = await poc_gen.generate_steps_to_reproduce(finding)
                    
                    db.update_finding(
                        finding["id"],
                        poc_script=poc_result.get("script", ""),
                        poc_screenshot=poc_result.get("screenshot_path", ""),
                        poc_evidence=json.dumps(poc_result.get("evidence", {})),
                    )
                    
                    # Store steps to reproduce if generated
                    if steps_result.get("steps"):
                        db.update_finding(
                            finding["id"],
                            extracted_results=json.dumps({
                                "steps_to_reproduce": steps_result
                            })
                        )
                except Exception as e:
                    db.update_finding(finding["id"], poc_script=f"# PoC failed: {e}")
                    logger.error(f"[{scan_id}] PoC generation failed for {finding.get('id')}: {e}")

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


@app.get("/api/scans")
async def list_scans(limit: int = Query(50, le=200), offset: int = Query(0, ge=0), status: Optional[str] = None):
    return db.get_scans(limit=limit, offset=offset, status=status)

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan

@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    db.delete_scan(scan_id)
    return {"message": "Scan deleted"}

@app.get("/api/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: str, severity: Optional[str] = None, status: Optional[str] = None):
    return db.get_findings(scan_id=scan_id, severity=severity, status=status)

@app.get("/api/findings")
async def list_findings(severity: Optional[str] = None, status: Optional[str] = None,
                        limit: int = Query(100, le=500), offset: int = Query(0, ge=0)):
    return db.get_findings(severity=severity, status=status, limit=limit, offset=offset)

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


# ── Report Generation ────────────────────────────────────────────────────────

@app.get("/api/scans/{scan_id}/report/pdf")
async def export_scan_pdf(scan_id: str):
    """Generate and download a PDF report for a specific scan."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    findings = db.get_findings(scan_id=scan_id)
    if not findings:
        findings = []

    # Convert scan row to dict
    scan_dict = dict(scan)

    # Generate PDF
    try:
        pdf_buffer = pdf_generator.generate_report(
            scan=scan_dict,
            findings=findings,
            report_title=f"Vulnerability Scan Report — {scan_dict.get('target', 'Unknown')}",
        )

        # Return as streaming response
        return StreamingResponse(
            iter([pdf_buffer.getvalue()]),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="report_{scan_id}.pdf"'
            },
        )
    except Exception as e:
        logger.error(f"[PDF] Report generation failed: {e}")
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
