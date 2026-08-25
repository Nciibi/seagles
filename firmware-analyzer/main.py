"""
Seagles Firmware Analyzer — FastAPI microservice.
Performs entropy analysis, string extraction, binwalk scanning,
and CVE lookup on firmware images.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional
import psycopg2
import os
import json
import logging
from datetime import datetime, timezone
from contextlib import contextmanager
from entropy import analyze_file_entropy
from binwalk_runner import find_suspicious_strings, run_binwalk
from cve_lookup import lookup_cve

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Seagles Firmware Analyzer", version="2.0.0")

DB_URL = os.environ.get("DATABASE_URL", "")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

class EntropyReport(BaseModel):
    entropy_score: float = Field(0.0, ge=0.0, le=8.0)
    suspicious: bool = False
    details: str = ""

class BinwalkReport(BaseModel):
    has_filesystem: bool = False
    filesystem_type: Optional[str] = None
    has_kernel: bool = False
    signatures_found: list = []
    raw_output: str = ""

class CVEResult(BaseModel):
    cve_id: str = ""
    cvss_score: Optional[float] = None
    severity: str = "unknown"
    description: str = ""

class AnalysisReport(BaseModel):
    entropy: EntropyReport = EntropyReport()
    suspicious_strings: list = []
    suspicious_string_count: int = 0
    binwalk: BinwalkReport = BinwalkReport()
    cve_matches: list[CVEResult] = []

class AnalyzeResponse(BaseModel):
    firmware_id: str
    status: str = "complete"
    report: AnalysisReport

class AnalyzeRequest(BaseModel):
    firmware_id: str = Field(..., min_length=1, max_length=100)
    filepath: str = Field(..., min_length=1, max_length=500)
    vendor: str = Field("", max_length=200)
    version: str = Field("", max_length=100)

class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "firmware-analyzer"
    version: str = "2.0.0"

@contextmanager
def get_db():
    conn = psycopg2.connect(DB_URL)
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        conn.close()

def update_database(firmware_id: str, report: AnalysisReport):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cve_ids = [c.cve_id for c in report.cve_matches if c.cve_id]
            cur.execute("""
                UPDATE firmware SET
                    entropy_score = %s,
                    has_default_creds = %s,
                    has_telnet = %s,
                    has_backdoor_indicators = %s,
                    strings_of_interest = %s,
                    cve_matches = %s,
                    analyzed_at = %s,
                    analysis_status = 'complete',
                    analysis_report = %s
                WHERE id = %s
            """, (
                report.entropy.entropy_score,
                False,
                False,
                report.suspicious_string_count > 0,
                report.suspicious_strings,
                cve_ids,
                datetime.now(timezone.utc),
                report.model_dump_json(),
                firmware_id
            ))
            cur.close()
        logger.info(f"Database updated for firmware {firmware_id}")
    except Exception as e:
        logger.error(f"Database update failed for firmware {firmware_id}: {e}")

@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse()

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_firmware(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    """
    Run full firmware analysis pipeline:
    1. Entropy analysis
    2. Suspicious string extraction
    3. Binwalk signature scan
    4. CVE lookup via NVD API
    5. Update database with results
    """
    if not os.path.exists(req.filepath):
        raise HTTPException(status_code=400, detail=f"File not found: {req.filepath}")

    logger.info(f"Starting analysis for firmware {req.firmware_id}")

    entropy_result = {"entropy_score": 0, "suspicious": False, "details": ""}
    try:
        entropy_result = analyze_file_entropy(req.filepath)
    except Exception as e:
        logger.error(f"Entropy analysis failed: {e}")
        entropy_result["details"] = str(e)

    suspicious_strings = []
    try:
        suspicious_strings = find_suspicious_strings(req.filepath)
    except Exception as e:
        logger.error(f"String extraction failed: {e}")

    binwalk_result = {"has_filesystem": False, "signatures_found": [], "raw_output": ""}
    try:
        binwalk_result = run_binwalk(req.filepath)
    except Exception as e:
        logger.error(f"Binwalk scan failed: {e}")

    cve_results = []
    if req.vendor or req.version:
        try:
            raw_cves = lookup_cve(req.vendor, req.version, NVD_API_KEY or None)
            cve_results = [
                CVEResult(
                    cve_id=c.get("cve_id", ""),
                    cvss_score=c.get("cvss_score"),
                    severity=c.get("severity", "unknown"),
                    description=c.get("description", "")
                )
                for c in raw_cves
            ]
        except Exception as e:
            logger.error(f"CVE lookup failed: {e}")

    report = AnalysisReport(
        entropy=EntropyReport(
            entropy_score=entropy_result.get("entropy_score", 0),
            suspicious=entropy_result.get("suspicious", False),
            details=entropy_result.get("details", "")
        ),
        suspicious_strings=suspicious_strings,
        suspicious_string_count=len(suspicious_strings),
        binwalk=BinwalkReport(
            has_filesystem=binwalk_result.get("has_filesystem", False),
            filesystem_type=binwalk_result.get("filesystem_type"),
            has_kernel=binwalk_result.get("has_kernel", False),
            signatures_found=binwalk_result.get("signatures_found", []),
            raw_output=binwalk_result.get("raw_output", "")
        ),
        cve_matches=cve_results
    )

    background_tasks.add_task(update_database, req.firmware_id, report)

    logger.info(f"Analysis complete for firmware {req.firmware_id}: entropy={report.entropy.entropy_score:.2f}, "
                f"strings={report.suspicious_string_count}, cves={len(cve_results)}")

    return AnalyzeResponse(
        firmware_id=req.firmware_id,
        status="complete",
        report=report
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
