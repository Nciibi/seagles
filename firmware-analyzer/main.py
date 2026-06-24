"""
IronMesh Firmware Analyzer — FastAPI microservice.
Performs entropy analysis, string extraction, binwalk scanning,
and CVE lookup on firmware images.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg2
import os
import json
from datetime import datetime
from entropy import analyze_file_entropy
from binwalk_runner import find_suspicious_strings, run_binwalk
from cve_lookup import lookup_cve

app = FastAPI(title="IronMesh Firmware Analyzer", version="1.0.0")

DB_URL = os.environ.get("DATABASE_URL", "")
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")


def get_db():
    """Get a database connection."""
    return psycopg2.connect(DB_URL)


class AnalyzeRequest(BaseModel):
    firmware_id: str
    filepath: str
    vendor: str = ""
    version: str = ""


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "firmware-analyzer"}


@app.post("/analyze")
def analyze_firmware(req: AnalyzeRequest):
    """
    Run full firmware analysis pipeline:
    1. Entropy analysis
    2. Suspicious string extraction
    3. Binwalk signature scan
    4. CVE lookup via NVD API
    5. Update database with results
    """
    report = {}

    # Step 1: Entropy analysis
    entropy_result = analyze_file_entropy(req.filepath)
    report["entropy"] = entropy_result

    # Step 2: String extraction
    suspicious_strings = find_suspicious_strings(req.filepath)
    report["suspicious_strings"] = suspicious_strings
    report["suspicious_string_count"] = len(suspicious_strings)

    # Step 3: Binwalk signature scan
    binwalk_result = run_binwalk(req.filepath)
    report["binwalk"] = binwalk_result

    # Step 4: CVE lookup
    cve_results = []
    if req.vendor or req.version:
        cve_results = lookup_cve(req.vendor, req.version, NVD_API_KEY or None)
    report["cve_matches"] = cve_results

    # Step 5: Update database
    cve_ids = [c["cve_id"] for c in cve_results if "cve_id" in c]
    entropy_score = entropy_result.get("entropy_score", 0)
    has_backdoor = len(suspicious_strings) > 0

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE firmware SET
                entropy_score = %s,
                has_backdoor_indicators = %s,
                strings_of_interest = %s,
                cve_matches = %s,
                analyzed_at = %s,
                analysis_status = 'complete',
                analysis_report = %s
            WHERE id = %s
        """, (
            entropy_score,
            has_backdoor,
            suspicious_strings,
            cve_ids,
            datetime.utcnow(),
            json.dumps(report),
            req.firmware_id
        ))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        report["db_error"] = str(e)

    return {
        "firmware_id": req.firmware_id,
        "status": "complete",
        "report": report
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
