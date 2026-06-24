"""
CVE lookup module — queries the NVD API for known vulnerabilities
matching a device vendor and firmware version.
"""

import requests
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cve(vendor: str, version: str, api_key: str = None) -> list[dict]:
    """
    Query NVD for CVEs matching vendor and firmware version.

    Rate limited: 6s between requests without API key, 0.6s with key.
    Only returns CVEs with CVSS score >= 4.0.
    """
    keyword = f"{vendor} {version}".strip()
    if not keyword or keyword == " ":
        return []

    headers = {"User-Agent": "IronMesh-Security-Scanner/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20,
    }

    # Rate limiting: 6s without key, 0.6s with key
    sleep_time = 0.6 if api_key else 6.0
    time.sleep(sleep_time)

    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return [{"error": str(e)}]

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Get CVSS score (try v3.1 first, then v2)
        cvss = None
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        if cvss is None or cvss < 4.0:
            continue  # Skip low-severity findings

        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        results.append({
            "cve_id": cve_id,
            "cvss_score": cvss,
            "description": desc[:500],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        })

    return results
