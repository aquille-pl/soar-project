import ipaddress
import os

import httpx
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def is_public_ip(ip: str) -> bool:
    """False for private, loopback, link-local, reserved, etc."""
    return ipaddress.ip_address(ip).is_global


def check_ip_reputation(ip: str) -> dict:
    """Query AbuseIPDB. Returns a dict with the score, or an error marker."""
    if not is_public_ip(ip):
        return {"checked": False, "reason": "non-public IP, skipped"}

    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"checked": False, "reason": "API key not configured"}

    try:
        response = httpx.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        return {"checked": False, "reason": f"lookup failed: {exc.__class__.__name__}"}

    data = response.json()["data"]
    return {
        "checked": True,
        "abuse_score": data["abuseConfidenceScore"],
        "total_reports": data["totalReports"],
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
    }