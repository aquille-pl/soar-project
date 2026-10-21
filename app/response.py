import ipaddress
import logging
import os

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("soar")
logging.basicConfig(level=logging.INFO)

BLOCK_THRESHOLD = int(os.getenv("BLOCK_THRESHOLD", "75"))
DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"
ALLOWLIST = [n.strip() for n in os.getenv("ALLOWLIST", "").split(",") if n.strip()]


def is_allowlisted(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(n, strict=False) for n in ALLOWLIST)


def decide(ip: str, reputation: dict) -> dict:
    """Return the action to take and why. Fails safe: when unsure, don't block."""
    if is_allowlisted(ip):
        return {"action": "none", "reason": "IP is on the allowlist"}
    if not reputation.get("checked"):
        return {"action": "none", "reason": f"no verdict: {reputation.get('reason')}"}
    score = reputation["abuse_score"]
    if score >= BLOCK_THRESHOLD:
        return {"action": "block", "reason": f"abuse score {score} >= {BLOCK_THRESHOLD}"}
    return {"action": "none", "reason": f"abuse score {score} < {BLOCK_THRESHOLD}"}


def block_ip(ip: str) -> dict:
    """Placeholder for the real firewall / AWS Security Group call."""
    if DRY_RUN:
        logger.info("[DRY RUN] would block %s", ip)
        return {"executed": False, "mode": "dry_run"}
    logger.info("[MOCK] blocking %s", ip)
    return {"executed": True, "mode": "mock"}