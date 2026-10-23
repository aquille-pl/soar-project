import ipaddress
import logging
import os

from dotenv import load_dotenv

from app.blockers import get_blocker

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
    if DRY_RUN:
        logger.info("[DRY RUN] would block %s", ip)
        return {"executed": False, "mode": "dry_run"}
    try:
        result = get_blocker().block(ip)
    except Exception as exc:  # a failed block must not crash the webhook
        logger.exception("block failed for %s", ip)
        return {"executed": False, "mode": "error", "error": exc.__class__.__name__}
    return {"mode": "live", **result}