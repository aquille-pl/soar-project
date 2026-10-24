import asyncio
import logging

from app.blockers import get_blocker
from app.db import due_blocks, mark_block

logger = logging.getLogger("soar")

CHECK_INTERVAL_SECONDS = 30


def expire_due_blocks() -> int:
    count = 0
    for block in due_blocks():
        try:
            get_blocker(block["backend"]).unblock(block["ip"])
            mark_block(block["id"], "expired")
            count += 1
            logger.info("Expired block on %s", block["ip"])
        except Exception:
            # Leave it 'active' so the next pass retries.
            logger.exception("Failed to expire block on %s", block["ip"])
    return count


async def expiry_loop():
    while True:
        await asyncio.to_thread(expire_due_blocks)
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
    