import logging

logger = logging.getLogger("soar")


class MockBlocker:
    def block(self, ip: str) -> dict:
        logger.info("[MOCK] block %s", ip)
        return {"executed": True, "backend": "mock", "detail": "no real change made"}

    def unblock(self, ip: str) -> dict:
        logger.info("[MOCK] unblock %s", ip)
        return {"executed": True, "backend": "mock", "detail": "no real change made"}