from app import db, expiry


def test_only_expired_blocks_are_removed(fake_blocker):
    db.record_block(1, "1.2.3.4", "fake", "rule-a", ttl_minutes=-5)  # already expired
    db.record_block(2, "5.6.7.8", "fake", "rule-b", ttl_minutes=60)  # still valid

    assert expiry.expire_due_blocks() == 1
    assert fake_blocker.unblocked == ["1.2.3.4"]
    statuses = {b["ip"]: b["status"] for b in db.list_blocks()}
    assert statuses == {"1.2.3.4": "expired", "5.6.7.8": "active"}


def test_failed_unblock_stays_active_for_retry(monkeypatch):
    class Broken:
        def unblock(self, ip):
            raise RuntimeError("Azure unreachable")

    monkeypatch.setattr(expiry, "get_blocker", lambda backend=None: Broken())
    db.record_block(1, "1.2.3.4", "fake", "rule-a", ttl_minutes=-5)

    assert expiry.expire_due_blocks() == 0
    assert db.list_blocks()[0]["status"] == "active"