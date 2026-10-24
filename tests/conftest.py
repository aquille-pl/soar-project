import pytest
from fastapi.testclient import TestClient

import app.db
import app.expiry
import app.main
import app.response
from app.main import app as fastapi_app

API_KEY = "test-secret"


class FakeBlocker:
    """Stands in for Azure: records calls, changes nothing."""

    def __init__(self):
        self.blocked = []
        self.unblocked = []

    def block(self, ip):
        self.blocked.append(ip)
        return {"executed": True, "backend": "fake", "rule": f"rule-{ip}"}

    def unblock(self, ip):
        self.unblocked.append(ip)
        return {"executed": True, "backend": "fake", "rule": f"rule-{ip}"}


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """Every test gets a fresh temp database and known-safe settings."""
    monkeypatch.setattr(app.db, "DB_PATH", str(tmp_path / "test.db"))
    app.db.init_db()
    monkeypatch.setenv("WEBHOOK_SECRET", API_KEY)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.setattr(app.response, "BLOCK_THRESHOLD", 75)
    monkeypatch.setattr(app.response, "ALLOWLIST", [])
    monkeypatch.setattr(app.response, "DRY_RUN", True)


@pytest.fixture
def client():
    # Not used as a context manager, so the background expiry loop doesn't start.
    return TestClient(fastapi_app, headers={"X-API-Key": API_KEY})


@pytest.fixture
def anon():
    return TestClient(fastapi_app)


@pytest.fixture
def fake_blocker(monkeypatch):
    blocker = FakeBlocker()
    getter = lambda backend=None: blocker
    monkeypatch.setattr(app.response, "get_blocker", getter)
    monkeypatch.setattr(app.main, "get_blocker", getter)
    monkeypatch.setattr(app.expiry, "get_blocker", getter)
    return blocker


@pytest.fixture
def intel(monkeypatch):
    """Fake AbuseIPDB. Tests tweak intel['result'] to set the score."""
    state = {
        "result": {
            "checked": True,
            "abuse_score": 0,
            "total_reports": 0,
            "country": "US",
            "isp": "Test ISP",
        }
    }
    monkeypatch.setattr(app.main, "check_ip_reputation", lambda ip: state["result"])
    return state