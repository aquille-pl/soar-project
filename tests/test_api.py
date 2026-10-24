import app.response


def payload(ip="1.2.3.4", **extra):
    return {"source_ip": ip, "alert_type": "port_scan", **extra}


def go_live(monkeypatch):
    monkeypatch.setattr(app.response, "DRY_RUN", False)


# --- authentication ---------------------------------------------------------

def test_requests_without_a_key_are_rejected(anon):
    assert anon.post("/api/v1/incident", json=payload()).status_code == 401
    assert anon.get("/api/v1/incidents").status_code == 401
    assert anon.get("/api/v1/blocks").status_code == 401
    assert anon.post("/api/v1/unblock", json={"source_ip": "1.2.3.4"}).status_code == 401


def test_wrong_key_is_rejected(anon):
    response = anon.post(
        "/api/v1/incident", json=payload(), headers={"X-API-Key": "wrong"}
    )
    assert response.status_code == 401


def test_fails_closed_when_no_secret_is_configured(client, monkeypatch):
    monkeypatch.delenv("WEBHOOK_SECRET")
    assert client.post("/api/v1/incident", json=payload()).status_code == 503


# --- validation -------------------------------------------------------------

def test_invalid_ip_is_rejected_and_not_stored(client):
    response = client.post("/api/v1/incident", json=payload(ip="banana"))
    assert response.status_code == 422
    assert client.get("/api/v1/incidents").json() == []


# --- decisions and actions --------------------------------------------------

def test_low_score_is_logged_but_not_blocked(client, intel, fake_blocker, monkeypatch):
    go_live(monkeypatch)
    intel["result"]["abuse_score"] = 10
    body = client.post("/api/v1/incident", json=payload()).json()
    assert body["decision"]["action"] == "none"
    assert fake_blocker.blocked == []
    assert len(client.get("/api/v1/incidents").json()) == 1
    assert client.get("/api/v1/blocks").json() == []


def test_high_score_blocks_and_records_the_block(client, intel, fake_blocker, monkeypatch):
    go_live(monkeypatch)
    intel["result"]["abuse_score"] = 90
    body = client.post("/api/v1/incident", json=payload()).json()
    assert body["decision"]["action"] == "block"
    assert body["action_result"]["mode"] == "live"
    assert fake_blocker.blocked == ["1.2.3.4"]
    blocks = client.get("/api/v1/blocks").json()
    assert len(blocks) == 1
    assert blocks[0]["ip"] == "1.2.3.4"
    assert blocks[0]["status"] == "active"


def test_dry_run_never_calls_the_blocker(client, intel, fake_blocker):
    intel["result"]["abuse_score"] = 90  # DRY_RUN is True by default in tests
    body = client.post("/api/v1/incident", json=payload()).json()
    assert body["action_result"]["mode"] == "dry_run"
    assert fake_blocker.blocked == []
    assert client.get("/api/v1/blocks").json() == []


def test_allowlisted_ip_is_never_blocked(client, intel, fake_blocker, monkeypatch):
    go_live(monkeypatch)
    monkeypatch.setattr(app.response, "ALLOWLIST", ["1.2.3.0/24"])
    intel["result"]["abuse_score"] = 100
    body = client.post("/api/v1/incident", json=payload()).json()
    assert body["decision"]["action"] == "none"
    assert fake_blocker.blocked == []


def test_failed_block_does_not_crash_the_webhook(client, intel, monkeypatch):
    go_live(monkeypatch)
    intel["result"]["abuse_score"] = 90

    class Broken:
        def block(self, ip):
            raise RuntimeError("firewall unreachable")

    monkeypatch.setattr(app.response, "get_blocker", lambda backend=None: Broken())
    response = client.post("/api/v1/incident", json=payload())
    assert response.status_code == 200
    assert response.json()["action_result"]["mode"] == "error"
    assert client.get("/api/v1/blocks").json() == []
    assert len(client.get("/api/v1/incidents").json()) == 1


def test_manual_unblock(client, intel, fake_blocker, monkeypatch):
    go_live(monkeypatch)
    intel["result"]["abuse_score"] = 90
    client.post("/api/v1/incident", json=payload())
    response = client.post("/api/v1/unblock", json={"source_ip": "1.2.3.4"})
    assert response.status_code == 200
    assert fake_blocker.unblocked == ["1.2.3.4"]
    assert client.get("/api/v1/blocks").json()[0]["status"] == "manually_unblocked"