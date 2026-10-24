import asyncio
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI
from pydantic import BaseModel, IPvAnyAddress
from app.auth import require_api_key
from app.blockers import get_blocker
from app.db import (
    end_blocks_for_ip,
    init_db,
    list_blocks,
    list_incidents,
    record_block,
    save_incident,
)
from app.expiry import expiry_loop
from app.response import BLOCK_TTL_MINUTES, block_ip, decide
from app.threat_intel import check_ip_reputation

init_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(expiry_loop())
    yield
    task.cancel()


app = FastAPI(
    title="SOAR Incident Response",
    lifespan=lifespan,
    dependencies=[Depends(require_api_key)],
)


class Incident(BaseModel):
    source_ip: IPvAnyAddress
    alert_type: str
    severity: str = "medium"
    timestamp: datetime | None = None
    details: str | None = None


class UnblockRequest(BaseModel):
    source_ip: IPvAnyAddress


@app.post("/api/v1/incident")
def receive_incident(incident: Incident):
    ip = str(incident.source_ip)
    reputation = check_ip_reputation(ip)
    decision = decide(ip, reputation)
    action_result = block_ip(ip) if decision["action"] == "block" else None
    incident_id = save_incident(incident, reputation, decision, action_result)

    if action_result and action_result.get("mode") == "live" and action_result.get("executed"):
        record_block(
            incident_id, ip, action_result.get("backend"),
            action_result.get("rule"), BLOCK_TTL_MINUTES,
        )

    return {
        "status": "processed",
        "incident_id": incident_id,
        "source_ip": ip,
        "alert_type": incident.alert_type,
        "reputation": reputation,
        "decision": decision,
        "action_result": action_result,
    }


@app.get("/api/v1/incidents")
def get_incidents(limit: int = 50):
    return list_incidents(limit)


@app.get("/api/v1/blocks")
def get_blocks(limit: int = 50):
    return list_blocks(limit)


@app.post("/api/v1/unblock")
def unblock(req: UnblockRequest):
    ip = str(req.source_ip)
    result = get_blocker().unblock(ip)
    end_blocks_for_ip(ip, "manually_unblocked")
    return {"source_ip": ip, "result": result}