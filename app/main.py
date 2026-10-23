from datetime import datetime

from fastapi import FastAPI
from pydantic import BaseModel, IPvAnyAddress

from app.threat_intel import check_ip_reputation

from app.response import block_ip, decide

from app.db import init_db, list_incidents, save_incident

app = FastAPI(title="SOAR Incident Response")
init_db()

class Incident(BaseModel):
    source_ip: IPvAnyAddress
    alert_type: str
    severity: str = "medium"
    timestamp: datetime | None = None
    details: str | None = None


@app.post("/api/v1/incident")
def receive_incident(incident: Incident):
    ip = str(incident.source_ip)
    reputation = check_ip_reputation(ip)
    decision = decide(ip, reputation)
    action_result = block_ip(ip) if decision["action"] == "block" else None
    incident_id = save_incident(incident, reputation, decision, action_result)
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