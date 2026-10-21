from datetime import datetime

from fastapi import FastAPI
from pydantic import BaseModel, IPvAnyAddress

app = FastAPI(title="SOAR Incident Response")


class Incident(BaseModel):
    source_ip: IPvAnyAddress
    alert_type: str
    severity: str = "medium"
    timestamp: datetime | None = None
    details: str | None = None


@app.post("/api/v1/incident")
def receive_incident(incident: Incident):
    return {
        "status": "received",
        "source_ip": str(incident.source_ip),
        "alert_type": incident.alert_type,
    }