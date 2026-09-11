from fastapi import APIRouter
from pydantic import BaseModel
from app.graph_db import graph_db
from app.websocket import manager

router = APIRouter()

class InjectPayload(BaseModel):
    vuln_name: str
    target_software: str
    description: str

@router.post("/inject")
async def inject_vulnerability(payload: InjectPayload):
    """
    Role A (Hacker): Injects a vulnerability node and an [:AFFECTS] edge to a target software.
    Triggers a WebSocket broadcast to all SOC Analysts.
    """
    result = graph_db.inject_vulnerability(
        payload.vuln_name, payload.target_software, payload.description
    )
    
    # Broadcast alert to all active UI sessions
    await manager.broadcast({
        "type": "VULN_INJECTED",
        "details": result
    })
    
    return {"status": "success", "data": result}
