from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from app.graphrag_agent import agent
from app.graph_db import graph_db
from app.websocket import manager

router = APIRouter()

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep alive and listen for ping/messages
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

class ChatQuery(BaseModel):
    query: str

@router.post("/chat")
async def chat_with_agent(payload: ChatQuery):
    """
    Role B (SOC Analyst): Triggers the LangGraph Reflection Loop.
    Traverses Neo4j to find unmitigated vulnerabilities and self-heals using Gemini.
    """
    result = agent.execute_reflection_loop(payload.query)
    
    # Broadcast graph update so UI visually refreshes
    await manager.broadcast({
        "type": "GRAPH_UPDATED",
        "details": "Self-healing loop completed."
    })
    
    return {"status": "success", "data": result}

@router.get("/graph")
async def get_graph():
    """Retrieve the full CTI knowledge graph for Vis.js visualization."""
    return graph_db.get_graph_snapshot()
