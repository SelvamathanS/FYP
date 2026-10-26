from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import uvicorn

from app.routes import hacker_routes, user_routes
from app.auth import init_auth_db

app = FastAPI(title="Self-Healing GraphRAG CTI Platform")

# CORS configured with explicit safe origins
allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "")
allowed_origins = [orig.strip() for orig in allowed_origins_env.split(",") if orig.strip()]
if not allowed_origins:
    allowed_origins = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173"
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# API Routers
app.include_router(hacker_routes.router, prefix="/api/hacker", tags=["Hacker"])
app.include_router(user_routes.router, prefix="/api/user", tags=["User"])

@app.on_event("startup")
def startup_event():
    # Initialize SQLite and Neo4j
    init_auth_db()

@app.get("/api/health")
def health_check():
    return {"status": "ok", "message": "GraphRAG CTI Backend is running"}

# Serve Frontend SPA (Vite output) if it exists
dist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dist")
if os.path.isdir(dist_dir):
    app.mount("/assets", StaticFiles(directory=os.path.join(dist_dir, "assets")), name="assets")
    
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        index_file = os.path.join(dist_dir, "index.html")
        return FileResponse(index_file)

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
