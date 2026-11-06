import os
import sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from app.api.endpoints import router as api_router
from app.core.config import settings
from app.db_init import init_db

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Assisted Decision-Support Platform for AICTE EoA Scrutiny (SIH 2026)"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Router
app.include_router(api_router, prefix="/api")

# Static files for UI
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.on_event("startup")
def startup_event():
    print(f"[{settings.APP_NAME}] Initializing database and synthetic seed records...")
    init_db()
    print(f"[{settings.APP_NAME}] System is ready.")

@app.get("/api/health")
def health():
    return {
        "status": "HEALTHY",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "compliance_banner": settings.COMPLIANCE_BANNER,
        "offline_ready": True
    }

@app.get("/")
def index():
    # Serve the integrated scrutiny portal UI
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse(f"""
    <html>
      <head><title>{settings.APP_NAME}</title></head>
      <body style="font-family: sans-serif; padding: 2rem;">
        <h2>{settings.APP_NAME} Backend Active</h2>
        <p>API documentation available at <a href="/docs">/docs</a></p>
      </body>
    </html>
    """)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
