"""Main FastAPI application entry point for PromptShield X."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api import router
from backend.app.storage import init_db

app = FastAPI(
    title="PromptShield X — AI Security Gateway",
    description="Adaptive, Trust-Aware AI Security Gateway for prompt injection and data-exfiltration defense",
    version="2.1.0"
)

# Enable CORS for local Vite development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize local SQLite database schema
init_db()

# Mount API endpoints (both with and without /api prefix for Vercel serverless and local dev)
app.include_router(router)
app.include_router(router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
