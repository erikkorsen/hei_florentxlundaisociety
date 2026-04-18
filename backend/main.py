import asyncio
import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from models import ScanRequest, ScanResponse
from scanner.orchestrator import run_scan

load_dotenv()

app = FastAPI(title="Security Scanner API")

allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="URL must start with http:// or https://")

    try:
        result = await run_scan(request)
    except (TimeoutError, asyncio.TimeoutError):
        raise HTTPException(status_code=504, detail="Scan timed out after 30 seconds")
    except ConnectionError:
        raise HTTPException(status_code=400, detail="Host unreachable")

    return result
