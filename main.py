from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

app = FastAPI(title="AegisChain API", version="1.0.0")

# CORS - Allow your React frontend to access this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/")
async def root():
    return {
        "message": "AegisChain API is running",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "healthy"
    }

@app.get("/health")
async def health_check():
    return {"status": "ok"}

# Example endpoint for testing
class ScanRequest(BaseModel):
    target: str
    scan_type: str

@app.post("/api/v1/scan")
async def create_scan(scan_request: ScanRequest):
    return {
        "message": "Scan created successfully",
        "scan_id": "test-123",
        "target": scan_request.target,
        "type": scan_request.scan_type,
        "status": "queued"
    }

@app.get("/api/v1/scans")
async def get_scans():
    # Mock data for now
    return {
        "scans": [
            {
                "id": "scan-1",
                "target": "example.com",
                "status": "completed",
                "created_at": "2025-01-15T10:00:00"
            },
            {
                "id": "scan-2",
                "target": "192.168.1.1",
                "status": "running",
                "created_at": "2025-01-15T11:30:00"
            }
        ]
    }