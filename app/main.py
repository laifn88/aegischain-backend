from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1 import scans, vulnerabilities

app = FastAPI(
    title="AegisChain API",
    version="1.0.0",
    description="Advanced Vulnerability Scanning Platform"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])

@app.get("/")
async def root():
    return {"message": "AegisChain API", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}