from fastapi import APIRouter, HTTPException
from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel
from enum import Enum
from datetime import datetime

router = APIRouter()

class SeverityEnum(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class CKCStageEnum(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    C2 = "C2"
    ACTIONS = "Actions"

class VulnerabilityResponse(BaseModel):
    vuln_id: UUID
    scan_id: UUID
    title: str
    description: str
    severity: SeverityEnum
    cvss_score: Optional[float]
    cve_id: Optional[str]
    cwe_id: Optional[str]
    affected_component: str
    attack_vector: Optional[str]
    exploit_available: Optional[str]
    ckc_stage: CKCStageEnum
    ai_explanation: Optional[str]
    remediation: str
    references: Optional[str]
    discovered_at: datetime

class VulnerabilityList(BaseModel):
    vulnerabilities: List[VulnerabilityResponse]
    total: int
    critical: int
    high: int
    medium: int
    low: int

@router.get("/scan/{scan_id}", response_model=VulnerabilityList)
async def get_scan_vulnerabilities(
    scan_id: UUID,
    severity: Optional[SeverityEnum] = None,
    ckc_stage: Optional[CKCStageEnum] = None
):
    """
    Retrieve all vulnerabilities for a specific scan
    
    Optional filters:
    - severity: Filter by severity level
    - ckc_stage: Filter by Cyber Kill Chain stage
    """
    # In production, query database with filters
    return {
        "vulnerabilities": [],
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(vuln_id: UUID):
    """Get detailed information about a specific vulnerability"""
    raise HTTPException(status_code=404, detail="Vulnerability not found")

@router.get("/")
async def list_all_vulnerabilities(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[SeverityEnum] = None
):
    """List all vulnerabilities across all scans"""
    return {
        "vulnerabilities": [],
        "total": 0
    }