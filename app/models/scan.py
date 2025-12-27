from datetime import datetime
from uuid import uuid4
from typing import Optional, Dict, Any
import enum

class ScanType(str, enum.Enum):
    WEB = "Web"
    SYSTEM = "System"
    NETWORK = "Network"
    API = "API"
    CLOUD = "Cloud"
    CONTAINER = "Container"
    DATABASE = "Database"
    MOBILE = "Mobile"

class ScanStatus(str, enum.Enum):
    PENDING = "Pending"
    QUEUED = "Queued"
    RUNNING = "Running"
    PAUSED = "Paused"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"

class ScanJob:
    """
    Represents a vulnerability scan job
    
    Stores scan configuration, status, and results metadata
    """
    
    def __init__(
        self,
        scan_type: ScanType,
        target: str,
        scan_profile: str = "Standard",
        config: Optional[Dict[str, Any]] = None
    ):
        self.scan_id = uuid4()
        self.scan_type = scan_type
        self.target = target
        self.status = ScanStatus.PENDING
        self.scan_profile = scan_profile
        self.config = config or {}
        
        # Timestamps
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        
        # Progress tracking
        self.progress_percentage = 0
        self.current_phase: Optional[str] = None
        
        # Results summary
        self.vulnerabilities_count = 0
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        
        # Results storage
        self.raw_results: Optional[Dict] = None
        self.scan_log: str = ""
    
    def start(self):
        """Mark scan as started"""
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.utcnow()
    
    def complete(self):
        """Mark scan as completed"""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        self.progress_percentage = 100
    
    def fail(self, error_message: str):
        """Mark scan as failed"""
        self.status = ScanStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.scan_log += f"\nError: {error_message}"
    
    def update_progress(self, percentage: int, phase: str):
        """Update scan progress"""
        self.progress_percentage = min(percentage, 100)
        self.current_phase = phase
    
    def update_vulnerability_counts(self, vulnerabilities: list):
        """Update vulnerability statistics"""
        self.vulnerabilities_count = len(vulnerabilities)
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '').upper()
            if severity == 'CRITICAL':
                self.critical_count += 1
            elif severity == 'HIGH':
                self.high_count += 1
            elif severity == 'MEDIUM':
                self.medium_count += 1
            elif severity == 'LOW':
                self.low_count += 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'scan_id': str(self.scan_id),
            'scan_type': self.scan_type.value,
            'target': self.target,
            'status': self.status.value,
            'scan_profile': self.scan_profile,
            'config': self.config,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'progress_percentage': self.progress_percentage,
            'current_phase': self.current_phase,
            'vulnerabilities_count': self.vulnerabilities_count,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count
        }