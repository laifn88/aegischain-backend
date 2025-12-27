from datetime import datetime
from uuid import uuid4, UUID
from typing import Optional, Dict, Any
import enum

class Severity(str, enum.Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

class CKCStage(str, enum.Enum):
    """Cyber Kill Chain Stages"""
    RECONNAISSANCE = "Reconnaissance"
    WEAPONIZATION = "Weaponization"
    DELIVERY = "Delivery"
    EXPLOITATION = "Exploitation"
    INSTALLATION = "Installation"
    C2 = "C2"
    ACTIONS = "Actions"

class Vulnerability:
    """
    Represents a discovered vulnerability
    
    Contains vulnerability details, AI-generated explanations,
    and mapping to the Cyber Kill Chain
    """
    
    def __init__(
        self,
        scan_id: UUID,
        title: str,
        description: str,
        severity: Severity,
        affected_component: str,
        remediation: str,
        ckc_stage: CKCStage,
        cvss_score: Optional[float] = None,
        cve_id: Optional[str] = None,
        cwe_id: Optional[str] = None,
        attack_vector: Optional[str] = None,
        exploit_available: Optional[str] = None,
        ai_explanation: Optional[str] = None,
        references: Optional[str] = None
    ):
        self.vuln_id = uuid4()
        self.scan_id = scan_id
        
        # Core vulnerability data
        self.title = title
        self.description = description
        self.severity = severity
        self.cvss_score = cvss_score
        self.cve_id = cve_id
        self.cwe_id = cwe_id
        
        # Context
        self.affected_component = affected_component
        self.attack_vector = attack_vector
        self.exploit_available = exploit_available
        
        # Cyber Kill Chain mapping
        self.ckc_stage = ckc_stage
        
        # AI-generated content
        self.ai_explanation = ai_explanation
        self.remediation = remediation
        
        # Additional data
        self.references = references
        self.discovered_at = datetime.utcnow()
    
    def get_risk_level(self) -> str:
        """
        Calculate overall risk level based on severity and exploitability
        """
        if self.severity == Severity.CRITICAL:
            return "Extreme Risk"
        elif self.severity == Severity.HIGH:
            if self.exploit_available == "Yes":
                return "Critical Risk"
            return "High Risk"
        elif self.severity == Severity.MEDIUM:
            return "Moderate Risk"
        else:
            return "Low Risk"
    
    def get_priority_score(self) -> int:
        """
        Calculate priority score for remediation ordering
        Higher score = higher priority
        """
        severity_scores = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 75,
            Severity.MEDIUM: 50,
            Severity.LOW: 25,
            Severity.INFORMATIONAL: 10
        }
        
        base_score = severity_scores.get(self.severity, 0)
        
        # Boost score if exploit is available
        if self.exploit_available == "Yes":
            base_score += 20
        elif self.exploit_available == "PoC":
            base_score += 10
        
        # Boost score for early kill chain stages (more preventable)
        ckc_boosts = {
            CKCStage.RECONNAISSANCE: 15,
            CKCStage.WEAPONIZATION: 12,
            CKCStage.DELIVERY: 10,
            CKCStage.EXPLOITATION: 8,
            CKCStage.INSTALLATION: 5,
            CKCStage.C2: 3,
            CKCStage.ACTIONS: 1
        }
        base_score += ckc_boosts.get(self.ckc_stage, 0)
        
        return min(base_score, 150)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'vuln_id': str(self.vuln_id),
            'scan_id': str(self.scan_id),
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'cvss_score': self.cvss_score,
            'cve_id': self.cve_id,
            'cwe_id': self.cwe_id,
            'affected_component': self.affected_component,
            'attack_vector': self.attack_vector,
            'exploit_available': self.exploit_available,
            'ckc_stage': self.ckc_stage.value,
            'ai_explanation': self.ai_explanation,
            'remediation': self.remediation,
            'references': self.references,
            'discovered_at': self.discovered_at.isoformat(),
            'risk_level': self.get_risk_level(),
            'priority_score': self.get_priority_score()
        }