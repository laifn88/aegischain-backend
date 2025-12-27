from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import asyncio

class BaseScanner(ABC):
    """
    Abstract base class for all vulnerability scanners
    
    Defines the interface that all scanner implementations must follow
    """
    
    def __init__(self, timeout: int = 3600):
        """
        Initialize scanner
        
        Args:
            timeout: Maximum scan duration in seconds
        """
        self.timeout = timeout
        self.scan_results = []
    
    @abstractmethod
    async def discover_target(self, target: str) -> Dict[str, Any]:
        """
        Phase 1: Target discovery and reconnaissance
        
        Args:
            target: Target identifier (URL, IP, etc.)
        
        Returns:
            Dictionary containing discovery results
        """
        pass
    
    @abstractmethod
    async def scan(
        self,
        target: str,
        config: Dict[str, Any],
        discovery_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Phase 2: Execute vulnerability scan
        
        Args:
            target: Target to scan
            config: Scanner-specific configuration
            discovery_data: Data from discovery phase
        
        Returns:
            Dictionary containing raw scan results
        """
        pass
    
    @abstractmethod
    def normalize_results(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Phase 3: Normalize scanner-specific results to common format
        
        Args:
            raw_results: Raw scanner output
        
        Returns:
            List of normalized vulnerability dictionaries
        """
        pass
    
    def validate_target(self, target: str) -> bool:
        """
        Validate target format
        
        Args:
            target: Target to validate
        
        Returns:
            True if valid, False otherwise
        """
        if not target or len(target) < 3:
            return False
        return True
    
    async def run_with_timeout(self, coro, timeout: Optional[int] = None):
        """
        Run coroutine with timeout
        
        Args:
            coro: Coroutine to run
            timeout: Timeout in seconds (uses self.timeout if not provided)
        """
        timeout = timeout or self.timeout
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            raise Exception(f"Scan exceeded timeout of {timeout} seconds")
    
    def map_severity(self, raw_severity: str) -> str:
        """
        Map scanner-specific severity to standard levels
        
        Args:
            raw_severity: Scanner's severity rating
        
        Returns:
            Standardized severity level
        """
        severity_map = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Informational',
            'informational': 'Informational'
        }
        
        return severity_map.get(raw_severity.lower(), 'Low')
    
    def extract_cve(self, text: str) -> Optional[str]:
        """
        Extract CVE identifier from text
        
        Args:
            text: Text potentially containing CVE ID
        
        Returns:
            CVE ID if found, None otherwise
        """
        import re
        
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        match = re.search(cve_pattern, text, re.IGNORECASE)
        
        if match:
            return match.group(0).upper()
        return None
    
    def extract_cwe(self, text: str) -> Optional[str]:
        """
        Extract CWE identifier from text
        
        Args:
            text: Text potentially containing CWE ID
        
        Returns:
            CWE ID if found, None otherwise
        """
        import re
        
        cwe_pattern = r'CWE-\d{1,5}'
        match = re.search(cwe_pattern, text, re.IGNORECASE)
        
        if match:
            return match.group(0).upper()
        return None