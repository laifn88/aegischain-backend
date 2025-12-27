from typing import Dict
from app.models.scan import ScanType
from app.scanners.base_scanner import BaseScanner
from app.scanners.web_scanner import WebScanner
from app.scanners.network_scanner import NetworkScanner

class ScannerFactory:
    """
    Factory pattern for creating appropriate scanner instances
    
    Maps scan types to their corresponding scanner implementations
    """
    
    def __init__(self):
        self._scanners: Dict[ScanType, type] = {
            ScanType.WEB: WebScanner,
            ScanType.NETWORK: NetworkScanner,
            # Additional scanners can be registered here
        }
    
    def get_scanner(self, scan_type: ScanType, **kwargs) -> BaseScanner:
        """
        Get appropriate scanner for the scan type
        
        Args:
            scan_type: Type of scan to perform
            **kwargs: Additional arguments passed to scanner constructor
        
        Returns:
            Scanner instance
        
        Raises:
            ValueError: If scan type is not supported
        """
        scanner_class = self._scanners.get(scan_type)
        
        if not scanner_class:
            raise ValueError(f"Unsupported scan type: {scan_type}")
        
        return scanner_class(**kwargs)
    
    def register_scanner(self, scan_type: ScanType, scanner_class: type):
        """
        Register a new scanner type
        
        Args:
            scan_type: Scan type identifier
            scanner_class: Scanner class to register
        """
        if not issubclass(scanner_class, BaseScanner):
            raise ValueError("Scanner must inherit from BaseScanner")
        
        self._scanners[scan_type] = scanner_class
    
    def get_available_scan_types(self) -> list:
        """Get list of supported scan types"""
        return list(self._scanners.keys())