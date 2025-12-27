import asyncio
from uuid import UUID
from typing import Dict, Any, List
from datetime import datetime

from app.models.scan import ScanJob, ScanStatus
from app.models.vulnerability import Vulnerability
from app.scanners.scanner_factory import ScannerFactory
from app.utils.ckc_mapper import CKCMapper

class ScanOrchestrator:
    """
    Main orchestrator for vulnerability scans
    
    Coordinates:
    - Scanner execution
    - Result normalization
    - Vulnerability storage
    - Progress tracking
    """
    
    def __init__(self):
        self.scanner_factory = ScannerFactory()
        self.ckc_mapper = CKCMapper()
        self.active_scans: Dict[UUID, ScanJob] = {}
    
    async def execute_scan(self, scan_id: UUID):
        """
        Main scan execution workflow
        
        Phases:
        1. Load scan configuration
        2. Target discovery
        3. Vulnerability testing
        4. Result normalization
        5. Kill chain mapping
        6. Result storage
        """
        # Create scan job (in production, load from database)
        scan_job = self._create_mock_scan_job(scan_id)
        self.active_scans[scan_id] = scan_job
        
        try:
            # Update status to Running
            scan_job.start()
            scan_job.update_progress(5, "Initializing")
            
            # Get appropriate scanner
            scanner = self.scanner_factory.get_scanner(scan_job.scan_type)
            
            # Phase 1: Discovery
            scan_job.update_progress(10, "Target Discovery")
            discovery_results = await scanner.discover_target(scan_job.target)
            scan_job.scan_log += f"\nDiscovery completed: {len(discovery_results.get('discovered_urls', []))} endpoints found"
            
            # Phase 2: Vulnerability Testing
            scan_job.update_progress(30, "Vulnerability Testing")
            raw_results = await scanner.scan(
                target=scan_job.target,
                config=scan_job.config,
                discovery_data=discovery_results
            )
            scan_job.scan_log += f"\nScan completed: {len(raw_results.get('alerts', []))} potential issues detected"
            
            # Phase 3: Result Normalization
            scan_job.update_progress(60, "Processing Results")
            normalized_vulnerabilities = scanner.normalize_results(raw_results)
            scan_job.scan_log += f"\nNormalized {len(normalized_vulnerabilities)} vulnerabilities"
            
            # Phase 4: Cyber Kill Chain Mapping
            scan_job.update_progress(75, "Mapping Attack Vectors")
            final_vulnerabilities = await self._map_to_kill_chain(normalized_vulnerabilities)
            scan_job.scan_log += "\nKill chain mapping completed"
            
            # Phase 5: Store Results
            scan_job.update_progress(90, "Storing Results")
            vulnerability_objects = self._create_vulnerability_objects(
                scan_id,
                final_vulnerabilities
            )
            
            # Update scan statistics
            scan_job.update_vulnerability_counts(final_vulnerabilities)
            scan_job.raw_results = raw_results
            
            # Phase 6: Complete
            scan_job.complete()
            scan_job.scan_log += f"\nScan completed successfully at {datetime.utcnow().isoformat()}"
            
            return {
                "status": "success",
                "scan_id": str(scan_id),
                "vulnerabilities_found": len(vulnerability_objects)
            }
            
        except Exception as e:
            scan_job.fail(str(e))
            raise
        
        finally:
            # Cleanup
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
    
    async def _map_to_kill_chain(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Map each vulnerability to Cyber Kill Chain stage
        """
        for vuln in vulnerabilities:
            ckc_stage = self.ckc_mapper.map_vulnerability(vuln)
            vuln['ckc_stage'] = ckc_stage
            
            # Add kill chain context
            vuln['ckc_description'] = self.ckc_mapper.get_stage_description(ckc_stage)
        
        return vulnerabilities
    
    def _create_vulnerability_objects(
        self,
        scan_id: UUID,
        vulnerabilities: List[Dict]
    ) -> List[Vulnerability]:
        """
        Create Vulnerability objects from normalized data
        """
        vuln_objects = []
        
        for vuln_data in vulnerabilities:
            vuln = Vulnerability(
                scan_id=scan_id,
                title=vuln_data.get('title', 'Unknown'),
                description=vuln_data.get('description', ''),
                severity=vuln_data.get('severity', 'Low'),
                affected_component=vuln_data.get('affected_component', ''),
                remediation=vuln_data.get('solution', 'No remediation available'),
                ckc_stage=vuln_data.get('ckc_stage', 'Reconnaissance'),
                cvss_score=vuln_data.get('cvss_score'),
                cve_id=vuln_data.get('cve_id'),
                cwe_id=vuln_data.get('cwe_id'),
                attack_vector=vuln_data.get('attack_vector'),
                exploit_available=vuln_data.get('exploit_available'),
                ai_explanation=vuln_data.get('ai_explanation'),
                references=vuln_data.get('references')
            )
            vuln_objects.append(vuln)
        
        return vuln_objects
    
    def _create_mock_scan_job(self, scan_id: UUID) -> ScanJob:
        """
        Create mock scan job for demonstration
        In production, this loads from database
        """
        from app.models.scan import ScanType
        
        return ScanJob(
            scan_type=ScanType.WEB,
            target="example.com",
            scan_profile="Standard"
        )
    
    def get_scan_status(self, scan_id: UUID) -> Dict[str, Any]:
        """Get real-time scan status"""
        scan_job = self.active_scans.get(scan_id)
        
        if scan_job:
            return scan_job.to_dict()
        
        return {"status": "not_found"}
    
    async def cancel_scan(self, scan_id: UUID):
        """Cancel an active scan"""
        scan_job = self.active_scans.get(scan_id)
        
        if scan_job:
            scan_job.status = ScanStatus.CANCELLED
            scan_job.completed_at = datetime.utcnow()
            scan_job.scan_log += f"\nScan cancelled at {datetime.utcnow().isoformat()}"
            
            del self.active_scans[scan_id]