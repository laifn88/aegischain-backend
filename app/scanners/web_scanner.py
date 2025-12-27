from typing import Dict, Any, List, Optional
import asyncio
from app.scanners.base_scanner import BaseScanner

class WebScanner(BaseScanner):
    """
    Web Application Security Scanner
    
    Integrates with OWASP ZAP for web vulnerability scanning
    """
    
    def __init__(self, zap_proxy_url: str = "http://localhost:8080", api_key: str = ""):
        super().__init__(timeout=3600)
        self.zap_proxy_url = zap_proxy_url
        self.api_key = api_key
    
    async def discover_target(self, target: str) -> Dict[str, Any]:
        """
        Discover web application structure
        
        Performs:
        - Spider/crawl to discover pages
        - Technology detection
        - Form identification
        """
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        discovery_results = {
            'target_url': target,
            'discovered_urls': [],
            'forms': [],
            'technologies': [],
            'cookies': [],
            'headers': {}
        }
        
        try:
            # Simulate spider/discovery
            # In production, integrate with OWASP ZAP spider
            await asyncio.sleep(2)  # Simulate discovery time
            
            discovery_results['discovered_urls'] = [
                f"{target}/",
                f"{target}/login",
                f"{target}/api",
            ]
            
            discovery_results['technologies'] = ['Apache', 'PHP', 'MySQL']
            
        except Exception as e:
            raise Exception(f"Discovery failed: {str(e)}")
        
        return discovery_results
    
    async def scan(
        self,
        target: str,
        config: Dict[str, Any],
        discovery_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute active web vulnerability scan
        
        Tests for:
        - SQL Injection
        - XSS (Cross-Site Scripting)
        - CSRF
        - Authentication issues
        - Security misconfigurations
        - Sensitive data exposure
        """
        scan_profile = config.get('scan_profile', 'Standard')
        
        # Simulate scan execution
        await asyncio.sleep(5)  # Simulate scan time
        
        # Mock scan results (in production, integrate with OWASP ZAP API)
        raw_results = {
            'alerts': [
                {
                    'alert': 'SQL Injection',
                    'risk': 'High',
                    'confidence': 'Medium',
                    'desc': 'SQL injection may be possible',
                    'url': f"{target}/login",
                    'param': 'username',
                    'attack': "' OR '1'='1",
                    'evidence': 'Error message revealed database structure',
                    'solution': 'Use parameterized queries',
                    'reference': 'https://owasp.org/www-community/attacks/SQL_Injection',
                    'cweid': '89',
                    'wascid': '19'
                },
                {
                    'alert': 'Cross-Site Scripting (Reflected)',
                    'risk': 'High',
                    'confidence': 'High',
                    'desc': 'Reflected XSS vulnerability detected',
                    'url': f"{target}/search",
                    'param': 'q',
                    'attack': '<script>alert(1)</script>',
                    'evidence': 'Script executed in response',
                    'solution': 'Sanitize user input and encode output',
                    'reference': 'https://owasp.org/www-community/attacks/xss/',
                    'cweid': '79',
                    'wascid': '8'
                },
                {
                    'alert': 'Missing Security Headers',
                    'risk': 'Low',
                    'confidence': 'High',
                    'desc': 'Security headers not implemented',
                    'url': target,
                    'param': 'N/A',
                    'attack': '',
                    'evidence': 'X-Frame-Options, CSP headers missing',
                    'solution': 'Implement security headers',
                    'reference': 'https://owasp.org/www-project-secure-headers/',
                    'cweid': '16'
                }
            ],
            'scan_metadata': {
                'target': target,
                'scan_duration': 300,
                'urls_tested': 15,
                'alerts_count': 3
            }
        }
        
        return raw_results
    
    def normalize_results(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalize OWASP ZAP results to common format
        """
        normalized = []
        
        for alert in raw_results.get('alerts', []):
            normalized_vuln = {
                'title': alert.get('alert', 'Unknown Vulnerability'),
                'description': alert.get('desc', ''),
                'severity': self.map_severity(alert.get('risk', 'Low')),
                'cvss_score': self._calculate_cvss(alert),
                'cve_id': self.extract_cve(alert.get('reference', '')),
                'cwe_id': f"CWE-{alert.get('cweid')}" if alert.get('cweid') else None,
                'affected_component': alert.get('url', ''),
                'attack_vector': alert.get('attack', ''),
                'exploit_available': 'PoC' if alert.get('confidence') == 'High' else 'Unknown',
                'evidence': alert.get('evidence', ''),
                'solution': alert.get('solution', ''),
                'references': alert.get('reference', ''),
                'scanner_confidence': alert.get('confidence', 'Unknown')
            }
            
            normalized.append(normalized_vuln)
        
        return normalized
    
    def _calculate_cvss(self, alert: Dict[str, Any]) -> float:
        """
        Calculate approximate CVSS score based on risk and confidence
        """
        risk = alert.get('risk', '').lower()
        confidence = alert.get('confidence', '').lower()
        
        base_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0,
            'informational': 0.0
        }
        
        score = base_scores.get(risk, 3.0)
        
        # Adjust based on confidence
        if confidence == 'high':
            score += 0.5
        elif confidence == 'low':
            score -= 0.5
        
        return min(max(score, 0.0), 10.0)