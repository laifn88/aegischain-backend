from typing import Dict, Any
from app.models.vulnerability import CKCStage

class CKCMapper:
    """
    Maps vulnerabilities to Cyber Kill Chain stages
    
    The Cyber Kill Chain is a framework for understanding
    the stages of a cyber attack:
    1. Reconnaissance - Information gathering
    2. Weaponization - Creating attack tools
    3. Delivery - Transmitting weapon to target
    4. Exploitation - Triggering vulnerability
    5. Installation - Installing malware
    6. Command & Control - Remote control channel
    7. Actions on Objectives - Achieving attack goals
    """
    
    def __init__(self):
        # Keyword mapping for automatic classification
        self.stage_keywords = {
            CKCStage.RECONNAISSANCE: [
                'information disclosure', 'banner', 'version disclosure',
                'directory listing', 'exposed', 'misconfiguration',
                'fingerprint', 'enumeration', 'scan', 'discovery'
            ],
            CKCStage.WEAPONIZATION: [
                'deserialization', 'code generation', 'payload',
                'template injection'
            ],
            CKCStage.DELIVERY: [
                'upload', 'email', 'phishing', 'social engineering',
                'file inclusion', 'path traversal', 'lfi', 'rfi'
            ],
            CKCStage.EXPLOITATION: [
                'injection', 'xss', 'sqli', 'command injection',
                'buffer overflow', 'xxe', 'ssrf', 'idor',
                'authentication bypass', 'privilege escalation',
                'rce', 'remote code execution'
            ],
            CKCStage.INSTALLATION: [
                'backdoor', 'trojan', 'persistent', 'malware',
                'rootkit', 'webshell'
            ],
            CKCStage.C2: [
                'command and control', 'c2', 'reverse shell',
                'callback', 'beacon', 'botnet'
            ],
            CKCStage.ACTIONS: [
                'data exfiltration', 'ransomware', 'destruction',
                'lateral movement', 'privilege abuse'
            ]
        }
    
    def map_vulnerability(self, vuln: Dict[str, Any]) -> CKCStage:
        """
        Map a vulnerability to its most likely kill chain stage
        
        Args:
            vuln: Vulnerability dictionary with title, description, etc.
        
        Returns:
            Appropriate CKCStage
        """
        title = vuln.get('title', '').lower()
        description = vuln.get('description', '').lower()
        cwe_id = vuln.get('cwe_id', '').lower()
        
        combined_text = f"{title} {description} {cwe_id}"
        
        # Check each stage's keywords
        stage_scores = {}
        for stage, keywords in self.stage_keywords.items():
            score = sum(1 for keyword in keywords if keyword in combined_text)
            if score > 0:
                stage_scores[stage] = score
        
        # Return stage with highest score
        if stage_scores:
            return max(stage_scores.items(), key=lambda x: x[1])[0]
        
        # Default mappings based on vulnerability type
        if 'injection' in combined_text or 'xss' in combined_text:
            return CKCStage.EXPLOITATION
        elif 'disclosure' in combined_text or 'exposed' in combined_text:
            return CKCStage.RECONNAISSANCE
        elif 'upload' in combined_text:
            return CKCStage.DELIVERY
        
        # Default to reconnaissance for unknown types
        return CKCStage.RECONNAISSANCE
    
    def get_stage_description(self, stage: CKCStage) -> str:
        """
        Get human-readable description of a kill chain stage
        
        Args:
            stage: CKCStage enum value
        
        Returns:
            Description of the stage
        """
        descriptions = {
            CKCStage.RECONNAISSANCE: (
                "Information gathering phase where attackers research and "
                "identify potential targets and vulnerabilities."
            ),
            CKCStage.WEAPONIZATION: (
                "Attackers create or obtain tools and payloads to exploit "
                "identified vulnerabilities."
            ),
            CKCStage.DELIVERY: (
                "The weapon is transmitted to the target through various "
                "vectors like email, web, or removable media."
            ),
            CKCStage.EXPLOITATION: (
                "The vulnerability is triggered, allowing attackers to "
                "execute code or gain unauthorized access."
            ),
            CKCStage.INSTALLATION: (
                "Malware or backdoors are installed on the system to "
                "maintain persistent access."
            ),
            CKCStage.C2: (
                "Compromised systems establish communication channels "
                "with attacker-controlled servers."
            ),
            CKCStage.ACTIONS: (
                "Attackers achieve their objectives: data theft, "
                "destruction, or lateral movement."
            )
        }
        
        return descriptions.get(stage, "Unknown stage")
    
    def get_prevention_advice(self, stage: CKCStage) -> str:
        """
        Get prevention strategies for a kill chain stage
        
        Args:
            stage: CKCStage enum value
        
        Returns:
            Prevention recommendations
        """
        prevention = {
            CKCStage.RECONNAISSANCE: (
                "Minimize information disclosure. Remove version banners. "
                "Implement proper access controls. Monitor for scanning activity."
            ),
            CKCStage.WEAPONIZATION: (
                "Keep threat intelligence updated. Monitor for indicators "
                "of compromise. Implement advanced email security."
            ),
            CKCStage.DELIVERY: (
                "Implement web filtering. Use email security gateways. "
                "Train users on phishing awareness. Restrict file uploads."
            ),
            CKCStage.EXPLOITATION: (
                "Apply security patches promptly. Use WAF/IPS. Implement "
                "input validation. Deploy exploit prevention tools."
            ),
            CKCStage.INSTALLATION: (
                "Use endpoint protection. Monitor file system changes. "
                "Implement application whitelisting. Detect persistence mechanisms."
            ),
            CKCStage.C2: (
                "Monitor network traffic. Block known C2 domains. "
                "Implement egress filtering. Use DNS security."
            ),
            CKCStage.ACTIONS: (
                "Implement DLP. Use file integrity monitoring. "
                "Segment networks. Monitor for lateral movement."
            )
        }
        
        return prevention.get(stage, "Implement defense in depth")
    
    def get_detection_methods(self, stage: CKCStage) -> list:
        """
        Get detection methods for a kill chain stage
        
        Args:
            stage: CKCStage enum value
        
        Returns:
            List of detection methods
        """
        detection = {
            CKCStage.RECONNAISSANCE: [
                "Web server log analysis",
                "IDS/IPS alerts",
                "Unusual scan patterns",
                "Failed authentication attempts"
            ],
            CKCStage.WEAPONIZATION: [
                "Threat intelligence feeds",
                "Malware analysis",
                "Sandbox detonation"
            ],
            CKCStage.DELIVERY: [
                "Email gateway logs",
                "Web proxy logs",
                "File upload monitoring",
                "Phishing detection"
            ],
            CKCStage.EXPLOITATION: [
                "WAF alerts",
                "Application logs",
                "Memory analysis",
                "Behavior monitoring"
            ],
            CKCStage.INSTALLATION: [
                "EDR alerts",
                "File integrity monitoring",
                "Registry monitoring",
                "Startup item analysis"
            ],
            CKCStage.C2: [
                "Network traffic analysis",
                "DNS monitoring",
                "Beaconing detection",
                "Firewall logs"
            ],
            CKCStage.ACTIONS: [
                "Data loss prevention alerts",
                "User behavior analytics",
                "Lateral movement detection",
                "Privilege escalation monitoring"
            ]
        }
        
        return detection.get(stage, ["General security monitoring"])