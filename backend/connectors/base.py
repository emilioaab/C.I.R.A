from abc import ABC, abstractmethod
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class Finding:
    """Standard finding across all clouds"""
    check_id: str
    check_title: str
    service: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    status: str    # PASS, FAIL
    resource_id: str
    resource_type: str
    region: str
    description: str
    remediation: str
    frameworks: List[str]
    threat_score: int
    environment: str
    timestamp: str

class CloudConnector(ABC):
    """Abstract base class for cloud connectors"""
    
    @abstractmethod
    def assess_iam(self) -> List[Finding]:
        """Assess IAM configuration"""
        pass
    
    @abstractmethod
    def assess_resources(self) -> List[Finding]:
        """Map and assess resources"""
        pass
    
    @abstractmethod
    def assess_network(self) -> List[Finding]:
        """Assess network security"""
        pass
    
    @abstractmethod
    def assess_storage(self) -> List[Finding]:
        """Assess storage security"""
        pass
    
    @abstractmethod
    def assess_logging(self) -> List[Finding]:
        """Assess logging configuration"""
        pass
    
    @abstractmethod
    def assess_compliance(self) -> List[Finding]:
        """Assess compliance frameworks"""
        pass
    
    @abstractmethod
    def collect_logs(self) -> Dict:
        """Collect logs (future)"""
        pass
    
    @abstractmethod
    def deploy_forensics(self, instance_id: str) -> Dict:
        """Deploy forensics agent (future, requires elevated permissions)"""
        pass