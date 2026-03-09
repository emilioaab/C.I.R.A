"""
C.I.R.A Forensics — Velociraptor Integration (Phase 3)

Velociraptor is a DFIR (Digital Forensics & Incident Response) tool.
When C.I.R.A detects a critical security finding, this module:
  1. Deploys the Velociraptor agent on the affected EC2 instance via AWS SSM
  2. Runs a VQL (Velociraptor Query Language) hunt to collect forensic artifacts
  3. Returns results to the C.I.R.A dashboard

Architecture:
  C.I.R.A (CSPM) → critical finding → VelociraptorIntegration → SSM → EC2 instance
                                                ↓
                                     Velociraptor Server (self-hosted)
                                                ↓
                                     Forensic artifacts → C.I.R.A DB

Requirements to enable:
  - Velociraptor server running (can be on EC2 or local VM)
  - Set in .env:
      VELOCIRAPTOR_URL=https://your-velo-server:8000
      VELOCIRAPTOR_API_KEY=your-api-key
  - EC2 instances must have SSM agent installed and IAM role with SSM permissions

References:
  https://docs.velociraptor.app/
  https://docs.velociraptor.app/docs/deployment/
"""

import os
import uuid
import boto3
import logging
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS & DATA CLASSES
# ============================================================================

class IRStatus(str, Enum):
    OPEN          = "open"
    INVESTIGATING = "investigating"
    RESOLVED      = "resolved"

class HuntType(str, Enum):
    QUICK     = "quick"      # Basic: processes, network connections, users
    FULL      = "full"       # Deep: filesystem, memory, registry, all artifacts
    NETWORK   = "network"    # Network only: connections, DNS, firewall
    PROCESSES = "processes"  # Running processes and loaded DLLs

# VQL artifacts to collect per hunt type
HUNT_ARTIFACTS = {
    HuntType.QUICK: [
        'Generic.System.Pstree',          # Process tree
        'Linux.Network.Netstat',           # Network connections
        'Generic.System.Users',            # Local users
        'Linux.Sys.LastUserLogin',         # Recent logins
    ],
    HuntType.NETWORK: [
        'Linux.Network.Netstat',
        'Linux.Network.PacketCapture',
        'Generic.Network.InterfaceAddresses',
    ],
    HuntType.PROCESSES: [
        'Generic.System.Pstree',
        'Linux.Proc.Modules',
        'Linux.Sys.Crontab',
    ],
    HuntType.FULL: [
        'Generic.System.Pstree',
        'Linux.Network.Netstat',
        'Generic.System.Users',
        'Linux.Sys.LastUserLogin',
        'Linux.Network.PacketCapture',
        'Linux.Proc.Modules',
        'Linux.Sys.Crontab',
        'Generic.Forensic.Timeline',
        'Linux.Forensics.Journal',
    ],
}

@dataclass
class IRIncident:
    """Represents a single IR incident triggered by a finding"""
    incident_id: str
    instance_id: str
    finding_id: str
    reason: str
    status: IRStatus
    created_at: str
    updated_at: str
    hunt_type: str = HuntType.QUICK
    artifacts: Dict = None
    notes: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        d['status'] = self.status.value
        return d


# ============================================================================
# IN-MEMORY INCIDENT STORE (replace with DB in production)
# ============================================================================
_incidents: Dict[str, IRIncident] = {}


# ============================================================================
# VELOCIRAPTOR INTEGRATION
# ============================================================================

class VelociraptorIntegration:
    """
    Connects C.I.R.A to a Velociraptor server for forensic response.

    When VELOCIRAPTOR_URL is not set, all methods operate in simulation mode
    so the rest of the system can still run and be demonstrated.
    """

    def __init__(self):
        self.server_url = os.getenv('VELOCIRAPTOR_URL', '')
        self.api_key    = os.getenv('VELOCIRAPTOR_API_KEY', '')
        self.region     = os.getenv('AWS_REGION', 'us-east-1')
        self._ssm       = boto3.client('ssm', region_name=self.region)

    def is_connected(self) -> bool:
        """Check if Velociraptor server is configured and reachable"""
        if not self.server_url:
            return False
        try:
            import requests
            r = requests.get(
                f"{self.server_url}/api/v1/GetServerInfo",
                headers={'Authorization': f'Bearer {self.api_key}'},
                timeout=3,
                verify=False
            )
            return r.status_code == 200
        except Exception:
            return False

    # -------------------------------------------------------------------------
    # DEPLOY AGENT via AWS SSM
    # -------------------------------------------------------------------------

    def deploy_agent(self, instance_id: str, finding_id: str = '', reason: str = '') -> Dict:
        """
        Deploy Velociraptor agent on an EC2 instance using AWS SSM Run Command.
        SSM allows running shell commands without SSH access.
        """
        logger.info(f"[IR] Deploying Velociraptor agent on {instance_id}")

        incident_id = str(uuid.uuid4())[:8]
        now = datetime.utcnow().isoformat()

        incident = IRIncident(
            incident_id=incident_id,
            instance_id=instance_id,
            finding_id=finding_id,
            reason=reason,
            status=IRStatus.INVESTIGATING,
            created_at=now,
            updated_at=now,
            artifacts={}
        )
        _incidents[incident_id] = incident

        if not self.server_url:
            logger.warning("[IR] Velociraptor URL not configured — running in simulation mode")
            return {
                'success': True,
                'simulation': True,
                'incident_id': incident_id,
                'instance_id': instance_id,
                'message': (
                    'Simulation mode: set VELOCIRAPTOR_URL and VELOCIRAPTOR_API_KEY in .env '
                    'to deploy a real agent. See backend/connectors/aws/forensics.py for setup.'
                ),
                'next_step': f'POST /api/ir/hunt/{instance_id}'
            }

        # Build SSM install command
        install_cmd = self._build_install_command()

        try:
            response = self._ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={'commands': install_cmd},
                Comment=f'CIRA IR: Deploy Velociraptor for finding {finding_id}'
            )
            command_id = response['Command']['CommandId']
            logger.info(f"[IR] SSM command sent: {command_id}")

            return {
                'success': True,
                'simulation': False,
                'incident_id': incident_id,
                'instance_id': instance_id,
                'ssm_command_id': command_id,
                'message': f'Velociraptor agent deployment started on {instance_id}',
                'next_step': f'POST /api/ir/hunt/{instance_id}'
            }

        except Exception as e:
            logger.error(f"[IR] SSM deploy failed: {e}")
            return {
                'success': False,
                'incident_id': incident_id,
                'instance_id': instance_id,
                'error': str(e),
                'hint': (
                    'Make sure the instance has SSM agent installed and '
                    'the IAM role includes AmazonSSMManagedInstanceCore policy.'
                )
            }

    # -------------------------------------------------------------------------
    # RUN HUNT
    # -------------------------------------------------------------------------

    def run_hunt(self, instance_id: str, hunt_type: str = 'quick') -> Dict:
        """
        Run a Velociraptor VQL hunt on the instance to collect forensic artifacts.
        """
        logger.info(f"[IR] Running {hunt_type} hunt on {instance_id}")

        try:
            hunt_enum = HuntType(hunt_type)
        except ValueError:
            hunt_enum = HuntType.QUICK

        artifacts_to_collect = HUNT_ARTIFACTS[hunt_enum]

        # Find open incident for this instance
        incident = self._find_incident(instance_id)

        if not self.server_url:
            # Simulation: return sample forensic data
            sample_results = self._simulate_hunt_results(instance_id, hunt_enum)
            if incident:
                incident.artifacts = sample_results
                incident.hunt_type = hunt_type
                incident.updated_at = datetime.utcnow().isoformat()

            return {
                'success': True,
                'simulation': True,
                'instance_id': instance_id,
                'hunt_type': hunt_type,
                'artifacts_collected': artifacts_to_collect,
                'results': sample_results,
                'message': 'Simulation mode — sample forensic data returned'
            }

        # Real Velociraptor hunt via REST API
        try:
            import requests
            hunt_response = requests.post(
                f"{self.server_url}/api/v1/CreateHunt",
                headers={'Authorization': f'Bearer {self.api_key}'},
                json={
                    'artifacts': artifacts_to_collect,
                    'condition': {
                        'os': {'windows': False, 'linux': True, 'darwin': False}
                    }
                },
                verify=False,
                timeout=10
            )
            hunt_data = hunt_response.json()
            hunt_id = hunt_data.get('hunt_id', 'unknown')

            if incident:
                incident.artifacts = {'hunt_id': hunt_id, 'status': 'running'}
                incident.updated_at = datetime.utcnow().isoformat()

            return {
                'success': True,
                'simulation': False,
                'instance_id': instance_id,
                'hunt_id': hunt_id,
                'artifacts_collecting': artifacts_to_collect,
                'message': f'Hunt {hunt_id} started on {instance_id}',
                'next_step': f'GET /api/ir/results/{instance_id}'
            }

        except Exception as e:
            logger.error(f"[IR] Hunt failed: {e}")
            return {'success': False, 'instance_id': instance_id, 'error': str(e)}

    # -------------------------------------------------------------------------
    # GET ARTIFACTS
    # -------------------------------------------------------------------------

    def get_artifacts(self, instance_id: str) -> Dict:
        """Return collected forensic artifacts for an instance"""
        incident = self._find_incident(instance_id)

        if not incident:
            return {
                'instance_id': instance_id,
                'found': False,
                'message': 'No IR incident found for this instance. Run deploy first.'
            }

        return {
            'instance_id': instance_id,
            'incident_id': incident.incident_id,
            'status': incident.status.value,
            'finding_id': incident.finding_id,
            'hunt_type': incident.hunt_type,
            'artifacts': incident.artifacts or {},
            'created_at': incident.created_at,
            'updated_at': incident.updated_at,
        }

    # -------------------------------------------------------------------------
    # LIST INCIDENTS
    # -------------------------------------------------------------------------

    def list_incidents(self, status_filter: str = 'all') -> List[Dict]:
        """Return list of all IR incidents"""
        incidents = list(_incidents.values())
        if status_filter != 'all':
            incidents = [i for i in incidents if i.status.value == status_filter]
        incidents.sort(key=lambda x: x.created_at, reverse=True)
        return [i.to_dict() for i in incidents]

    # -------------------------------------------------------------------------
    # RESOLVE INCIDENT
    # -------------------------------------------------------------------------

    def resolve_incident(self, incident_id: str, notes: str = '') -> Dict:
        """Mark an incident as resolved"""
        if incident_id not in _incidents:
            return {'success': False, 'error': f'Incident {incident_id} not found'}

        _incidents[incident_id].status = IRStatus.RESOLVED
        _incidents[incident_id].notes = notes
        _incidents[incident_id].updated_at = datetime.utcnow().isoformat()

        return {
            'success': True,
            'incident_id': incident_id,
            'status': 'resolved',
            'message': f'Incident {incident_id} marked as resolved'
        }

    # -------------------------------------------------------------------------
    # HELPERS
    # -------------------------------------------------------------------------

    def _find_incident(self, instance_id: str) -> Optional[IRIncident]:
        """Find the most recent open incident for an instance"""
        matches = [
            i for i in _incidents.values()
            if i.instance_id == instance_id and i.status != IRStatus.RESOLVED
        ]
        if not matches:
            return None
        return sorted(matches, key=lambda x: x.created_at, reverse=True)[0]

    def _build_install_command(self) -> List[str]:
        """Build SSM shell commands to install Velociraptor agent"""
        server = self.server_url
        api_key = self.api_key
        return [
            '#!/bin/bash',
            'set -e',
            f'echo "CIRA IR: Installing Velociraptor agent from {server}"',
            'curl -L https://github.com/Velocidex/velociraptor/releases/latest/download/velociraptor-linux-amd64 -o /tmp/velociraptor',
            'chmod +x /tmp/velociraptor',
            f'/tmp/velociraptor config client --server_url {server} --api_key {api_key} > /tmp/velociraptor.config.yaml',
            '/tmp/velociraptor --config /tmp/velociraptor.config.yaml service install',
            'echo "CIRA IR: Velociraptor agent installed successfully"'
        ]

    def _simulate_hunt_results(self, instance_id: str, hunt_type: HuntType) -> Dict:
        """Return simulated forensic artifacts for demo purposes"""
        return {
            'simulation': True,
            'instance_id': instance_id,
            'hunt_type': hunt_type.value,
            'collected_at': datetime.utcnow().isoformat(),
            'processes': [
                {'pid': 1,    'name': 'systemd',  'user': 'root',   'cmdline': '/sbin/init'},
                {'pid': 1234, 'name': 'sshd',     'user': 'root',   'cmdline': '/usr/sbin/sshd -D'},
                {'pid': 5678, 'name': 'python3',  'user': 'ubuntu', 'cmdline': 'python3 api.py'},
            ],
            'network_connections': [
                {'local': '0.0.0.0:22',   'remote': '0.0.0.0:0',        'state': 'LISTEN', 'pid': 1234, 'risk': 'HIGH — open to internet'},
                {'local': '0.0.0.0:5000', 'remote': '0.0.0.0:0',        'state': 'LISTEN', 'pid': 5678, 'risk': 'MEDIUM'},
                {'local': '10.0.1.5:22',  'remote': '203.0.113.42:4122', 'state': 'ESTABLISHED', 'pid': 1234, 'risk': 'INVESTIGATE — external SSH session'},
            ],
            'recent_logins': [
                {'user': 'ubuntu', 'from': '203.0.113.42', 'time': datetime.utcnow().isoformat()},
            ],
            'suspicious_indicators': [
                'SSH connection from external IP 203.0.113.42',
                'Port 22 open to 0.0.0.0/0 (matches finding AWS_EC2_001)',
            ]
        }
