"""
C.I.R.A Incident Response Routes
Flask Blueprint for Phase 3 — Velociraptor forensics integration.

When C.I.R.A detects a critical finding, these endpoints trigger
a Velociraptor hunt on the affected EC2 instance to collect forensic artifacts.

Flow:
  Critical Finding detected
        ↓
  POST /api/ir/deploy/<instance_id>    → deploy Velociraptor agent
        ↓
  POST /api/ir/hunt/<instance_id>      → run forensic hunt
        ↓
  GET  /api/ir/results/<instance_id>   → retrieve artifacts
        ↓
  GET  /api/ir/incidents               → list all IR cases
"""

from flask import Blueprint, jsonify, request
from datetime import datetime

from backend.connectors.aws.forensics import VelociraptorIntegration, IRIncident, IRStatus

ir_bp = Blueprint('ir', __name__, url_prefix='/api/ir')


# ============================================================================
# DEPLOY VELOCIRAPTOR AGENT
# ============================================================================

@ir_bp.route('/deploy/<instance_id>', methods=['POST'])
def deploy_agent(instance_id):
    """
    POST /api/ir/deploy/<instance_id>
    Deploys Velociraptor agent on an EC2 instance via SSM.

    Body (optional):
        { "finding_id": "AWS_EC2_001", "reason": "Unrestricted SSH detected" }
    """
    body = request.get_json(silent=True) or {}
    finding_id = body.get('finding_id', 'manual')
    reason = body.get('reason', 'Manual IR trigger')

    velo = VelociraptorIntegration()
    result = velo.deploy_agent(instance_id, finding_id=finding_id, reason=reason)

    status_code = 200 if result['success'] else 500
    return jsonify(result), status_code


# ============================================================================
# RUN FORENSIC HUNT
# ============================================================================

@ir_bp.route('/hunt/<instance_id>', methods=['POST'])
def run_hunt(instance_id):
    """
    POST /api/ir/hunt/<instance_id>
    Runs a Velociraptor hunt on the instance to collect forensic artifacts.

    Body (optional):
        { "hunt_type": "full" }   # full | quick | network | processes
    """
    body = request.get_json(silent=True) or {}
    hunt_type = body.get('hunt_type', 'quick')

    velo = VelociraptorIntegration()
    result = velo.run_hunt(instance_id, hunt_type=hunt_type)

    status_code = 200 if result['success'] else 500
    return jsonify(result), status_code


# ============================================================================
# GET FORENSIC RESULTS
# ============================================================================

@ir_bp.route('/results/<instance_id>', methods=['GET'])
def get_results(instance_id):
    """
    GET /api/ir/results/<instance_id>
    Returns collected forensic artifacts for an instance.
    """
    velo = VelociraptorIntegration()
    result = velo.get_artifacts(instance_id)
    return jsonify(result), 200


# ============================================================================
# LIST ALL IR INCIDENTS
# ============================================================================

@ir_bp.route('/incidents', methods=['GET'])
def list_incidents():
    """
    GET /api/ir/incidents
    Returns all active and past IR incidents.

    Query params:
        status: open | investigating | resolved | all (default: all)
    """
    status_filter = request.args.get('status', 'all')

    velo = VelociraptorIntegration()
    incidents = velo.list_incidents(status_filter=status_filter)
    return jsonify({
        'total': len(incidents),
        'incidents': incidents
    }), 200


# ============================================================================
# CLOSE / RESOLVE INCIDENT
# ============================================================================

@ir_bp.route('/incidents/<incident_id>/resolve', methods=['POST'])
def resolve_incident(incident_id):
    """
    POST /api/ir/incidents/<incident_id>/resolve
    Marks an IR incident as resolved.
    """
    body = request.get_json(silent=True) or {}
    notes = body.get('notes', '')

    velo = VelociraptorIntegration()
    result = velo.resolve_incident(incident_id, notes=notes)

    status_code = 200 if result['success'] else 404
    return jsonify(result), status_code


# ============================================================================
# STATUS CHECK
# ============================================================================

@ir_bp.route('/status', methods=['GET'])
def ir_status():
    """
    GET /api/ir/status
    Returns Velociraptor server connection status.
    """
    velo = VelociraptorIntegration()
    return jsonify({
        'velociraptor_connected': velo.is_connected(),
        'server_url': velo.server_url or 'not configured',
        'timestamp': datetime.utcnow().isoformat(),
        'note': 'Set VELOCIRAPTOR_URL and VELOCIRAPTOR_API_KEY in .env to enable'
    }), 200
