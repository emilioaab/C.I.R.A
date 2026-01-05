#!/usr/bin/env python3
"""
C.I.R.A Flask API
REST endpoints for AWS security assessment and log collection
Serves Jinja2 dashboard template
"""

from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from datetime import datetime, timezone
import os
import json
import glob
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, 
    template_folder=os.path.join(os.path.dirname(__file__), 'frontend/templates'),
    static_folder=os.path.join(os.path.dirname(__file__), 'frontend/static'))
CORS(app)

# ============================================================================
# DATA LOADING FUNCTIONS
# ============================================================================

def get_latest_scan_data():
    """Load the latest assessment report from JSON file"""
    assessment_files = sorted(glob.glob('cira_assessment_*.json'), reverse=True)
    if not assessment_files:
        return None
    with open(assessment_files[0], 'r') as f:
        return json.load(f)

def get_latest_logs_data():
    """Load the latest logs report from JSON file"""
    log_files = sorted(glob.glob('logs_*.json'), reverse=True)
    if not log_files:
        return None
    with open(log_files[0], 'r') as f:
        return json.load(f)

# ============================================================================
# FRONTEND ROUTES
# ============================================================================

@app.route('/')
def dashboard():
    """Main dashboard - served via Jinja template"""
    data = get_latest_scan_data()
    return render_template('dashboard.html', data=data)

# ============================================================================
# API ROOT
# ============================================================================

@app.route('/api/')
def api_root():
    """API root - list available endpoints"""
    return jsonify({
        'service': 'C.I.R.A - AWS Cloud Security Assessment',
        'version': '1.0.0',
        'frontend': '/',
        'endpoints': {
            '/': 'Main dashboard (Jinja template)',
            '/api/health': 'API health check',
            '/api/assessments/latest': 'Latest assessment report',
            '/api/assessments/summary': 'Assessment summary only',
            '/api/findings': 'All findings with optional filters',
            '/api/findings/<id>': 'Specific finding details',
            '/api/resources': 'All discovered resources',
            '/api/resources/<type>': 'Resources by type',
            '/api/compliance/<framework>': 'Compliance framework status',
            '/api/logs': 'All logs with optional filters (Phase 2)',
            '/api/logs/stats': 'Log statistics summary (Phase 2)'
        }
    }), 200

# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'service': 'C.I.R.A Assessment API'
    }), 200

# ============================================================================
# ASSESSMENT ENDPOINTS
# ============================================================================

@app.route('/api/assessments/latest', methods=['GET'])
def get_latest_assessment():
    """GET /api/assessments/latest - Returns full latest assessment data"""
    data = get_latest_scan_data()
    if not data:
        return jsonify({'error': 'No assessment data available'}), 404
    return jsonify(data), 200

@app.route('/api/assessments/summary', methods=['GET'])
def get_assessment_summary():
    """GET /api/assessments/summary - Returns summary information only"""
    data = get_latest_scan_data()
    if not data:
        return jsonify({'error': 'No assessment data available'}), 404
    return jsonify({
        'summary': data.get('summary'),
        'timestamp': data.get('timestamp'),
        'environment': data.get('environment')
    }), 200

# ============================================================================
# FINDINGS ENDPOINTS
# ============================================================================

@app.route('/api/findings', methods=['GET'])
def list_findings():
    """GET /api/findings - Returns findings with optional filters
    
    Query Parameters:
        severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
        service: Filter by service (iam, ec2, s3, etc.)
        status: Filter by status (PASS, FAIL)
    """
    data = get_latest_scan_data()
    if not data:
        return jsonify({'total': 0, 'findings': []}), 200
    
    severity = request.args.get('severity', None)
    service = request.args.get('service', None)
    status = request.args.get('status', None)
    findings = data.get('findings', [])
    
    if severity:
        findings = [f for f in findings if f['severity'] == severity]
    if service:
        findings = [f for f in findings if f['service'] == service]
    if status:
        findings = [f for f in findings if f['status'] == status]
    
    findings.sort(key=lambda x: x.get('threat_score', 0), reverse=True)
    
    return jsonify({
        'total': len(findings),
        'findings': findings
    }), 200

@app.route('/api/findings/<finding_id>', methods=['GET'])
def get_finding(finding_id):
    """GET /api/findings/<id> - Returns specific finding details"""
    data = get_latest_scan_data()
    if not data:
        return jsonify({'error': 'No finding data available'}), 404
    
    findings = data.get('findings', [])
    finding = next((f for f in findings if f['check_id'] == finding_id), None)
    
    if not finding:
        return jsonify({'error': f'Finding {finding_id} not found'}), 404
    
    return jsonify(finding), 200

# ============================================================================
# RESOURCES ENDPOINTS
# ============================================================================

@app.route('/api/resources', methods=['GET'])
def get_resources():
    """GET /api/resources - Returns all discovered resource types"""
    data = get_latest_scan_data()
    if not data:
        return jsonify({'resources': {}}), 200
    
    resources = data.get('resources', {})
    
    return jsonify({
        'total_types': len(resources),
        'resources': resources
    }), 200

@app.route('/api/resources/<resource_type>', methods=['GET'])
def get_resources_by_type(resource_type):
    """GET /api/resources/<type> - Returns resources of specific type"""
    data = get_latest_scan_data()
    if not data:
        return jsonify({'resources': []}), 200
    
    resources = data.get('resources', {})
    
    if resource_type not in resources:
        return jsonify({'error': f'Resource type {resource_type} not found'}), 404
    
    return jsonify({
        'type': resource_type,
        'count': len(resources[resource_type]),
        'resources': resources[resource_type]
    }), 200

# ============================================================================
# COMPLIANCE ENDPOINTS
# ============================================================================

@app.route('/api/compliance/<framework>', methods=['GET'])
def get_compliance(framework):
    """GET /api/compliance/<framework> - Returns compliance status
    
    Frameworks: CIS, GDPR, HIPAA, PCI-DSS
    """
    data = get_latest_scan_data()
    if not data:
        return jsonify({'compliance': {}}), 200
    
    findings = data.get('findings', [])
    framework_findings = [f for f in findings if framework in f.get('frameworks', [])]
    
    if not framework_findings:
        return jsonify({
            'framework': framework,
            'status': 'not_found',
            'message': f'No findings for {framework} framework'
        }), 200
    
    passed = len([f for f in framework_findings if f['status'] == 'PASS'])
    failed = len([f for f in framework_findings if f['status'] == 'FAIL'])
    total = passed + failed
    compliance_percentage = (passed / total * 100) if total > 0 else 0
    
    return jsonify({
        'framework': framework,
        'total_controls': total,
        'passed': passed,
        'failed': failed,
        'compliance_percentage': round(compliance_percentage, 1),
        'findings': framework_findings
    }), 200

# ============================================================================
# LOG ENDPOINTS
# ============================================================================

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """GET /api/logs - Returns logs with optional filters
    
    Query Parameters:
        source: Filter by source (cloudtrail, vpc_flow, cloudwatch)
        severity: Filter by severity (critical, high, medium, low, info)
        service: Filter by service (iam, ec2, s3, etc.)
        status: Filter by status (success, failure)
        limit: Maximum records to return (default: 100)
        offset: Pagination offset (default: 0)
    
    Example: /api/logs?source=cloudtrail&severity=critical&limit=50
    """
    data = get_latest_logs_data()
    if not data:
        return jsonify({
            'total': 0,
            'logs': [],
            'message': 'No logs available. Run log collector first.'
        }), 200
    
    source = request.args.get('source', None)
    severity = request.args.get('severity', None)
    service = request.args.get('service', None)
    status = request.args.get('status', None)
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    logs = data.get('records', [])
    
    if source:
        logs = [l for l in logs if l.get('source') == source]
    if severity:
        logs = [l for l in logs if l.get('severity') == severity]
    if service:
        logs = [l for l in logs if l.get('service') == service]
    if status:
        logs = [l for l in logs if l.get('status') == status]
    
    logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    total = len(logs)
    paginated_logs = logs[offset:offset + limit]
    
    return jsonify({
        'total': total,
        'returned': len(paginated_logs),
        'offset': offset,
        'limit': limit,
        'logs': paginated_logs
    }), 200

@app.route('/api/logs/stats', methods=['GET'])
def get_logs_stats():
    """GET /api/logs/stats - Returns log statistics and summaries"""
    data = get_latest_logs_data()
    if not data:
        return jsonify({
            'total': 0,
            'by_source': {},
            'by_service': {},
            'by_severity': {},
            'by_status': {},
            'timestamp': None
        }), 200
    
    logs = data.get('records', [])
    
    stats = {
        'total': len(logs),
        'timestamp': data.get('timestamp'),
        'source_file': data.get('source'),
        'by_source': {},
        'by_service': {},
        'by_severity': {},
        'by_status': {}
    }
    
    for log in logs:
        source = log.get('source', 'unknown')
        service = log.get('service', 'unknown')
        severity = log.get('severity', 'unknown')
        status = log.get('status', 'unknown')
        
        stats['by_source'][source] = stats['by_source'].get(source, 0) + 1
        stats['by_service'][service] = stats['by_service'].get(service, 0) + 1
        stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
    
    stats['by_source'] = dict(sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True))
    stats['by_service'] = dict(sorted(stats['by_service'].items(), key=lambda x: x[1], reverse=True))
    stats['by_severity'] = dict(sorted(stats['by_severity'].items(), key=lambda x: x[1], reverse=True))
    stats['by_status'] = dict(sorted(stats['by_status'].items(), key=lambda x: x[1], reverse=True))
    
    return jsonify(stats), 200

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    print("\n" + "=" * 80)
    print("C.I.R.A AWS Assessment API + Dashboard")
    print("=" * 80)
    print("\nApplication Running on: http://localhost:5000")
    print("\nFrontend:")
    print("   Dashboard: http://localhost:5000/ (Jinja template)")
    print("\nAPI Endpoints:")
    print("   GET /api/                              List all endpoints")
    print("   GET /api/health                        API health check")
    print("   GET /api/assessments/latest            Latest assessment report")
    print("   GET /api/assessments/summary           Assessment summary only")
    print("   GET /api/findings                      All findings with filters")
    print("   GET /api/findings/<id>                 Specific finding details")
    print("   GET /api/resources                     All resources")
    print("   GET /api/resources/<type>              Resources by type")
    print("   GET /api/compliance/<framework>        Compliance status (CIS, GDPR, HIPAA, PCI-DSS)")
    print("   GET /api/logs                          All logs with filters (Phase 2)")
    print("   GET /api/logs/stats                    Log statistics (Phase 2)")
    print("\nQuery Parameters for /api/findings:")
    print("   ?severity=CRITICAL")
    print("   ?service=iam")
    print("   ?status=FAIL")
    print("\nQuery Parameters for /api/logs:")
    print("   ?source=cloudtrail")
    print("   ?severity=critical")
    print("   ?service=iam")
    print("   ?status=success")
    print("   ?limit=50&offset=0")
    print("\nDocumentation:")
    print("   Full API documentation at: http://localhost:5000/api/")
    print("\n" + "=" * 80 + "\n")
    
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('API_PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development'
    )