#!/usr/bin/env python3
"""Flask API - REST endpoints for C.I.R.A with integrated Jinja dashboard"""
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from datetime import datetime
import os
import json
from dotenv import load_dotenv

load_dotenv()

# Configure Flask to serve templates and static files from frontend
app = Flask(__name__, 
    template_folder=os.path.join(os.path.dirname(__file__), 'frontend/templates'),
    static_folder=os.path.join(os.path.dirname(__file__), 'frontend/static'))
CORS(app)

# Load latest scan report
def get_latest_scan_data():
    """Load the latest assessment report"""
    import glob
    assessment_files = sorted(glob.glob('cira_assessment_*.json'), reverse=True)
    if not assessment_files:
        return None
    
    with open(assessment_files[0], 'r') as f:
        return json.load(f)

# ============================================================================
# FRONTEND ROUTES (Jinja Templates)
# ============================================================================

@app.route('/')
def dashboard():
    """Main dashboard - served via Jinja template"""
    data = get_latest_scan_data()
    return render_template('dashboard.html', data=data)

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
            '/api/findings': 'All findings (with filters)',
            '/api/findings/<id>': 'Find detail',
            '/api/resources': 'All resources',
            '/api/resources/<type>': 'Resources by type',
            '/api/compliance/<framework>': 'Compliance status',
        }
    }), 200

# ============================================================================
# API ENDPOINTS (REST)
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'C.I.R.A Assessment API'
    }), 200

@app.route('/api/assessments/latest', methods=['GET'])
def get_latest_assessment():
    """GET /api/assessments/latest - Returns latest assessment data"""
    data = get_latest_scan_data()
    if not data:
        return jsonify({'error': 'No assessment data available'}), 404
    return jsonify(data), 200

@app.route('/api/assessments/summary', methods=['GET'])
def get_assessment_summary():
    """GET /api/assessments/summary - Returns summary only"""
    data = get_latest_scan_data()
    if not data:
        return jsonify({'error': 'No assessment data available'}), 404
    
    return jsonify({
        'summary': data.get('summary'),
        'timestamp': data.get('timestamp'),
        'environment': data.get('environment')
    }), 200

@app.route('/api/findings', methods=['GET'])
def list_findings():
    """GET /api/findings - Returns findings with optional filters"""
    data = get_latest_scan_data()
    if not data:
        return jsonify({'total': 0, 'findings': []}), 200
    
    # Get filters from query params
    severity = request.args.get('severity', None)
    service = request.args.get('service', None)
    status = request.args.get('status', None)
    
    findings = data.get('findings', [])
    
    # Apply filters
    if severity:
        findings = [f for f in findings if f['severity'] == severity]
    if service:
        findings = [f for f in findings if f['service'] == service]
    if status:
        findings = [f for f in findings if f['status'] == status]
    
    # Sort by threat score
    findings.sort(key=lambda x: x.get('threat_score', 0), reverse=True)
    
    return jsonify({
        'total': len(findings),
        'findings': findings
    }), 200

@app.route('/api/findings/<finding_id>', methods=['GET'])
def get_finding(finding_id):
    """GET /api/findings/<id> - Returns finding detail"""
    data = get_latest_scan_data()
    if not data:
        return jsonify({'error': 'No finding data available'}), 404
    
    findings = data.get('findings', [])
    finding = next((f for f in findings if f['check_id'] == finding_id), None)
    
    if not finding:
        return jsonify({'error': f'Finding {finding_id} not found'}), 404
    
    return jsonify(finding), 200

@app.route('/api/resources', methods=['GET'])
def get_resources():
    """GET /api/resources - Returns all resource types"""
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
    """GET /api/resources/<type> - Returns resources by type"""
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

@app.route('/api/compliance/<framework>', methods=['GET'])
def get_compliance(framework):
    """GET /api/compliance/<framework> - Returns compliance status"""
    data = get_latest_scan_data()
    if not data:
        return jsonify({'compliance': {}}), 200
    
    findings = data.get('findings', [])
    
    # Filter findings by framework
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

if __name__ == '__main__':
    print("\n" + "="*80)
    print("🚀 C.I.R.A AWS Assessment API + Dashboard")
    print("="*80)
    print("\n📍 Application Running on: http://localhost:5000")
    print("\n🌐 Frontend:")
    print("   Dashboard: http://localhost:5000/ (Jinja template)")
    print("\n📋 API Endpoints:")
    print("   GET /api/                      - List endpoints")
    print("   GET /api/health                - Health check")
    print("   GET /api/assessments/latest    - Latest assessment")
    print("   GET /api/assessments/summary   - Summary only")
    print("   GET /api/findings              - All findings (with filters)")
    print("   GET /api/findings/<id>         - Finding detail")
    print("   GET /api/resources             - All resources")
    print("   GET /api/resources/<type>      - Resources by type")
    print("   GET /api/compliance/<framework>- Compliance status")
    print("\n🔗 Query Parameters:")
    print("   /api/findings?severity=CRITICAL")
    print("   /api/findings?service=iam")
    print("   /api/findings?status=FAIL")
    print("\n" + "="*80 + "\n")
    
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('API_PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development'
    )