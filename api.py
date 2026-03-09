#!/usr/bin/env python3
"""
C.I.R.A Flask API
REST endpoints for AWS security assessment and log collection
Reads from PostgreSQL DB (falls back to JSON if DB unavailable)
"""

import os
import json
import glob
from datetime import datetime, timezone

from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker

load_dotenv()

from backend.api.models import Base, Assessment, Finding, Resource, LogEvent, ComplianceStatus
from backend.api.routes import ir_bp

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), 'frontend/templates'),
    static_folder=os.path.join(os.path.dirname(__file__), 'frontend/static')
)
CORS(app)
app.register_blueprint(ir_bp)

# ============================================================================
# DATABASE
# ============================================================================

def get_db_session():
    url = (
        f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
        f"@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
    )
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


# ============================================================================
# JSON FALLBACK (used only if DB has no data)
# ============================================================================

def get_latest_scan_data():
    files = sorted(glob.glob('cira_assessment_*.json'), reverse=True)
    if not files:
        return None
    with open(files[0]) as f:
        return json.load(f)

def get_latest_logs_data():
    files = sorted(glob.glob('logs_*.json'), reverse=True)
    if not files:
        return None
    with open(files[0]) as f:
        return json.load(f)


# ============================================================================
# HELPERS
# ============================================================================

def assessment_to_dict(a: Assessment) -> dict:
    return {
        'id': a.id,
        'environment': a.environment,
        'account_id': a.account_id,
        'region': a.region,
        'timestamp': a.timestamp.isoformat() if a.timestamp else None,
        'summary': {
            'total_checks': a.total_checks,
            'passed': a.passed,
            'failed': a.failed,
            'pass_rate': a.pass_rate,
            'severity': {
                'critical': a.critical_count,
                'high': a.high_count,
                'medium': a.medium_count,
                'low': a.low_count,
            }
        }
    }

def finding_to_dict(f: Finding) -> dict:
    return {
        'id': f.id,
        'assessment_id': f.assessment_id,
        'check_id': f.check_id,
        'check_title': f.check_title,
        'service': f.service,
        'severity': f.severity,
        'status': f.status,
        'resource_id': f.resource_id,
        'resource_type': f.resource_type,
        'region': f.region,
        'description': f.description,
        'remediation': f.remediation,
        'frameworks': f.frameworks or [],
        'threat_score': f.threat_score,
        'timestamp': f.timestamp.isoformat() if f.timestamp else None,
    }

def log_to_dict(l: LogEvent) -> dict:
    return {
        'id': l.id,
        'timestamp': l.timestamp.isoformat() if l.timestamp else None,
        'source': l.source,
        'account': l.account,
        'region': l.region,
        'service': l.service,
        'action': l.action,
        'principal': l.principal,
        'principal_type': l.principal_type,
        'status': l.status,
        'severity': l.severity,
        'resource_id': l.resource_id,
        'resource_type': l.resource_type,
        'message': l.message,
    }


# ============================================================================
# DASHBOARD
# ============================================================================

@app.route('/')
def dashboard():
    """Main dashboard - tries DB first, falls back to JSON"""
    data = None
    try:
        session = get_db_session()
        assessment = session.query(Assessment).order_by(desc(Assessment.timestamp)).first()
        if assessment:
            findings = session.query(Finding).filter_by(assessment_id=assessment.id).all()
            resources_raw = session.query(Resource).all()

            resources = {}
            for r in resources_raw:
                key = r.resource_type + 's'
                resources.setdefault(key, []).append(r.resource_metadata or {'id': r.resource_id})

            data = {
                **assessment_to_dict(assessment),
                'findings': [finding_to_dict(f) for f in findings],
                'resources': resources,
            }
        session.close()
    except Exception as e:
        print(f"DB unavailable, falling back to JSON: {e}")
        data = get_latest_scan_data()

    return render_template('dashboard.html', data=data)


# ============================================================================
# API ROOT
# ============================================================================

@app.route('/api/')
def api_root():
    return jsonify({
        'service': 'C.I.R.A - AWS Cloud Security Assessment',
        'version': '2.0.0',
        'endpoints': {
            '/': 'Dashboard',
            '/api/health': 'Health check',
            '/api/assessments/latest': 'Latest assessment',
            '/api/assessments/summary': 'Assessment summary',
            '/api/findings': 'Findings (filters: severity, service, status)',
            '/api/findings/<id>': 'Finding by check_id',
            '/api/resources': 'All resources',
            '/api/compliance/<framework>': 'Compliance status (CIS, GDPR, HIPAA, PCI-DSS)',
            '/api/logs': 'Logs (filters: source, severity, service, status, limit, offset)',
            '/api/logs/stats': 'Log statistics',
            '/api/ir/status': 'Velociraptor connection status (Phase 3)',
            '/api/ir/deploy/<instance_id>': 'Deploy Velociraptor agent on EC2 instance',
            '/api/ir/hunt/<instance_id>': 'Run forensic hunt (quick/full/network/processes)',
            '/api/ir/results/<instance_id>': 'Get collected forensic artifacts',
            '/api/ir/incidents': 'List all IR incidents',
        }
    }), 200


# ============================================================================
# HEALTH
# ============================================================================

@app.route('/api/health')
def health_check():
    db_ok = False
    try:
        session = get_db_session()
        session.execute(__import__('sqlalchemy').text('SELECT 1'))
        db_ok = True
        session.close()
    except Exception:
        pass

    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'db_connected': db_ok,
    }), 200


# ============================================================================
# ASSESSMENTS
# ============================================================================

@app.route('/api/assessments/latest')
def get_latest_assessment():
    try:
        session = get_db_session()
        assessment = session.query(Assessment).order_by(desc(Assessment.timestamp)).first()
        if not assessment:
            session.close()
            return jsonify({'error': 'No assessment data available'}), 404

        findings = session.query(Finding).filter_by(assessment_id=assessment.id).all()
        resources_raw = session.query(Resource).all()
        resources = {}
        for r in resources_raw:
            resources.setdefault(r.resource_type + 's', []).append(r.resource_metadata or {})

        result = {
            **assessment_to_dict(assessment),
            'findings': [finding_to_dict(f) for f in findings],
            'resources': resources,
        }
        session.close()
        return jsonify(result), 200
    except Exception as e:
        data = get_latest_scan_data()
        if not data:
            return jsonify({'error': str(e)}), 500
        return jsonify(data), 200


@app.route('/api/assessments/summary')
def get_assessment_summary():
    try:
        session = get_db_session()
        assessment = session.query(Assessment).order_by(desc(Assessment.timestamp)).first()
        session.close()
        if not assessment:
            return jsonify({'error': 'No data'}), 404
        return jsonify(assessment_to_dict(assessment)), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# FINDINGS
# ============================================================================

@app.route('/api/findings')
def list_findings():
    severity = request.args.get('severity')
    service  = request.args.get('service')
    status   = request.args.get('status')

    try:
        session = get_db_session()
        q = session.query(Finding)
        if severity:
            q = q.filter(Finding.severity == severity.upper())
        if service:
            q = q.filter(Finding.service == service.lower())
        if status:
            q = q.filter(Finding.status == status.upper())
        findings = q.order_by(desc(Finding.threat_score)).all()
        session.close()
        return jsonify({'total': len(findings), 'findings': [finding_to_dict(f) for f in findings]}), 200
    except Exception as e:
        data = get_latest_scan_data()
        if not data:
            return jsonify({'total': 0, 'findings': []}), 200
        findings = data.get('findings', [])
        if severity:
            findings = [f for f in findings if f['severity'] == severity.upper()]
        if service:
            findings = [f for f in findings if f['service'] == service.lower()]
        if status:
            findings = [f for f in findings if f['status'] == status.upper()]
        findings.sort(key=lambda x: x.get('threat_score', 0), reverse=True)
        return jsonify({'total': len(findings), 'findings': findings}), 200


@app.route('/api/findings/<finding_id>')
def get_finding(finding_id):
    try:
        session = get_db_session()
        finding = session.query(Finding).filter_by(check_id=finding_id).first()
        session.close()
        if not finding:
            return jsonify({'error': f'Finding {finding_id} not found'}), 404
        return jsonify(finding_to_dict(finding)), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# RESOURCES
# ============================================================================

@app.route('/api/resources')
def get_resources():
    try:
        session = get_db_session()
        resources_raw = session.query(Resource).all()
        session.close()
        resources = {}
        for r in resources_raw:
            resources.setdefault(r.resource_type + 's', []).append(r.resource_metadata or {'id': r.resource_id})
        return jsonify({'total_types': len(resources), 'resources': resources}), 200
    except Exception as e:
        return jsonify({'resources': {}}), 200


@app.route('/api/resources/<resource_type>')
def get_resources_by_type(resource_type):
    try:
        session = get_db_session()
        resources = session.query(Resource).filter_by(resource_type=resource_type).all()
        session.close()
        return jsonify({
            'type': resource_type,
            'count': len(resources),
            'resources': [r.resource_metadata or {'id': r.resource_id} for r in resources],
        }), 200
    except Exception as e:
        return jsonify({'resources': []}), 200


# ============================================================================
# COMPLIANCE
# ============================================================================

@app.route('/api/compliance/<framework>')
def get_compliance(framework):
    try:
        session = get_db_session()
        compliance = session.query(ComplianceStatus).filter_by(framework=framework.upper()).order_by(desc(ComplianceStatus.timestamp)).first()
        session.close()

        if not compliance:
            return jsonify({'framework': framework, 'status': 'not_found'}), 200

        return jsonify({
            'framework': compliance.framework,
            'total_controls': compliance.total_controls,
            'passed': compliance.passed,
            'failed': compliance.failed,
            'compliance_percentage': compliance.compliance_percentage,
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# LOGS
# ============================================================================

@app.route('/api/logs')
def get_logs():
    source   = request.args.get('source')
    severity = request.args.get('severity')
    service  = request.args.get('service')
    status   = request.args.get('status')
    limit    = int(request.args.get('limit', 100))
    offset   = int(request.args.get('offset', 0))

    try:
        session = get_db_session()
        q = session.query(LogEvent).order_by(desc(LogEvent.timestamp))
        if source:
            q = q.filter(LogEvent.source == source)
        if severity:
            q = q.filter(LogEvent.severity == severity)
        if service:
            q = q.filter(LogEvent.service == service)
        if status:
            q = q.filter(LogEvent.status == status)

        total = q.count()
        logs = q.offset(offset).limit(limit).all()
        session.close()
        return jsonify({
            'total': total,
            'returned': len(logs),
            'offset': offset,
            'limit': limit,
            'logs': [log_to_dict(l) for l in logs],
        }), 200
    except Exception as e:
        data = get_latest_logs_data()
        if not data:
            return jsonify({'total': 0, 'logs': [], 'message': 'No logs available'}), 200
        logs = data.get('records', [])
        return jsonify({'total': len(logs), 'returned': len(logs), 'logs': logs}), 200


@app.route('/api/logs/stats')
def get_logs_stats():
    try:
        session = get_db_session()
        from sqlalchemy import func
        stats = {
            'total': session.query(LogEvent).count(),
            'by_source': {},
            'by_service': {},
            'by_severity': {},
            'by_status': {},
        }
        for col, key in [(LogEvent.source, 'by_source'), (LogEvent.service, 'by_service'),
                         (LogEvent.severity, 'by_severity'), (LogEvent.status, 'by_status')]:
            rows = session.query(col, func.count(col)).group_by(col).all()
            stats[key] = {str(r[0]): r[1] for r in rows if r[0]}
        session.close()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'total': 0, 'by_source': {}, 'by_service': {}, 'by_severity': {}, 'by_status': {}}), 200


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*80)
    print("C.I.R.A AWS Assessment API + Dashboard  (DB-backed)")
    print("="*80)
    print(f"\n  Dashboard : http://localhost:5000/")
    print(f"  API root  : http://localhost:5000/api/")
    print(f"  Health    : http://localhost:5000/api/health")
    print("\n" + "="*80 + "\n")
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('API_PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development'
    )
