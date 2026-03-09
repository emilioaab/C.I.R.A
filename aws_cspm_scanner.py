#!/usr/bin/env python3
"""
C.I.R.A - AWS Cloud Security Assessment
Main scanner orchestrator - reads from AWS, saves to DB and JSON
"""

import os
import json
import uuid
from datetime import datetime, timezone
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

load_dotenv()

from backend.connectors.aws import AWSAssessment
from backend.api.models import Base, Assessment, Finding, Resource, ComplianceStatus


def get_db_session():
    url = (
        f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
        f"@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
    )
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def save_to_db(session, assessment_id: str, environment: str, region: str, report: dict):
    """Save full assessment report to PostgreSQL"""

    summary = report.get('summary', {})
    severity = summary.get('severity', {})

    # Upsert Assessment row
    existing = session.query(Assessment).filter_by(id=assessment_id).first()
    if existing:
        session.delete(existing)
        session.flush()

    assessment_row = Assessment(
        id=assessment_id,
        environment=environment,
        account_id=os.getenv('AWS_ACCOUNT_ID', 'unknown'),
        region=region,
        timestamp=datetime.utcnow(),
        total_checks=summary.get('total_checks', 0),
        passed=summary.get('passed', 0),
        failed=summary.get('failed', 0),
        pass_rate=summary.get('pass_rate', '0%'),
        critical_count=severity.get('critical', 0),
        high_count=severity.get('high', 0),
        medium_count=severity.get('medium', 0),
        low_count=severity.get('low', 0),
    )
    session.add(assessment_row)

    # Delete old findings for this assessment, then re-insert
    session.query(Finding).filter_by(assessment_id=assessment_id).delete()
    for f in report.get('findings', []):
        ts = f.get('timestamp')
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace('Z', '+00:00')).replace(tzinfo=None)
            except Exception:
                ts = datetime.utcnow()
        else:
            ts = datetime.utcnow()

        session.add(Finding(
            id=str(uuid.uuid4()),
            assessment_id=assessment_id,
            check_id=f.get('check_id', ''),
            check_title=f.get('check_title', ''),
            service=f.get('service', ''),
            severity=f.get('severity', ''),
            status=f.get('status', ''),
            resource_id=f.get('resource_id', ''),
            resource_type=f.get('resource_type', ''),
            region=f.get('region', region),
            description=f.get('description', ''),
            remediation=f.get('remediation', ''),
            frameworks=f.get('frameworks', []),
            threat_score=f.get('threat_score', 0),
            timestamp=ts,
        ))

    # Save resources (upsert by resource_id)
    resources = report.get('resources', {})
    for resource_type, items in resources.items():
        if not isinstance(items, list):
            continue
        for item in items:
            rid = (
                item.get('instance_id') or
                item.get('bucket_name') or
                item.get('db_identifier') or
                item.get('role_name') or
                item.get('lb_name') or
                str(uuid.uuid4())
            )
            existing_r = session.query(Resource).filter_by(resource_id=rid).first()
            if existing_r:
                existing_r.state = item.get('state', 'unknown')
                existing_r.resource_metadata = item
            else:
                session.add(Resource(
                    id=str(uuid.uuid4()),
                    resource_id=rid,
                    resource_type=resource_type.rstrip('s'),  # ec2_instances → ec2_instance
                    account=os.getenv('AWS_ACCOUNT_ID', 'unknown'),
                    region=region,
                    name=rid,
                    state=item.get('state', 'unknown'),
                    resource_metadata=item,
                ))

    # Save compliance per framework
    session.query(ComplianceStatus).filter_by(assessment_id=assessment_id).delete()
    all_findings = report.get('findings', [])
    frameworks = set()
    for f in all_findings:
        for fw in f.get('frameworks', []):
            frameworks.add(fw)

    for fw in frameworks:
        fw_findings = [f for f in all_findings if fw in f.get('frameworks', [])]
        fw_passed = len([f for f in fw_findings if f['status'] == 'PASS'])
        fw_failed = len([f for f in fw_findings if f['status'] == 'FAIL'])
        total = fw_passed + fw_failed
        pct = round((fw_passed / total * 100), 1) if total > 0 else 0.0

        session.add(ComplianceStatus(
            id=str(uuid.uuid4()),
            assessment_id=assessment_id,
            framework=fw,
            total_controls=total,
            passed=fw_passed,
            failed=fw_failed,
            compliance_percentage=pct,
        ))

    session.commit()
    print(f"DB: Assessment saved  (id={assessment_id})")


class AWSCSPMScanner:
    """Main AWS CSPM Scanner"""

    def __init__(self, region: str = None):
        self.region = region or os.getenv('AWS_REGION', 'us-east-1')
        self.all_findings = []
        self.resource_map = {}

    def scan_environment(self, environment: str = 'prod'):
        """Run comprehensive AWS assessment and save to DB + JSON"""
        print(f"\n{'='*80}")
        print(f"CIRA AWS Security Assessment - {environment.upper()} Environment")
        print(f"{'='*80}\n")

        assessment = AWSAssessment(region=self.region, environment=environment)

        print("1. IAM Assessment")
        iam_findings = assessment.assess_iam()
        print(f"   PASS: {len([f for f in iam_findings if f.status=='PASS'])}  FAIL: {len([f for f in iam_findings if f.status=='FAIL'])}\n")

        print("2. Network Assessment")
        network_findings = assessment.assess_network()
        print(f"   PASS: {len([f for f in network_findings if f.status=='PASS'])}  FAIL: {len([f for f in network_findings if f.status=='FAIL'])}\n")

        print("3. Storage Assessment")
        storage_findings = assessment.assess_storage()
        print(f"   PASS: {len([f for f in storage_findings if f.status=='PASS'])}  FAIL: {len([f for f in storage_findings if f.status=='FAIL'])}\n")

        print("4. Compliance Assessment")
        compliance_findings = assessment.assess_compliance()
        print(f"   PASS: {len([f for f in compliance_findings if f.status=='PASS'])}  FAIL: {len([f for f in compliance_findings if f.status=='FAIL'])}\n")

        print("5. Logging Assessment")
        logging_findings = assessment.assess_logging()
        print(f"   PASS: {len([f for f in logging_findings if f.status=='PASS'])}  FAIL: {len([f for f in logging_findings if f.status=='FAIL'])}\n")

        print("6. Resource Mapping")
        resources = assessment.assess_resources()
        print(f"   Mapped {len(resources)} resource types\n")

        self.all_findings = (
            iam_findings + network_findings + storage_findings +
            compliance_findings + logging_findings
        )
        self.resource_map = resources

        return self._generate_report(environment)

    def _generate_report(self, environment: str):
        findings = self.all_findings
        critical = [f for f in findings if f.severity == 'CRITICAL']
        high     = [f for f in findings if f.severity == 'HIGH']
        medium   = [f for f in findings if f.severity == 'MEDIUM']
        low      = [f for f in findings if f.severity == 'LOW']
        passed   = [f for f in findings if f.status == 'PASS']
        failed   = [f for f in findings if f.status == 'FAIL']
        total    = len(findings)

        print(f"\n{'='*80}")
        print(f"SUMMARY - {environment.upper()}")
        print(f"{'='*80}")
        print(f"Total:    {total}")
        print(f"Passed:   {len(passed)}")
        print(f"Failed:   {len(failed)}")
        pass_rate = f"{(len(passed)/total*100):.1f}%" if total > 0 else "0%"
        print(f"Pass rate: {pass_rate}")
        print(f"Critical: {len(critical)}  High: {len(high)}  Medium: {len(medium)}  Low: {len(low)}\n")

        report = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'environment': environment,
            'region': self.region,
            'summary': {
                'total_checks': total,
                'passed': len(passed),
                'failed': len(failed),
                'pass_rate': pass_rate,
                'severity': {
                    'critical': len(critical),
                    'high': len(high),
                    'medium': len(medium),
                    'low': len(low),
                }
            },
            'findings': [
                {
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
                    'frameworks': f.frameworks,
                    'threat_score': f.threat_score,
                    'timestamp': f.timestamp,
                }
                for f in findings
            ],
            'resources': self.resource_map,
        }

        # Save JSON (backup)
        filename = f"cira_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"JSON saved: {filename}")

        # Save to DB
        try:
            session = get_db_session()
            assessment_id = f"{environment}-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            save_to_db(session, assessment_id, environment, self.region, report)
            session.close()
        except Exception as e:
            print(f"DB save failed: {e}  (JSON backup still available)")

        return report


if __name__ == "__main__":
    env = os.getenv('CIRA_ENV', 'prod')
    scanner = AWSCSPMScanner()
    scanner.scan_environment(env)
    print(f"\nAssessment complete for environment: {env}\n")
