"""
Check Database Data
Displays all data in C.I.R.A database
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.api.models import Assessment, Finding, Resource, LogEvent, ComplianceStatus
import os
from dotenv import load_dotenv

load_dotenv()

print("\n" + "=" * 60)
print("Database Data Check")
print("=" * 60)

def get_db_url():
    """Get database URL from environment variables"""
    return f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"

try:
    print("\nConnecting to PostgreSQL...")
    engine = create_engine(get_db_url())
    Session = sessionmaker(bind=engine)
    session = Session()
    print("OK: Connected to database")
    
    print("\n" + "-" * 60)
    print("ASSESSMENTS")
    print("-" * 60)
    assessments = session.query(Assessment).all()
    if assessments:
        for assessment in assessments:
            print(f"\nID: {assessment.id}")
            print(f"Environment: {assessment.environment}")
            print(f"Region: {assessment.region}")
            print(f"Total Checks: {assessment.total_checks}")
            print(f"Passed: {assessment.passed}")
            print(f"Failed: {assessment.failed}")
            print(f"Pass Rate: {assessment.pass_rate}")
    else:
        print("No assessments found")
    
    print("\n" + "-" * 60)
    print("RESOURCES")
    print("-" * 60)
    resources = session.query(Resource).all()
    if resources:
        print(f"Total: {len(resources)}")
        for resource in resources:
            status = "running" if resource.state == "running" else resource.state
            print(f"  - {resource.name} ({resource.resource_id}) [{status}]")
    else:
        print("No resources found")
    
    print("\n" + "-" * 60)
    print("FINDINGS")
    print("-" * 60)
    findings = session.query(Finding).all()
    if findings:
        print(f"Total: {len(findings)}")
        critical = len([f for f in findings if f.severity == 'CRITICAL'])
        high = len([f for f in findings if f.severity == 'HIGH'])
        medium = len([f for f in findings if f.severity == 'MEDIUM'])
        passed = len([f for f in findings if f.status == 'PASS'])
        failed = len([f for f in findings if f.status == 'FAIL'])
        
        print(f"  By Severity:")
        print(f"    - Critical: {critical}")
        print(f"    - High: {high}")
        print(f"    - Medium: {medium}")
        print(f"  By Status:")
        print(f"    - Passed: {passed}")
        print(f"    - Failed: {failed}")
        
        print(f"\n  Open Findings:")
        for finding in findings:
            if finding.status == 'FAIL':
                print(f"    [{finding.severity}] {finding.check_title}")
    else:
        print("No findings found")
    
    print("\n" + "-" * 60)
    print("LOG EVENTS")
    print("-" * 60)
    logs = session.query(LogEvent).all()
    if logs:
        print(f"Total: {len(logs)}")
        
        by_service = {}
        by_severity = {}
        by_status = {}
        
        for log in logs:
            by_service[log.service] = by_service.get(log.service, 0) + 1
            by_severity[log.severity] = by_severity.get(log.severity, 0) + 1
            by_status[log.status] = by_status.get(log.status, 0) + 1
        
        print(f"  By Service:")
        for service, count in sorted(by_service.items()):
            print(f"    - {service}: {count}")
        
        print(f"  By Severity:")
        for severity, count in sorted(by_severity.items()):
            print(f"    - {severity}: {count}")
        
        print(f"  By Status:")
        for status, count in sorted(by_status.items()):
            print(f"    - {status}: {count}")
        
        print(f"\n  Recent Events:")
        recent = sorted(logs, key=lambda x: x.timestamp, reverse=True)[:5]
        for log in recent:
            print(f"    - {log.timestamp} | {log.service} | {log.action}")
    else:
        print("No log events found")
    
    print("\n" + "-" * 60)
    print("COMPLIANCE STATUS")
    print("-" * 60)
    compliance = session.query(ComplianceStatus).all()
    if compliance:
        print(f"Frameworks: {len(compliance)}")
        for status in compliance:
            print(f"\n  {status.framework}:")
            print(f"    - Total Controls: {status.total_controls}")
            print(f"    - Passed: {status.passed}")
            print(f"    - Failed: {status.failed}")
            print(f"    - Compliance: {status.compliance_percentage}%")
    else:
        print("No compliance data found")
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    total_assessments = session.query(Assessment).count()
    total_resources = session.query(Resource).count()
    total_findings = session.query(Finding).count()
    total_logs = session.query(LogEvent).count()
    
    print(f"Assessments: {total_assessments}")
    print(f"Resources: {total_resources}")
    print(f"Findings: {total_findings}")
    print(f"Log Events: {total_logs}")
    
    if total_assessments == 0:
        print("\nNo data in database. Run create_test_data.py first.")
    
except Exception as e:
    print(f"\nFAIL: {e}")
    print("\nTroubleshooting:")
    print("   - Check PostgreSQL is running")
    print("   - Run init_database.py first")
    print("   - Run create_test_data.py to populate data")
finally:
    if 'session' in locals():
        session.close()