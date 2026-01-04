#!/usr/bin/env python3
"""
C.I.R.A - AWS Cloud Security Assessment
Main scanner orchestrator
"""

from backend.connectors.aws import AWSAssessment
from datetime import datetime
import json
import os
from dotenv import load_dotenv

load_dotenv()

class AWSCSPMScanner:
    """Main AWS CSPM Scanner"""
    
    def __init__(self, region: str = None):
        self.region = region or os.getenv('AWS_REGION', 'us-east-1')
        self.all_findings = []
        self.resource_map = {}
    
    def scan_environment(self, environment: str = 'prod'):
        """Run comprehensive AWS assessment"""
        print(f"\n{'='*80}")
        print(f"🔍 CIRA AWS Security Assessment - {environment.upper()} Environment")
        print(f"{'='*80}\n")
        
        # Initialize AWS Assessment
        assessment = AWSAssessment(region=self.region, environment=environment)
        
        # Run all assessments
        print("📋 ASSESSMENT MODULES:\n")
        
        print("1️⃣  IAM Assessment")
        iam_findings = assessment.assess_iam()
        iam_pass = len([f for f in iam_findings if f.status == 'PASS'])
        iam_fail = len([f for f in iam_findings if f.status == 'FAIL'])
        print(f"   ✅ {iam_pass} PASS | ❌ {iam_fail} FAIL\n")
        
        print("2️⃣  Network Assessment")
        network_findings = assessment.assess_network()
        net_pass = len([f for f in network_findings if f.status == 'PASS'])
        net_fail = len([f for f in network_findings if f.status == 'FAIL'])
        print(f"   ✅ {net_pass} PASS | ❌ {net_fail} FAIL\n")
        
        print("3️⃣  Storage Assessment")
        storage_findings = assessment.assess_storage()
        stor_pass = len([f for f in storage_findings if f.status == 'PASS'])
        stor_fail = len([f for f in storage_findings if f.status == 'FAIL'])
        print(f"   ✅ {stor_pass} PASS | ❌ {stor_fail} FAIL\n")
        
        print("4️⃣  Compliance Assessment")
        compliance_findings = assessment.assess_compliance()
        comp_pass = len([f for f in compliance_findings if f.status == 'PASS'])
        comp_fail = len([f for f in compliance_findings if f.status == 'FAIL'])
        print(f"   ✅ {comp_pass} PASS | ❌ {comp_fail} FAIL\n")
        
        print("5️⃣  Logging Assessment")
        logging_findings = assessment.assess_logging()
        log_pass = len([f for f in logging_findings if f.status == 'PASS'])
        log_fail = len([f for f in logging_findings if f.status == 'FAIL'])
        print(f"   ✅ {log_pass} PASS | ❌ {log_fail} FAIL\n")
        
        print("6️⃣  Resource Mapping (Cloud-Mapper style)")
        resources = assessment.assess_resources()
        print(f"   📊 Mapped {len(resources)} resource types\n")
        
        # Combine all findings
        self.all_findings.extend(iam_findings)
        self.all_findings.extend(network_findings)
        self.all_findings.extend(storage_findings)
        self.all_findings.extend(compliance_findings)
        self.all_findings.extend(logging_findings)
        
        self.resource_map = resources
        
        # Generate report
        return self._generate_report(environment)
    
    def _generate_report(self, environment: str):
        """Generate comprehensive report"""
        critical = [f for f in self.all_findings if f.severity == 'CRITICAL']
        high = [f for f in self.all_findings if f.severity == 'HIGH']
        medium = [f for f in self.all_findings if f.severity == 'MEDIUM']
        low = [f for f in self.all_findings if f.severity == 'LOW']
        passed = [f for f in self.all_findings if f.status == 'PASS']
        failed = [f for f in self.all_findings if f.status == 'FAIL']
        
        # Print summary
        print(f"\n{'='*80}")
        print(f"📊 ASSESSMENT SUMMARY - {environment.upper()}")
        print(f"{'='*80}\n")
        
        print(f"Total Checks:   {len(self.all_findings)}")
        print(f"Passed:         {len(passed)} ✅")
        print(f"Failed:         {len(failed)} ❌")
        
        if len(self.all_findings) > 0:
            pass_rate = (len(passed) / len(self.all_findings) * 100)
            print(f"Pass Rate:      {pass_rate:.1f}%\n")
        else:
            print(f"Pass Rate:      0%\n")
        
        print(f"🔴 Critical:    {len(critical)}")
        print(f"🟠 High:        {len(high)}")
        print(f"🟡 Medium:      {len(medium)}")
        print(f"🔵 Low:         {len(low)}\n")
        
        if failed:
            threat_scores = [f.threat_score for f in failed if f.threat_score > 0]
            if threat_scores:
                avg_threat = sum(threat_scores) / len(threat_scores)
                max_threat = max(threat_scores)
                print(f"Threat Scores (avg): {avg_threat:.0f}/100")
                print(f"Threat Scores (max): {max_threat}/100\n")
        
        # Create report object
        report = {
            'timestamp': datetime.now(datetime.timezone.utc).isoformat(),
            'environment': environment,
            'region': self.region,
            'summary': {
                'total_checks': len(self.all_findings),
                'passed': len(passed),
                'failed': len(failed),
                'pass_rate': f"{(len(passed) / len(self.all_findings) * 100):.1f}%" if len(self.all_findings) > 0 else "0%",
                'severity': {
                    'critical': len(critical),
                    'high': len(high),
                    'medium': len(medium),
                    'low': len(low)
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
                    'timestamp': f.timestamp
                }
                for f in self.all_findings
            ],
            'resources': self.resource_map
        }
        
        # Save report
        filename = f"cira_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"💾 Report saved: {filename}\n")
        
        return report

if __name__ == "__main__":
    scanner = AWSCSPMScanner()
    
    # Scan both environments
    print("\n" + "🧪 " * 40)
    print("TESTING ENVIRONMENT")
    print("🧪 " * 40)
    testing_report = scanner.scan_environment('testing')
    
    # Reset for prod scan
    scanner.all_findings = []
    scanner.resource_map = {}
    
    print("\n" + "🚀 " * 40)
    print("PRODUCTION ENVIRONMENT")
    print("🚀 " * 40)
    prod_report = scanner.scan_environment('prod')
    
    print(f"\n{'='*80}")
    print(f"📋 FULL ASSESSMENT COMPLETE")
    print(f"{'='*80}")
    print(f"\nTesting:     {testing_report['summary']['failed']} failures | {testing_report['summary']['passed']} passed")
    print(f"Production:  {prod_report['summary']['failed']} failures | {prod_report['summary']['passed']} passed")
    print(f"\n✅ Assessment complete!\n")