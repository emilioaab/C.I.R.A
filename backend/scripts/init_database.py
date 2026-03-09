"""
C.I.R.A Database Initializer
Creates all tables based on current models.
Safe to re-run — uses create_all (does not drop existing tables).
Use --reset flag to drop and recreate all tables (DELETES ALL DATA).
"""

import os
import sys
from dotenv import load_dotenv
from sqlalchemy import create_engine, inspect, text

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from backend.api.models import Base, Assessment, Finding, Resource, LogEvent, ComplianceStatus

DB_URL = (
    f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
    f"@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
)

TABLES = {
    'assessments': Assessment,
    'findings': Finding,
    'resources': Resource,
    'log_events': LogEvent,
    'compliance_status': ComplianceStatus,
}

reset_mode = '--reset' in sys.argv

print("\n" + "=" * 70)
print("C.I.R.A Database Initializer")
if reset_mode:
    print("MODE: RESET — all existing data will be deleted!")
print("=" * 70)

try:
    engine = create_engine(DB_URL)

    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    print("\nOK: Connected to PostgreSQL")

    if reset_mode:
        confirm = input("\nThis will DELETE ALL DATA. Type 'yes' to confirm: ").strip()
        if confirm != 'yes':
            print("Cancelled.")
            sys.exit(0)
        Base.metadata.drop_all(engine)
        print("OK: All tables dropped")

    Base.metadata.create_all(engine)

    # Verify tables exist and show row counts
    inspector = inspect(engine)
    existing = inspector.get_table_names()

    print("\nTables:")
    with engine.connect() as conn:
        for table_name in TABLES:
            if table_name in existing:
                count = conn.execute(text(f"SELECT COUNT(*) FROM {table_name}")).scalar()
                print(f"   {table_name:<20} {count:>6} rows")
            else:
                print(f"   {table_name:<20} MISSING (error)")

    print("\n" + "=" * 70)
    print("OK: Database ready.")
    print("=" * 70)
    print("\nNext steps:")
    print("  python aws_cspm_scanner.py              # Run security assessment")
    print("  python backend/connectors/aws/logs.py   # Collect CloudTrail logs")
    print("  python api.py                           # Start API + dashboard")
    print()

except Exception as e:
    print(f"\nFAIL: {e}")
    print("\nTroubleshooting:")
    print("  - Is PostgreSQL running?")
    print("  - Check DB_USER / DB_PASSWORD / DB_HOST in .env")
    sys.exit(1)
