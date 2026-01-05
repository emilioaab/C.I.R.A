"""
Initialize PostgreSQL Database
Creates all tables for C.I.R.A
"""

from backend.api.models import Base
from sqlalchemy import create_engine
import os
from dotenv import load_dotenv

load_dotenv()

print("=" * 60)
print("Database Initialization")
print("=" * 60)

def get_db_url():
    """Get database URL from environment variables"""
    return f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"

try:
    print("\nConnecting to PostgreSQL...")
    engine = create_engine(get_db_url())
    
    print("Creating all tables...")
    Base.metadata.create_all(engine)
    
    print("\nOK: Tables created successfully!")
    print("\nTables created:")
    print("   - assessments")
    print("   - log_events")
    print("   - findings")
    print("   - resources")
    print("   - compliance_status")
    
    print("\nNext steps:")
    print("   1. Run: python backend/scripts/create_test_data.py")
    print("   2. Run: python api.py")
    print("   3. Visit: http://localhost:5000")
    
except Exception as e:
    print(f"\nFAIL: {e}")
    print("\nTroubleshooting:")
    print("   - Check PostgreSQL is running")
    print("   - Verify .env has correct DB credentials")
    print("   - Ensure database exists")
    print("\nCreate database with:")
    print("   createdb cira_db")
    print("\nCreate user with:")
    print("   createuser -d -l -P cira_user")