import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Database connection
DB_URL = f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"

# Import models
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from backend.api.models import Base

# Create engine
engine = create_engine(DB_URL)

# Create tables
try:
    Base.metadata.create_all(engine)
    print("\n" + "="*80)
    print("OK: Database tables created successfully!")
    print("="*80)
    print("\nTables created:")
    print("   - assessments")
    print("   - findings")
    print("   - resources")
    print("   - log_events")
    print("   - compliance_status")
    print("\n" + "="*80 + "\n")
except Exception as e:
    print(f"FAIL: Error creating tables: {e}")
    sys.exit(1)