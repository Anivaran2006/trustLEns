"""
Database session management for TrustLens AI.
Uses SQLAlchemy engine configured from settings.DATABASE_URL.
Compatible with SQLite (local development / low-cost tier) and PostgreSQL.
"""

from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

# Normalize postgres:// to postgresql:// for SQLAlchemy 2.0 compatibility
db_url = settings.DATABASE_URL
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

connect_args = {}
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    db_url,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    """Initializes tables in database and applies non-destructive schema migrations."""
    Base.metadata.create_all(bind=engine)
    
    # Safe non-destructive column check for SQLite
    try:
        with engine.connect() as conn:
            if settings.DATABASE_URL.startswith("sqlite"):
                result = conn.execute(text("PRAGMA table_info(scan_records);"))
                columns = [row[1] for row in result.fetchall()]
                if "user_id" not in columns:
                    conn.execute(text("ALTER TABLE scan_records ADD COLUMN user_id VARCHAR(36) REFERENCES users(id);"))
                    conn.commit()
    except Exception as e:
        import logging
        logging.getLogger("trustlens").warning(f"Database migration note: {e}")

def get_db():
    """FastAPI dependency for yielding database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

