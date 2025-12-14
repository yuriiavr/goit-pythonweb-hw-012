from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from contextlib import contextmanager

DATABASE_HOST = os.getenv("DB_HOST", "localhost")
DATABASE_PORT = os.getenv("DB_PORT", "5432")
DATABASE_NAME = os.getenv("DB_NAME", "postgres")
DATABASE_USER = os.getenv("DB_USER", "postgres")
DATABASE_PASS = os.getenv("DB_PASS", "password")

SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    f"postgresql://{DATABASE_USER}:{DATABASE_PASS}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}"
)

engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()