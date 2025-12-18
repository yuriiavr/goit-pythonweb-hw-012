import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base
from main import app
from fastapi.testclient import TestClient
from database import get_db
from models import User, Role
from auth import auth_service

@pytest.fixture(scope="session")
def test_db_url():
    return "sqlite:///./test.db"

@pytest.fixture(scope="session")
def engine(test_db_url):
    return create_engine(test_db_url, connect_args={"check_same_thread": False})

@pytest.fixture(scope="session")
def TestingSessionLocal(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session")
def setup_db(engine):
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def session(engine, setup_db, TestingSessionLocal):
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture(scope="function")
def client(session, test_user):
    def override_get_db():
        yield session

    async def override_get_current_user():
        return test_user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[auth_service.get_current_user] = override_get_current_user

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()

@pytest.fixture
def test_user(session):
    user = User(
        id=1,
        username="testuser",
        email="test@example.com",
        password=auth_service.get_password_hash("shortpassword"),
        confirmed=True,
    )
    session.add(user)
    session.commit()
    return user

@pytest.fixture
def admin_user(session):
    user = session.query(User).filter_by(email="admin@example.com").first()
    if not user:
        user = User(
            username="admin_boss",
            email="admin@example.com",
            password=auth_service.get_password_hash("adminpassword"),
            confirmed=True,
            role=Role.admin
        )
        session.add(user)
        session.commit()
        session.refresh(user)
    return user

@pytest.fixture
def admin_client(session, admin_user):
    def override_get_db():
        yield session

    async def override_get_current_user():
        return admin_user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[auth_service.get_current_user] = override_get_current_user

    with TestClient(app) as c:
        yield c
    
    app.dependency_overrides.clear()