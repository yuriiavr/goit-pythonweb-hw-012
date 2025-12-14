import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi import HTTPException, status
from models import User, Role
from auth import auth_service, role_required
from datetime import timedelta
from jose import JWTError, jwt
from auth import auth_service
from models import Role, User
import json
from sqlalchemy.orm import Session

def test_password_hashing():
    password = "short_secure_password_123"
    hashed = auth_service.get_password_hash(password)
    assert auth_service.verify_password(password, hashed)
    assert not auth_service.verify_password("WrongPassword", hashed)

def test_create_access_token():
    data = {"sub": "test@example.com"}
    token = auth_service.create_access_token(data)
    assert isinstance(token, str)
    payload = jwt.decode(token, auth_service.SECRET_KEY, algorithms=[auth_service.ALGORITHM])
    assert payload["sub"] == "test@example.com"
    assert "exp" in payload
    assert payload["scope"] == "access_token"

def test_create_access_token_with_expiry():
    data = {"sub": "test@example.com"}
    token = auth_service.create_access_token(data, expires_delta=-300.0) 

    with pytest.raises(JWTError):
        jwt.decode(token, auth_service.SECRET_KEY, algorithms=[auth_service.ALGORITHM])

def test_decode_token_invalid():
    invalid_token = "invalid.token.string"
    with pytest.raises(Exception):
        auth_service.decode_refresh_token(invalid_token)

@pytest.mark.asyncio
@patch('auth.crud')
@patch('auth.auth_service.get_redis_client')
async def test_get_current_user_unconfirmed(mock_get_redis, mock_crud, session):
    test_email = "unconfirmed@example.com"
    token = auth_service.create_access_token({"sub": test_email}) 
    
    mock_redis = AsyncMock()
    mock_get_redis.return_value = mock_redis
    mock_redis.get.return_value = None
    
    mock_user = User(email=test_email, confirmed=False, role=Role.user)
    mock_crud.get_user_by_email.return_value = mock_user

    with pytest.raises(HTTPException) as excinfo:
        await auth_service.get_current_user(token, session)
    
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Email not confirmed" in excinfo.value.detail

@pytest.mark.asyncio
@patch('auth.crud')
@patch('auth.auth_service.get_redis_client')
async def test_get_current_user_not_found(mock_get_redis, mock_crud, session):
    test_email = "nonexistent@example.com"
    token = auth_service.create_access_token({"sub": test_email})
    
    mock_redis = AsyncMock()
    mock_get_redis.return_value = mock_redis
    mock_redis.get.return_value = None 
    mock_crud.get_user_by_email.return_value = None 

    with pytest.raises(HTTPException) as excinfo:
        await auth_service.get_current_user(token, session)
    
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Could not validate credentials" in excinfo.value.detail

def test_role_required_permission_denied(test_user):
    test_user.role = Role.user 
    required_role = Role.admin
    
    with pytest.raises(HTTPException) as excinfo:
        role_required(required_role)(current_user=test_user)
        
    assert excinfo.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Permission denied" in excinfo.value.detail
    
def test_role_required_failure():
    mock_user = MagicMock(spec=User, role=Role.user, confirmed=True)
    
    admin_required_func = role_required(Role.admin)
    
    with pytest.raises(HTTPException) as excinfo:
        admin_required_func(current_user=mock_user) 
    
    assert excinfo.value.status_code == status.HTTP_403_FORBIDDEN
    assert excinfo.value.detail == "Permission denied. Required role: admin"
    
@pytest.mark.asyncio
@patch('auth.crud')
@patch('auth.auth_service.get_redis_client')
async def test_get_current_user_not_found(mock_get_redis, mock_crud, session):
    test_email = "nonexistent@example.com"
    token = auth_service.create_access_token({"sub": test_email})
    
    mock_redis = AsyncMock()
    mock_get_redis.return_value = mock_redis
    mock_redis.get.return_value = None 
    
    mock_crud.get_user_by_email.return_value = None 

    with pytest.raises(HTTPException) as excinfo:
        await auth_service.get_current_user(token, session)
    
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Could not validate credentials" in excinfo.value.detail
    
@pytest.mark.asyncio
@patch('auth.crud')
@patch('auth.auth_service.get_redis_client')
async def test_get_current_user_cache_miss_unconfirmed(mock_get_redis, mock_crud, session):
    test_email = "unconfirmed_cache_miss@example.com"
    token = auth_service.create_access_token({"sub": test_email})
    
    mock_redis = AsyncMock()
    mock_get_redis.return_value = mock_redis
    mock_redis.get.return_value = None 
    
    mock_user = MagicMock(spec=User, email=test_email, confirmed=False, role=Role.user)
    mock_crud.get_user_by_email.return_value = mock_user

    with pytest.raises(HTTPException) as excinfo:
        await auth_service.get_current_user(token, session)
    
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Email not confirmed" in excinfo.value.detail
    mock_redis.get.assert_called_once()
    mock_crud.get_user_by_email.assert_called_once()
    
@pytest.mark.asyncio
@patch('auth.auth_service.get_redis_client')
async def test_get_current_user_cache_hit_unconfirmed(mock_get_redis, session: Session):
    test_email = "unconfirmed_cached@example.com"
    token = auth_service.create_access_token({"sub": test_email})
    
    mock_redis = AsyncMock()
    mock_get_redis.return_value = mock_redis
    
    cached_user_data = {
        "email": test_email, 
        "confirmed": False, 
        "role": Role.user.value 
    }
    mock_redis.get.return_value = json.dumps(cached_user_data).encode('utf-8')

    with pytest.raises(HTTPException) as excinfo:
        await auth_service.get_current_user(token, session)
    
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert excinfo.value.detail == "Could not validate credentials"
    mock_redis.get.assert_called_once()