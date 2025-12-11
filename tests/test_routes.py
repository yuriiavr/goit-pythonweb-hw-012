import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from models import User
from auth import auth_service
import json

@pytest.mark.asyncio
@patch('main.send_email')
def test_signup_success(mock_send_email, client: TestClient):
    response = client.post(
        "/api/auth/signup",
        json={"username": "newuser", "email": "new@example.com", "password": "newpassword"}
    )
    assert response.status_code == 201
    assert "id" in response.json()
    assert response.json()["email"] == "new@example.com"
    mock_send_email.assert_called_once()

@patch('main.send_email')
def test_signup_conflict(mock_send_email, client: TestClient, test_user):
    response = client.post(
        "/api/auth/signup",
        json={"username": "testuser2", "email": "test@example.com", "password": "newpassword"}
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Account already exists"

def test_login_success(client: TestClient, test_user):
    response = client.post(
        "/api/auth/login",
        data={"username": "test@example.com", "password": "shortpass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_login_wrong_password(client: TestClient, test_user):
    response = client.post(
        "/api/auth/login",
        data={"username": "test@example.com", "password": "wrongpassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

@patch('auth.Auth.get_redis_client', new_callable=AsyncMock)
def test_read_users_me_success(mock_get_redis_client, client: TestClient, test_user, auth_token):
    user_data = {
        "id": test_user.id,
        "username": test_user.username,
        "email": test_user.email,
        "role": test_user.role.value, 
        "confirmed": True,
        "created_at": "2023-01-01T00:00:00",
        "avatar": None 
    }
    cached_user_json = json.dumps(user_data)

    mock_redis_instance = mock_get_redis_client.return_value
    mock_redis_instance.get = AsyncMock(return_value=cached_user_json.encode('utf-8'))
    mock_redis_instance.set = AsyncMock(return_value=None) 

    response = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert response.status_code == 200
    assert response.json()["email"] == test_user.email
    assert response.json()["role"] == "admin"
    assert response.json()["confirmed"] == True

@patch('main.upload_avatar', return_value="http://new.avatar.url")
@patch('auth.Auth.get_redis_client', new_callable=AsyncMock)
def test_update_avatar_admin_success(mock_get_redis_client, mock_upload_avatar, client: TestClient, test_user, auth_token):
    mock_redis_instance = mock_get_redis_client.return_value
    
    mock_redis_instance.get = AsyncMock(return_value=None) 
    mock_redis_instance.set = AsyncMock(return_value=None) 
    mock_redis_instance.delete = AsyncMock(return_value=None)
    
    file_content = b"fake image data"
    response = client.patch(
        "/users/avatar",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("avatar.jpg", file_content, "image/jpeg")}
    )
    assert response.status_code == 200
    assert response.json()["avatar"] == "http://new.avatar.url"
    mock_upload_avatar.assert_called_once()