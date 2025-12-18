import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from models import User
from auth import auth_service
import json
from main import auth_service
from datetime import date, datetime, timedelta, timezone
from jose import JWTError

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
        data={"username": "test@example.com", "password": "shortpassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

@patch('main.send_email')
def test_request_email_verification_success(mock_send_email, client: TestClient, test_user):
    test_user.confirmed = False
    
    response = client.post(
        "/api/auth/request_email",
        json={"email": test_user.email}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Email confirmation sent successfully"
    mock_send_email.assert_called_once()
    
def test_request_email_verification_already_confirmed(client: TestClient, test_user):
    test_user.confirmed = True
    
    response = client.post(
        "/api/auth/request_email",
        json={"email": test_user.email}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Your email is already confirmed"

def test_get_contacts_success(client: TestClient, test_user): 
    response = client.get(
        "/contacts",
    )
    assert response.status_code == 200
    
@patch('main.crud.get_contact')
def test_get_contact_by_id_success(mock_get_contact, client: TestClient, test_user, session):
    
    mock_contact = MagicMock(
        id=1,
        first_name="Test",
        last_name="Contact",
        email="tc@test.com",
        phone_number="1234567890",
        birthday=date(2000, 1, 1), 
        additional_data=None 
    )
    mock_get_contact.return_value = mock_contact
    
    response = client.get(
        "/contacts/1",
    )
    assert response.status_code == 200
    assert response.json()["first_name"] == "Test"
    assert response.json()["email"] == "tc@test.com"

@patch('main.crud.get_contact')
def test_get_contact_by_id_not_found(mock_get_contact, client: TestClient, test_user, session):
    mock_get_contact.return_value = None
    
    response = client.get(
        "/contacts/999",
    )
    assert response.status_code == 404

@patch('main.upload_avatar')
@patch('auth.auth_service.get_redis_client', new_callable=AsyncMock)
def test_update_avatar_success(mock_redis, mock_upload, admin_client: TestClient):
    mock_upload.return_value = "http://res.cloudinary.com/demo.png"

    mock_redis_instance = MagicMock()
    mock_redis.return_value = mock_redis_instance
    mock_redis_instance.delete = AsyncMock()

    response = admin_client.patch(
        "/users/avatar", 
        files={"file": ("avatar.png", b"fake_content", "image/png")}
    )
    
    assert response.status_code == 200
    assert response.json()["avatar"] == "http://res.cloudinary.com/demo.png"
    
def test_update_avatar_forbidden_for_user(client: TestClient):
    response = client.patch(
        "/users/avatar",
        files={"file": ("test.png", b"fake-content", "image/png")}
    )
    assert response.status_code == 403

@patch('main.send_reset_email')
def test_request_reset_password_success(mock_send_reset_email, client: TestClient, test_user):
    response = client.post(
        "/api/auth/request_reset_password",
        json={"email": test_user.email}
    )
    assert response.status_code == 200
    mock_send_reset_email.assert_called_once()
    
def test_reset_password_success(client, session, test_user):
    token = auth_service.create_reset_token({"sub": test_user.email})
    response = client.post(
        f"/api/auth/reset_password?token={token}",
        json={"new_password": "newpassword123"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Password updated successfully. You can now login with your new password."

def test_reset_password_invalid_token(client):
    response = client.post(
        "/api/auth/reset_password?token=wrong_token",
        json={"new_password": "somepassword"}
    )
    assert response.status_code == 401
    assert "Invalid or expired token" in response.json()["detail"]
    
    
def test_login_failure(client: TestClient, test_user):
    response = client.post(
        "/api/auth/login",
        data={"username": test_user.email, "password": "wrongpassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]

def test_get_contacts_unconfirmed_user(client: TestClient, test_user: User, session: Session):
    test_user.confirmed = False
    session.add(test_user)
    session.commit()
    
    response = client.get("/contacts")
    
    assert response.status_code == 403
    assert response.json()["detail"] == "Email not confirmed"
    
    test_user.confirmed = True
    session.add(test_user)
    session.commit()
    
@patch('main.crud.update_contact')
def test_update_contact_not_found(mock_update_contact, client: TestClient, test_user):
    mock_update_contact.return_value = None
    
    response = client.put(
        "/contacts/999",
        json={"first_name": "NonExistent"}
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Contact not found or does not belong to user"

@patch('main.crud.get_contact')
def test_get_contact_not_found(mock_get_contact, client: TestClient):
    mock_get_contact.return_value = None
    
    response = client.get("/contacts/999")
    
    assert response.status_code == 404
    assert response.json()["detail"] == "Contact not found or does not belong to user"
    
@patch('main.crud.get_user_by_email')
@patch('main.auth_service.decode_reset_token')
def test_reset_password_user_not_found(mock_decode, mock_get_user, client: TestClient):
    mock_decode.return_value = "nonexistent@example.com"
    mock_get_user.return_value = None
    
    token = "some_valid_token"
    response = client.post(
        f"/api/auth/reset_password?token={token}",
        json={"new_password": "newpassword123"}
    )
    
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"
    
@patch('main.crud.get_contacts')
def test_get_contacts_none_found(mock_get_contacts, client: TestClient):
    mock_get_contacts.return_value = []
    
    response = client.get("/contacts?skip=0&limit=10")
    
    assert response.status_code == 200
    assert response.json() == []
    mock_get_contacts.assert_called_once()
    
@patch('main.auth_service.verify_password')
@patch('main.crud.get_user_by_email')
def test_login_unconfirmed_user(mock_get_user_by_email, mock_verify_password, client: TestClient):
    unconfirmed_user_mock = MagicMock(
        email="unconfirmed_login@test.com", 
        password="hashed_password", 
        confirmed=False
    )
    mock_get_user_by_email.return_value = unconfirmed_user_mock
    mock_verify_password.return_value = True

    response = client.post(
        "/api/auth/login",
        data={"username": "unconfirmed_login@test.com", "password": "testpassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    assert response.status_code == 401
    assert response.json()["detail"] == "Email not confirmed"
    
@patch('main.crud.delete_contact')
def test_delete_contact_not_found(mock_delete_contact, client: TestClient):
    mock_delete_contact.return_value = None
    
    response = client.delete("/contacts/999")
    
    assert response.status_code == 404
    assert response.json()["detail"] == "Contact not found or does not belong to user"
    
def test_refresh_token_expired(client: TestClient, test_user: User):
    expired_token = auth_service.create_refresh_token(
        data={"sub": test_user.email},
        expires_delta=timedelta(minutes=-5).total_seconds() 
    )

    response = client.get(
        "/api/auth/refresh_token",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"
    
def test_reset_password_flow(client, session, test_user):
    token = auth_service.create_reset_token({"sub": test_user.email})
    
    response = client.post(
        f"/api/auth/reset_password?token={token}",
        json={"new_password": "NewVerySecurePassword123"}
    )
    
    assert response.status_code == 200
    assert response.json()["message"] == "Password updated successfully. You can now login with your new password."
    
def test_update_avatar_forbidden_for_user(client):
    response = client.patch(
        "/users/avatar",
        files={"file": ("test.png", b"fake-content", "image/png")}
    )
    assert response.status_code == 403
    
@patch('main.upload_avatar')
@patch('auth.auth_service.get_redis_client', new_callable=AsyncMock)
def test_update_avatar_success_for_admin(mock_redis, mock_upload, admin_client: TestClient):
    mock_upload.return_value = "http://res.cloudinary.com/admin.png"
    
    mock_redis_instance = MagicMock()
    mock_redis.return_value = mock_redis_instance
    mock_redis_instance.delete = AsyncMock()

    response = admin_client.patch(
        "/users/avatar",
        files={"file": ("avatar.png", b"content", "image/png")}
    )
    assert response.status_code == 200
    assert response.json()["avatar"] == "http://res.cloudinary.com/admin.png"