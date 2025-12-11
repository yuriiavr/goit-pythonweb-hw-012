import pytest
from datetime import timedelta
from jose import JWTError, jwt
from auth import auth_service

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

def test_create_email_token():
    email = "test@example.com"
    token = auth_service.create_email_token({"sub": email})
    assert isinstance(token, str)

    email_result = auth_service.decode_email_token(token)
    assert email_result == email