import os
import pytest
from unittest.mock import AsyncMock, patch
from pydantic import EmailStr
from email_service import send_email, send_reset_email, get_bool_env

@pytest.mark.asyncio
@patch('email_service.FastMail')
@patch('email_service.auth_service')
async def test_send_email_success(mock_auth_service, mock_fastmail):
    mock_auth_service.create_email_token.return_value = "mock_token"
    mock_fm_instance = mock_fastmail.return_value
    mock_fm_instance.send_message = AsyncMock()

    email = "test@example.com" 
    
    await send_email(email, "testuser", "http://localhost")

    mock_auth_service.create_email_token.assert_called_once_with({"sub": email})
    mock_fm_instance.send_message.assert_called_once()

@pytest.mark.asyncio
@patch('email_service.FastMail')
@patch('email_service.auth_service')
async def test_send_email_failure(mock_auth_service, mock_fastmail, capsys):
    mock_fm_instance = mock_fastmail.return_value
    mock_fm_instance.send_message = AsyncMock(side_effect=Exception("Test Email Error"))

    await send_email("test@example.com", "testuser", "http://localhost") 

    captured = capsys.readouterr()
    assert "Error sending email: Exception raised Test Email Error" in captured.out
    
@pytest.mark.asyncio
@patch('email_service.FastMail')
@patch('email_service.auth_service')
async def test_send_reset_email_success(mock_auth_service, mock_fastmail):
    mock_auth_service.create_reset_token.return_value = "mock_reset_token"
    mock_fm_instance = mock_fastmail.return_value
    mock_fm_instance.send_message = AsyncMock()

    email = "reset@example.com" 
    
    await send_reset_email(email, "resetuser", "http://localhost")

    mock_auth_service.create_reset_token.assert_called_once_with({"sub": email})
    mock_fm_instance.send_message.assert_called_once()
    
@patch.dict(os.environ, {'TEST_VAR': 'True'})
def test_get_bool_env_true():
    assert get_bool_env('TEST_VAR') == True

@patch.dict(os.environ, {'TEST_VAR': 'False'})
def test_get_bool_env_false():
    assert get_bool_env('TEST_VAR') == False

@patch.dict(os.environ, {}, clear=True)
def test_get_bool_env_default():
    assert get_bool_env('NON_EXISTENT_VAR', default=True) == True
    assert get_bool_env('NON_EXISTENT_VAR', default=False) == False