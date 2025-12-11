import os
from pathlib import Path
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from pydantic import EmailStr
from auth import auth_service
from typing import Dict

def get_bool_env(key, default=False):
    val = os.environ.get(key)
    if val is None:
        return default
    return val.lower() in ('true', '1', 't')

conf = ConnectionConfig(
    MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
    MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
    MAIL_FROM=os.environ.get("MAIL_FROM"),
    MAIL_PORT=int(os.environ.get("MAIL_PORT", 0)),
    MAIL_SERVER=os.environ.get("MAIL_SERVER"),
    MAIL_FROM_NAME="Contact App",
    MAIL_STARTTLS=get_bool_env("MAIL_STARTTLS"),
    MAIL_SSL_TLS=get_bool_env("MAIL_SSL_TLS"),
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    TEMPLATE_FOLDER=Path(__file__).parent / 'templates'
)

async def send_email(email: EmailStr, username: str, host: str):
    try:
        token_verification = auth_service.create_email_token({"sub": email})
        
        message = MessageSchema(
            subject="Confirm your email",
            recipients=[email],
            template_body={"host": host, "username": username, "token": token_verification},
            subtype=MessageType.html
        )

        fm = FastMail(conf)
        await fm.send_message(message, template_name="email_confirmation.html")
    except Exception as e:
        print(f"Error sending email: Exception raised {e}, check your credentials or email service configuration")

async def send_reset_email(email: EmailStr, username: str, host: str):
    try:
        token_reset = auth_service.create_reset_token({"sub": email})
        
        message = MessageSchema(
            subject="Reset your password",
            recipients=[email],
            template_body={"host": host, "username": username, "token": token_reset},
            subtype=MessageType.html
        )

        fm = FastMail(conf)
        await fm.send_message(message, template_name="reset_password.html")
    except Exception as e:
        print(f"Error sending reset email: Exception raised {e}")