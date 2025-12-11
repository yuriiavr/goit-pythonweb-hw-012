from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from models import Role
from datetime import date, datetime

class ContactBase(BaseModel):
    first_name: str = Field(min_length=2, max_length=50)
    last_name: str = Field(min_length=2, max_length=50)
    email: EmailStr
    phone_number: str = Field(min_length=10, max_length=20)
    birthday: date
    additional_data: Optional[str] = None

class ContactCreate(ContactBase):
    pass

class ContactUpdate(BaseModel):
    first_name: Optional[str] = Field(None, min_length=2, max_length=50)
    last_name: Optional[str] = Field(None, min_length=2, max_length=50)
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = Field(None, min_length=10, max_length=20)
    birthday: Optional[date] = None
    additional_data: Optional[str] = None
    
class ContactResponse(ContactBase):
    id: int
    
    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str = Field(min_length=5, max_length=50)
    email: EmailStr
    password: str = Field(min_length=6, max_length=255)

class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    avatar: Optional[str]
    confirmed: bool
    role: Role
    created_at: datetime

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RequestEmail(BaseModel):
    email: EmailStr
    
class RequestResetPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    new_password: str = Field(min_length=6, max_length=255)