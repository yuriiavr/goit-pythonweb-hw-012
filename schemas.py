"""
Модуль схем Pydantic.

Забезпечує валідацію вхідних даних (DTO) та форматування відповідей API 
для сутностей Користувача та Контакту.
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from models import Role
from datetime import date, datetime

class ContactBase(BaseModel):
    """Базова схема контакту з основними атрибутами."""
    first_name: str = Field(min_length=2, max_length=50)
    last_name: str = Field(min_length=2, max_length=50)
    email: EmailStr
    phone_number: str = Field(min_length=10, max_length=20)
    birthday: date
    additional_data: Optional[str] = None

class ContactCreate(ContactBase):
    """Схема для створення нового контакту. Спадкує всі поля від ContactBase."""
    pass

class ContactUpdate(BaseModel):
    """
    Схема для оновлення контакту. 
    Всі поля є необов'язковими для забезпечення можливості часткового оновлення.
    """
    first_name: Optional[str] = Field(None, min_length=2, max_length=50)
    last_name: Optional[str] = Field(None, min_length=2, max_length=50)
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = Field(None, min_length=10, max_length=20)
    birthday: Optional[date] = None
    additional_data: Optional[str] = None
    
class ContactResponse(ContactBase):
    """
    Схема відповіді для контакту. 
    Включає ID та налаштована на роботу з об'єктами ORM.
    """
    id: int
    
    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    """Схема для реєстрації нового користувача."""
    username: str = Field(min_length=5, max_length=50)
    email: EmailStr
    password: str = Field(min_length=6, max_length=255)

class UserResponse(BaseModel):
    """
    Схема для повернення інформації про користувача.
    Не містить пароля або чутливих токенів.
    """
    id: int
    username: str
    email: EmailStr
    avatar: Optional[str]
    confirmed: bool
    role: Role
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    """Схема відповіді з access та refresh токенами."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RequestEmail(BaseModel):
    """Схема для запитів, що потребують лише email (напр. підтвердження або скидання пароля)."""
    email: EmailStr

class ResetPassword(BaseModel):
    """Схема для встановлення нового пароля."""
    new_password: str = Field(min_length=6, max_length=255)

class UserRoleUpdate(BaseModel):
    """Схема для зміни ролі користувача адміністратором."""
    role: Role