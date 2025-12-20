"""
Модуль моделей бази даних SQLAlchemy.

Визначає структуру таблиць для користувачів та їхніх контактів, а також 
зв'язки між ними та перерахування ролей.
"""
from sqlalchemy import Column, Integer, String, Date, DateTime, Boolean, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base
import enum

class Role(enum.Enum):
    """
    Перерахування ролей користувачів у системі.
    
    Використовується для контролю доступу (RBAC).
    """
    admin = "admin"
    user = "user"

class Contact(Base):
    """
    SQLAlchemy модель для таблиці 'contacts'.

    Зберігає детальну інформацію про контакти, які належать конкретному користувачу.
    """
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, index=True)
    last_name = Column(String, index=True)
    email = Column(String)
    phone_number = Column(String)
    birthday = Column(Date)
    additional_data = Column(String, nullable=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    #: Зв'язок з моделлю User
    user = relationship("User", backref="contacts")

class User(Base):
    """
    SQLAlchemy модель для таблиці 'users'.

    Містить дані облікових записів користувачів, включаючи хешовані паролі, 
    статус підтвердження email та посилання на аватар.
    """
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    created_at = Column(DateTime, default=datetime.now)
    avatar = Column(String, nullable=True)
    refresh_token = Column(String, nullable=True)
    confirmed = Column(Boolean, default=False)
    role = Column(Enum(Role), default=Role.user)