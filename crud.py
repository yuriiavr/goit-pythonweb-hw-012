"""
Модуль для виконання CRUD операцій (Create, Read, Update, Delete) з базою даних.
Містить функції для взаємодії з таблицями користувачів (User) та контактів (Contact).
"""
from sqlalchemy.orm import Session
from sqlalchemy import or_, extract, func
from datetime import date, timedelta
from typing import List
from typing import Optional

import models, schemas
from auth import auth_service

def get_user_by_email(db: Session, email: str):
    """
    Знаходить користувача в базі даних за його електронною поштою.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param email: Електронна пошта користувача для пошуку.
    :return: Об'єкт користувача :class:`models.User` або None, якщо не знайдено.
    """
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    """
    Створює нового користувача в системі. Пароль автоматично хешується перед збереженням.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param user: Схема Pydantic з даними для реєстрації нового користувача.
    :return: Створений об'єкт користувача :class:`models.User`.
    """
    hashed_password = auth_service.get_password_hash(user.password)
    db_user = models.User(username=user.username, email=user.email, password=hashed_password, confirmed=False)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_token(db: Session, user: models.User, token: str):
    """
    Оновлює Refresh Token для вказаного користувача.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param user: Об'єкт користувача, якому потрібно оновити токен.
    :param token: Новий Refresh Token (або None для виходу з системи).
    """
    user.refresh_token = token
    db.commit()
    
def update_avatar(db: Session, user: models.User, avatar_url: str) -> models.User:
    """
    Оновлює посилання на аватар користувача.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param user: Об'єкт користувача, чий аватар оновлюється.
    :param avatar_url: Пряме посилання на зображення (наприклад, з Cloudinary).
    :return: Оновлений об'єкт користувача :class:`models.User`.
    """
    user.avatar = avatar_url
    db.commit()
    db.refresh(user)
    return user

def confirm_email(db: Session, email: str):
    """
    Встановлює прапорець підтвердження електронної пошти користувача.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param email: Електронна пошта користувача для підтвердження.
    :return: True, якщо користувача знайдено і статус оновлено, інакше False.
    """
    user = get_user_by_email(db, email)
    if user:
        user.confirmed = True
        db.commit()
        return True
    return False

def confirm_user(db: Session, email: str) -> Optional[models.User]:
    """
    Підтверджує статус користувача та повертає оновлений об'єкт.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param email: Електронна пошта користувача.
    :return: Оновлений об'єкт користувача :class:`models.User` або None.
    """
    user = db.query(models.User).filter(models.User.email == email).first()
    if user:
        user.confirmed = True
        db.commit()
        db.refresh(user)
    return user

def update_password(db: Session, user: models.User, new_password: str):
    """
    Змінює пароль користувача. Новий пароль хешується перед збереженням.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param user: Об'єкт користувача, який змінює пароль.
    :param new_password: Новий пароль у відкритому вигляді.
    :return: Оновлений об'єкт користувача :class:`models.User`.
    """
    user.password = auth_service.get_password_hash(new_password)
    db.commit()
    db.refresh(user)
    return user

def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int):
    """
    Створює новий контакт для конкретного користувача.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param contact: Схема з даними нового контакту.
    :param user_id: Ідентифікатор власника (User ID).
    :return: Створений об'єкт контакту :class:`models.Contact`.
    """
    db_contact = models.Contact(**contact.model_dump(), user_id=user_id) 
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def get_contact(db: Session, contact_id: int, user_id: int):
    """
    Отримує конкретний контакт за ID, перевіряючи належність користувачу.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param contact_id: Унікальний ідентифікатор контакту.
    :param user_id: Ідентифікатор власника контакту.
    :return: Об'єкт контакту :class:`models.Contact` або None.
    """
    return db.query(models.Contact).filter(models.Contact.id == contact_id, models.Contact.user_id == user_id).first()

def get_contacts(db: Session, skip: int = 0, limit: int = 100, user_id: int = None) -> List[models.Contact]:
    """
    Отримує список всіх контактів вказаного користувача з підтримкою пагінації.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param skip: Кількість записів, які слід пропустити (Offset).
    :param limit: Максимальна кількість записів у відповіді (Limit).
    :param user_id: Ідентифікатор власника контактів.
    :return: Список об'єктів :class:`models.Contact`.
    """
    return db.query(models.Contact).filter(models.Contact.user_id == user_id).offset(skip).limit(limit).all()

def update_contact(db: Session, db_contact: models.Contact, contact: schemas.ContactUpdate):
    """
    Оновлює дані існуючого контакту.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param db_contact: Поточний об'єкт контакту з бази даних.
    :param contact: Схема з новими даними для оновлення.
    :return: Оновлений об'єкт контакту :class:`models.Contact`.
    """
    contact_data = contact.model_dump(exclude_unset=True)
    for key, value in contact_data.items():
        setattr(db_contact, key, value)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def delete_contact(db: Session, contact_id: int, user_id: int):
    """
    Видаляє контакт з бази даних.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param contact_id: Ідентифікатор контакту для видалення.
    :param user_id: Ідентифікатор власника контакту.
    :return: Об'єкт видаленого контакту або None, якщо контакт не знайдено.
    """
    db_contact = get_contact(db, contact_id, user_id)
    if db_contact:
        db.delete(db_contact)
        db.commit()
        return db_contact
    return None

def search_contacts(db: Session, query: str, user_id: int) -> List[models.Contact]:
    """
    Шукає контакти за ім'ям, прізвищем або email (регістронезалежно).

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param query: Рядок для пошуку (частина імені або пошти).
    :param user_id: Ідентифікатор власника контактів.
    :return: Список знайдених об'єктів :class:`models.Contact`.
    """
    search = f"%{query}%"
    return (
        db.query(models.Contact)
        .filter(models.Contact.user_id == user_id)
        .filter(
            or_(
                models.Contact.first_name.ilike(search),
                models.Contact.last_name.ilike(search),
                models.Contact.email.ilike(search),
            )
        )
        .all()
    )

def get_upcoming_birthdays(db: Session, user_id: int) -> List[models.Contact]:
    """
    Повертає список контактів, у яких день народження протягом наступних 7 днів (включаючи сьогодні).

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param user_id: Ідентифікатор користувача, чиї контакти перевіряються.
    :return: Список об'єктів :class:`models.Contact` з наближеними днями народження.
    """
    today = date.today()
    
    date_formats = []
    for i in range(8):
        target_date = today + timedelta(days=i)
        date_formats.append(target_date.strftime("%m-%d"))

    birthday_format = func.to_char(models.Contact.birthday, 'MM-DD')
    
    return (
        db.query(models.Contact)
        .filter(models.Contact.user_id == user_id)
        .filter(birthday_format.in_(date_formats))
        .all()
    )

def get_contact_by_email_for_user(db: Session, email: str, user_id: int):
    """
    Перевіряє, чи існує вже контакт з такою поштою у конкретного користувача.

    :param db: Поточна сесія бази даних SQLAlchemy.
    :param email: Електронна пошта контакту.
    :param user_id: Ідентифікатор власника контактів.
    :return: Об'єкт контакту :class:`models.Contact` або None.
    """
    return db.query(models.Contact).filter(models.Contact.email == email, models.Contact.user_id == user_id).first()