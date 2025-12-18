from sqlalchemy.orm import Session
from sqlalchemy import or_, extract, func
from datetime import date, timedelta
from typing import List
from typing import Optional

import models, schemas
from auth import auth_service

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = auth_service.get_password_hash(user.password)
    db_user = models.User(username=user.username, email=user.email, password=hashed_password, confirmed=False)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_token(db: Session, user: models.User, token: str):
    user.refresh_token = token
    db.commit()
    
def update_avatar(db: Session, user: models.User, avatar_url: str) -> models.User:
    user.avatar = avatar_url
    db.commit()
    db.refresh(user)
    return user

def confirm_email(db: Session, email: str):
    user = get_user_by_email(db, email)
    if user:
        user.confirmed = True
        db.commit()
        return True
    return False

def confirm_user(db: Session, email: str) -> Optional[models.User]:
    user = db.query(models.User).filter(models.User.email == email).first()
    if user:
        user.confirmed = True
        db.commit()
        db.refresh(user)
    return user

def update_password(db: Session, user: models.User, new_password: str):
    user.password = auth_service.get_password_hash(new_password)
    db.commit()
    db.refresh(user)
    return user

def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int):
    """
    Створює новий контакт для конкретного користувача.

    Args:
        db (Session): Сесія бази даних.
        contact (ContactCreate): Схема з даними контакту.
        user_id (int): ID власника контакту.

    Returns:
        Contact: Створений об'єкт контакту з БД.
    """
    db_contact = models.Contact(**contact.model_dump(), user_id=user_id) 
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def get_contact(db: Session, contact_id: int, user_id: int):
    return db.query(models.Contact).filter(models.Contact.id == contact_id, models.Contact.user_id == user_id).first()

def get_contacts(db: Session, skip: int = 0, limit: int = 100, user_id: int = None) -> List[models.Contact]:
    return db.query(models.Contact).filter(models.Contact.user_id == user_id).offset(skip).limit(limit).all()

def update_contact(db: Session, db_contact: models.Contact, contact: schemas.ContactUpdate):
    contact_data = contact.model_dump(exclude_unset=True)
    for key, value in contact_data.items():
        setattr(db_contact, key, value)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def delete_contact(db: Session, contact_id: int, user_id: int):
    db_contact = get_contact(db, contact_id, user_id)
    if db_contact:
        db.delete(db_contact)
        db.commit()
        return db_contact
    return None

def search_contacts(db: Session, query: str, user_id: int) -> List[models.Contact]:
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
    return db.query(models.Contact).filter(models.Contact.email == email, models.Contact.user_id == user_id).first()