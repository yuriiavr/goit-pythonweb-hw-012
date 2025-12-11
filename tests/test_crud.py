import pytest
from datetime import date
from sqlalchemy.orm import Session
from unittest.mock import MagicMock
from models import User, Contact
import crud
from schemas import UserCreate, ContactCreate

def test_get_user_by_email(session: Session):
    user = User(email="test@example.com", username="testuser", password="hashed_password", confirmed=True)
    session.add(user)
    session.commit()
    
    fetched_user = crud.get_user_by_email(session, "test@example.com")
    assert fetched_user.email == "test@example.com"
    
def test_create_user(session: Session):
    mock_auth = MagicMock()
    mock_auth.get_password_hash.return_value = "hashed_password"
    crud.auth_service = mock_auth
    
    user_schema = UserCreate(username="newuser", email="new@example.com", password="password123")
    new_user = crud.create_user(session, user_schema)
    
    assert new_user.email == "new@example.com"
    assert new_user.password == "hashed_password"
    assert new_user.confirmed == False

def test_create_contact(session: Session):
    user = User(id=1, email="contact@user.com", username="cuser", password="hp")
    session.add(user)
    session.commit()
    
    contact_schema = ContactCreate(first_name="John", last_name="Doe", email="john@doe.com", phone_number="1234567890", birthday=date(1990, 1, 1))
    new_contact = crud.create_contact(session, contact_schema, user_id=1)
    
    assert new_contact.first_name == "John"
    assert new_contact.user_id == 1

def test_get_contact(session: Session):
    user = User(id=1, email="contact@user.com", username="cuser", password="hp")
    contact = Contact(id=1, first_name="Test", last_name="Contact", email="tc@test.com", phone_number="111", birthday=date(2000, 1, 1), user_id=1)
    session.add(user)
    session.add(contact)
    session.commit()
    
    fetched_contact = crud.get_contact(session, 1, user_id=1)
    assert fetched_contact.email == "tc@test.com"
    
def test_update_contact(session: Session):
    user = User(id=1, email="contact@user.com", username="cuser", password="hp")
    contact = Contact(id=1, first_name="Old", last_name="Name", email="old@test.com", phone_number="111", birthday=date(2000, 1, 1), user_id=1)
    session.add(user)
    session.add(contact)
    session.commit()
    
    update_schema = ContactCreate(first_name="New", last_name="Name", email="new@test.com", phone_number="1234567890", birthday=date(2001, 2, 2))
    updated_contact = crud.update_contact(session, contact, update_schema)
    
    assert updated_contact.first_name == "New"
    assert updated_contact.email == "new@test.com"

def test_delete_contact(session: Session):
    user = User(id=1, email="contact@user.com", username="cuser", password="hp")
    contact = Contact(id=1, first_name="To", last_name="Delete", email="del@test.com", phone_number="111", birthday=date(2000, 1, 1), user_id=1)
    session.add(user)
    session.add(contact)
    session.commit()
    
    deleted_contact = crud.delete_contact(session, 1, user_id=1)
    assert deleted_contact.email == "del@test.com"
    
    fetched_contact = crud.get_contact(session, 1, user_id=1)
    assert fetched_contact is None