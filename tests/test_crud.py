import pytest
from datetime import date, timedelta
from sqlalchemy.orm import Session
from unittest.mock import MagicMock, patch
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
    with patch('crud.auth_service') as mock_auth: 
        expected_hash = "hashed_password" 
        mock_auth.get_password_hash.return_value = expected_hash

        user_schema = UserCreate(username="newuser", email="new@example.com", password="password123")
        new_user = crud.create_user(session, user_schema)

        assert new_user.email == "new@example.com"
        assert new_user.password == expected_hash 
        assert new_user.confirmed == False

def test_create_contact(session: Session):
    user = User(id=1, email="contact@user.com", username="cuser", password="hp")
    session.add(user)
    session.commit()
    
    contact_schema = ContactCreate(first_name="Test", last_name="Contact", email="tc@test.com", phone_number="1234567890", birthday=date(2000, 1, 1))
    new_contact = crud.create_contact(session, contact_schema, user_id=1)
    
    assert new_contact.email == "tc@test.com"
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
    contact = Contact(id=1, first_name="Test", last_name="Contact", email="tc@test.com", phone_number="111", birthday=date(2000, 1, 1), user_id=1)
    session.add(user)
    session.add(contact)
    session.commit()

    deleted_contact = crud.delete_contact(session, 1, user_id=1)
    
    assert deleted_contact.id == 1
    assert crud.get_contact(session, 1, user_id=1) is None

def test_get_user_by_email_not_found(session: Session):
    fetched_user = crud.get_user_by_email(session, "nonexistent@example.com")
    assert fetched_user is None
    
def test_confirm_user_success(session: Session):
    user = User(email="toconfirm@example.com", username="toconfirm", password="hp", confirmed=False)
    session.add(user)
    session.commit()
    
    confirmed_user = crud.confirm_user(session, user.email) 
    
    assert confirmed_user.confirmed == True
    
def test_confirm_user_not_found(session: Session):
    confirmed_user = crud.confirm_user(session, "unknown@example.com")
    assert confirmed_user is None

@patch('crud.get_upcoming_birthdays')
def test_upcoming_birthdays_found(mock_get_upcoming_birthdays, session: Session, test_user: User):
    mock_contact = MagicMock()
    mock_contact.first_name = "Next"
    mock_get_upcoming_birthdays.return_value = [mock_contact]
    
    results = crud.get_upcoming_birthdays(session, user_id=test_user.id)
    
    assert len(results) == 1
    assert results[0].first_name == "Next"
    
@patch('crud.get_upcoming_birthdays')
def test_upcoming_birthdays_not_found(mock_get_upcoming_birthdays, session: Session, test_user: User):
    mock_get_upcoming_birthdays.return_value = []
    
    results = crud.get_upcoming_birthdays(session, user_id=test_user.id)
    
    assert results == []
    
@patch('main.crud.get_contact')
def test_get_contact_by_id_not_found_on_get(mock_get_contact, client: TestClient, test_user, session):
    mock_get_contact.return_value = None
    
    response = client.get("/contacts/999")
    
    assert response.status_code == 404
    assert response.json()["detail"] == "Contact not found or does not belong to user"

@patch('main.crud.delete_contact')
def test_delete_contact_not_found(mock_delete_contact, client: TestClient, test_user, session):
    mock_delete_contact.return_value = None
    
    response = client.delete("/contacts/999")
    
    assert response.status_code == 404
    assert response.json()["detail"] == "Contact not found or does not belong to user"

@patch('main.crud.search_contacts')
def test_search_contacts_by_query(mock_search_contacts, client: TestClient, test_user, session):
    
    mock_contact = MagicMock(
        id=1, 
        first_name="Search", 
        last_name="Test", 
        email="s@t.com", 
        phone_number="1234567890", 
        birthday=date(2000, 1, 1), 
        additional_data=None, 
        user_id=test_user.id
    )
    mock_search_contacts.return_value = [mock_contact]
    
    response = client.get("/contacts/search/?query=Search")
    
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["phone_number"] == "1234567890" 
    mock_search_contacts.assert_called_once()
    
def test_confirm_email_not_found(session: Session):
    result = crud.confirm_email(session, "nonexistent_email@example.com")
    assert result == False
    
@patch('crud.get_contact')
def test_delete_contact_not_found(mock_get_contact, session: Session, test_user: User):
    mock_get_contact.return_value = None
    
    deleted_contact = crud.delete_contact(session, 999, user_id=test_user.id)
    
    assert deleted_contact is None
    mock_get_contact.assert_called_once_with(session, 999, test_user.id)